from __future__ import annotations

import json
from pathlib import Path
import shutil

from lua_nil_review_agent.agent_backend import BackendError, CodexCliBackend
from lua_nil_review_agent.models import AdjudicationRecord, AutofixPatch, RoleOpinion, Verdict
from lua_nil_review_agent.service import (
    apply_autofix_manifest,
    benchmark_cache_compare,
    benchmark_repository_review,
    bootstrap_repository,
    clear_backend_cache,
    export_autofix_patches,
    export_autofix_unified_diff,
)


class StrictEvidenceBackend:
    """Deterministic stand-in for a strict external adjudication agent."""

    def adjudicate(self, packet, sink_rule):  # noqa: ANN001
        observed_guards = _tuple_field(packet.static_reasoning, "observed_guards")
        origins = _tuple_field(packet.static_reasoning, "origin_candidates")
        safety_facts = tuple(
            fact for fact in packet.knowledge_facts if "returns non-nil" in fact.lower()
        )

        if observed_guards or safety_facts:
            safety_evidence = observed_guards or safety_facts
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("safety evidence blocks a clean risk proof",),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="high" if observed_guards else "medium",
                    risk_path=(),
                    safety_evidence=safety_evidence,
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="high" if observed_guards else "medium",
                    risk_path=(),
                    safety_evidence=safety_evidence,
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

        if _locally_proves_nil(origins, packet.local_context):
            risk_path = origins or ("explicit nil flow in local context",)
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="risky",
                    confidence="high",
                    risk_path=risk_path,
                    safety_evidence=(),
                    missing_evidence=(),
                    recommended_next_action="report",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("no explicit safety proof",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="risky",
                    confidence="high",
                    risk_path=risk_path,
                    safety_evidence=(),
                    counterarguments_considered=("no explicit safety proof",),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

        return AdjudicationRecord(
            prosecutor=RoleOpinion(
                role="prosecutor",
                status="uncertain",
                confidence="low",
                risk_path=origins,
                safety_evidence=(),
                missing_evidence=("origin may be nil, but no code-proven nil path exists",),
                recommended_next_action="expand_context",
                suggested_fix=None,
            ),
            defender=RoleOpinion(
                role="defender",
                status="uncertain",
                confidence="low",
                risk_path=(),
                safety_evidence=(),
                missing_evidence=("no explicit guard or trusted non-nil contract found",),
                recommended_next_action="expand_context",
                suggested_fix=None,
            ),
            judge=Verdict(
                case_id=packet.case_id,
                status="uncertain",
                confidence="medium",
                risk_path=origins,
                safety_evidence=(),
                counterarguments_considered=("insufficient local proof either way",),
                suggested_fix=None,
                needs_human=True,
            ),
        )


def test_bootstrap_repository_loads_config_and_discovers_sources(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()

    sink_rules = [
        {
            "id": "string.match.arg1",
            "kind": "function_arg",
            "qualified_name": "string.match",
            "arg_index": 1,
            "nil_sensitive": True,
            "failure_mode": "runtime_error",
            "default_severity": "high",
            "safe_patterns": ["x or ''"],
        }
    ]
    confidence_policy = {
        "levels": ["low", "medium", "high"],
        "default_report_min_confidence": "high",
        "default_include_medium_in_audit": True,
    }

    (config_dir / "sink_rules.json").write_text(json.dumps(sink_rules), encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(confidence_policy),
        encoding="utf-8",
    )
    (src_dir / "demo.lua").write_text("return string.match(name, 'x')", encoding="utf-8")

    snapshot = bootstrap_repository(tmp_path)

    assert snapshot.root == tmp_path
    assert len(snapshot.sink_rules) == 1
    assert snapshot.confidence_policy.default_report_min_confidence == "high"
    assert snapshot.lua_files == (src_dir / "demo.lua",)


def test_benchmark_repository_review_reports_semantic_accuracy(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)

    snapshot = bootstrap_repository(runtime_root)
    summary = benchmark_repository_review(snapshot, backend=StrictEvidenceBackend())

    assert summary.total_cases == 18
    assert summary.exact_matches == 18
    assert summary.expected_risky == 5
    assert summary.expected_safe == 8
    assert summary.expected_uncertain == 5
    assert summary.actual_risky == 5
    assert summary.actual_safe == 8
    assert summary.actual_uncertain == 5
    assert summary.false_positive_risks == 0
    assert summary.missed_risks == 0
    assert summary.unresolved_cases == 0
    assert summary.backend_fallbacks == 0
    assert summary.backend_timeouts == 0
    assert summary.backend_cache_hits == 0
    assert summary.backend_cache_misses == 0
    assert summary.backend_calls == 0
    assert summary.backend_total_seconds == 0.0
    assert summary.backend_average_seconds == 0.0
    assert all(case.matches_expectation for case in summary.cases)


def test_benchmark_repository_review_counts_backend_fallbacks(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "provable_risky_nil_literal.lua").write_text(
        "local username = nil\nreturn string.match(username, '^a')\n",
        encoding="utf-8",
    )

    def failing_runner(command, *, stdin_text, cwd):  # noqa: ANN001
        raise BackendError("CLI backend command timed out after 5s")

    snapshot = bootstrap_repository(tmp_path)
    summary = benchmark_repository_review(
        snapshot,
        backend=CodexCliBackend(
            runner=failing_runner,
            workdir=tmp_path,
            max_attempts=1,
            cache_path=tmp_path / "codex-cache.json",
        ),
    )

    assert summary.total_cases == 1
    assert summary.exact_matches == 0
    assert summary.actual_uncertain == 1
    assert summary.backend_fallbacks == 1
    assert summary.backend_timeouts == 1
    assert summary.backend_cache_hits == 0
    assert summary.backend_cache_misses == 1
    assert summary.backend_calls == 1
    assert summary.backend_total_seconds >= 0.0
    assert summary.backend_average_seconds >= 0.0
    assert summary.cases[0].backend_failure_reason == "CLI backend command timed out after 5s"


def test_benchmark_repository_review_reports_backend_cache_metrics(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)

    snapshot = bootstrap_repository(runtime_root)
    backend = StrictEvidenceBackend()
    backend.cache_hits = 7
    backend.cache_misses = 11
    backend.backend_call_count = 4
    backend.backend_total_seconds = 1.25
    summary = benchmark_repository_review(snapshot, backend=backend)

    assert summary.backend_cache_hits == 7
    assert summary.backend_cache_misses == 11
    assert summary.backend_calls == 4
    assert summary.backend_total_seconds == 1.25
    assert summary.backend_average_seconds == 0.3125


def test_benchmark_cache_compare_runs_cold_and_warm_passes(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)
    cache_path = tmp_path / "codex-cache.json"
    cache_path.write_text(json.dumps({"stale": {"judge": {"status": "safe"}}}), encoding="utf-8")

    snapshot = bootstrap_repository(runtime_root)
    backends: list[StrictEvidenceBackend] = []

    def make_backend() -> StrictEvidenceBackend:
        backend = StrictEvidenceBackend()
        if not backends:
            backend.cache_hits = 0
            backend.cache_misses = 18
            backend.backend_call_count = 18
            backend.backend_total_seconds = 9.0
        else:
            backend.cache_hits = 18
            backend.cache_misses = 0
            backend.backend_call_count = 0
            backend.backend_total_seconds = 0.0
        backends.append(backend)
        return backend

    comparison = benchmark_cache_compare(
        snapshot,
        backend_factory=make_backend,
        cache_path=cache_path,
    )

    assert comparison.cache_cleared_entries == 1
    assert comparison.cold.backend_cache_hits == 0
    assert comparison.cold.backend_cache_misses == 18
    assert comparison.cold.backend_calls == 18
    assert comparison.warm.backend_cache_hits == 18
    assert comparison.warm.backend_cache_misses == 0
    assert comparison.warm.backend_calls == 0


def test_clear_backend_cache_removes_cache_file_and_counts_entries(tmp_path: Path) -> None:
    cache_path = tmp_path / "codex-cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "entry-1": {"judge": {"status": "safe"}},
                "entry-2": {"judge": {"status": "uncertain"}},
            }
        ),
        encoding="utf-8",
    )

    removed = clear_backend_cache(cache_path)

    assert removed == 2
    assert not cache_path.exists()


def test_export_autofix_patches_writes_reportable_patch_file(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()

    sink_rules = [
        {
            "id": "string.match.arg1",
            "kind": "function_arg",
            "qualified_name": "string.match",
            "arg_index": 1,
            "nil_sensitive": True,
            "failure_mode": "runtime_error",
            "default_severity": "high",
            "safe_patterns": ["x or ''"],
        }
    ]
    confidence_policy = {
        "levels": ["low", "medium", "high"],
        "default_report_min_confidence": "high",
        "default_include_medium_in_audit": True,
    }

    (config_dir / "sink_rules.json").write_text(json.dumps(sink_rules), encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(confidence_policy),
        encoding="utf-8",
    )
    (src_dir / "demo.lua").write_text(
        "local username = nil\nreturn string.match(username, 'x')",
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    output_path = tmp_path / "data" / "autofix.json"

    patches = export_autofix_patches(snapshot, output_path=output_path)

    assert len(patches) == 1
    patch = patches[0]
    assert patch.action == "insert_before"
    assert patch.start_line == 2
    assert patch.expected_original == "return string.match(username, 'x')"
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["action"] == "insert_before"
    assert payload[0]["replacement"] == "username = username or ''"
    assert payload[0]["expected_original"] == "return string.match(username, 'x')"


def test_apply_autofix_manifest_updates_file_when_expected_original_matches(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(username, 'x')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_1",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, 'x')",
                }
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest)

    assert len(applied) == 1
    assert not conflicts
    assert target.read_text(encoding="utf-8") == (
        "username = username or ''\n"
        "return string.match(username, 'x')\n"
    )


def test_apply_autofix_manifest_dry_run_does_not_write_file(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(username, 'x')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_dry_run",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, 'x')",
                }
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest, dry_run=True)

    assert len(applied) == 1
    assert not conflicts
    assert target.read_text(encoding="utf-8") == original


def test_export_autofix_unified_diff_renders_patch_without_writing_file(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(username, 'x')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_diff",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, 'x')",
                }
            ]
        ),
        encoding="utf-8",
    )

    diff_text, conflicts = export_autofix_unified_diff(manifest)

    assert not conflicts
    assert f"--- {target}" in diff_text
    assert f"+++ {target}" in diff_text
    assert "+username = username or ''" in diff_text
    assert target.read_text(encoding="utf-8") == original


def test_apply_autofix_manifest_filters_by_case_id(tmp_path: Path) -> None:
    first = tmp_path / "first.lua"
    second = tmp_path / "second.lua"
    first.write_text("return string.match(username, 'x')\n", encoding="utf-8")
    second.write_text("return string.match(token, 'x')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_first",
                    "file": str(first),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, 'x')",
                },
                {
                    "case_id": "case_second",
                    "file": str(second),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "token = token or ''",
                    "expected_original": "return string.match(token, 'x')",
                },
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest, case_ids=("case_second",))

    assert len(applied) == 1
    assert not conflicts
    assert applied[0].case_id == "case_second"
    assert first.read_text(encoding="utf-8") == "return string.match(username, 'x')\n"
    assert second.read_text(encoding="utf-8") == (
        "token = token or ''\n"
        "return string.match(token, 'x')\n"
    )


def test_export_autofix_unified_diff_filters_by_file_path(tmp_path: Path) -> None:
    first = tmp_path / "first.lua"
    second = tmp_path / "second.lua"
    first.write_text("return string.match(username, 'x')\n", encoding="utf-8")
    second.write_text("return string.match(token, 'x')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_first",
                    "file": str(first),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, 'x')",
                },
                {
                    "case_id": "case_second",
                    "file": str(second),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "token = token or ''",
                    "expected_original": "return string.match(token, 'x')",
                },
            ]
        ),
        encoding="utf-8",
    )

    diff_text, conflicts = export_autofix_unified_diff(manifest, file_paths=(second,))

    assert not conflicts
    assert f"--- {second}" in diff_text
    assert f"+++ {second}" in diff_text
    assert "+token = token or ''" in diff_text
    assert str(first) not in diff_text


def test_apply_autofix_manifest_reports_conflicts_without_writing_file(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(user_name, 'x')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    patch = AutofixPatch(
        case_id="case_conflict",
        file=str(target),
        action="insert_before",
        start_line=1,
        end_line=1,
        replacement="user_name = user_name or ''",
        expected_original="return string.match(username, 'x')",
    )
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": patch.case_id,
                    "file": patch.file,
                    "action": patch.action,
                    "start_line": patch.start_line,
                    "end_line": patch.end_line,
                    "replacement": patch.replacement,
                    "expected_original": patch.expected_original,
                }
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest)

    assert not applied
    assert len(conflicts) == 1
    assert "anchor line no longer matches expected_original" in conflicts[0]
    assert target.read_text(encoding="utf-8") == original


def _tuple_field(values: dict[str, tuple[str, ...] | str], key: str) -> tuple[str, ...]:
    current = values.get(key, ())
    if isinstance(current, tuple):
        return current
    return ()


def _locally_proves_nil(origins: tuple[str, ...], local_context: str) -> bool:
    if any(origin.strip() == "nil" for origin in origins):
        return True
    return " and nil or " in local_context
