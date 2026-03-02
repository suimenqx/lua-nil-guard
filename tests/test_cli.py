from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

import lua_nil_review_agent.cli as cli_module
from lua_nil_review_agent.agent_backend import BackendError
from lua_nil_review_agent.cli import run
from lua_nil_review_agent.models import AdjudicationRecord, RoleOpinion, Verdict


def test_cli_help_lists_supported_backends() -> None:
    exit_code, output = run(["--help"])

    assert exit_code == 0
    assert "Backend values: heuristic | codex | codeagent" in output
    assert "--allow-skill-fallback" in output
    assert "--backend-executable PATH" in output
    assert "--backend-timeout SECONDS" in output
    assert "--backend-attempts N" in output
    assert "--backend-config KEY=VALUE" in output
    assert "benchmark" in output
    assert "export-autofix" in output
    assert "apply-autofix" in output
    assert "export-unified-diff" in output


def test_cli_scan_reports_static_summary(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "if username then",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["scan", str(tmp_path)])

    assert exit_code == 0
    assert "Lua Nil Review Static Summary" in output
    assert "Parser backend: tree_sitter_local" in output
    assert "Total candidates: 1" in output
    assert "safe_static: 1" in output


def test_cli_benchmark_reports_labeled_accuracy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)

    class FileLabelBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            file_name = Path(packet.target.file).name
            if file_name.startswith("provable_risky_"):
                status = "risky"
            elif file_name.startswith("provable_safe_"):
                status = "safe"
            else:
                status = "uncertain"
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status=status,
                    confidence="high",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=(),
                    recommended_next_action="report",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status=status,
                    confidence="high",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=(),
                    recommended_next_action="report",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status=status,
                    confidence="high",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    monkeypatch.setattr(
        cli_module,
        "create_adjudication_backend",
        lambda *args, **kwargs: FileLabelBackend(),
    )

    exit_code, output = run(["benchmark", str(runtime_root)])

    assert exit_code == 0
    assert "# Lua Nil Review Benchmark" in output
    assert "Total labeled cases: 18" in output
    assert "Exact matches: 18" in output
    assert "Accuracy: 100.0%" in output
    assert "Missed risks: 0" in output
    assert "False positive risks: 0" in output
    assert "Backend fallbacks: 0" in output
    assert "Backend timeouts: 0" in output


def test_cli_report_outputs_markdown_findings(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["report", str(tmp_path)])

    assert exit_code == 0
    assert "# Lua Nil Risk Report" in output
    assert "risky_verified" in output


def test_cli_export_autofix_outputs_machine_readable_patches(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-autofix", str(tmp_path)])

    assert exit_code == 0
    payload = json.loads(output)
    assert payload[0]["action"] == "insert_before"
    assert payload[0]["start_line"] == 2
    assert payload[0]["replacement"] == "username = username or ''"
    assert payload[0]["expected_original"] == "return string.match(username, '^a')"


def test_cli_apply_autofix_updates_files_from_manifest(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_apply",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", str(manifest)])

    assert exit_code == 0
    assert "Dry run: no" in output
    assert "Applied patches: 1" in output
    assert "Conflicts: 0" in output
    assert target.read_text(encoding="utf-8") == (
        "username = username or ''\n"
        "return string.match(username, '^a')\n"
    )


def test_cli_apply_autofix_dry_run_does_not_write_files(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(username, '^a')\n"
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
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", "--dry-run", str(manifest)])

    assert exit_code == 0
    assert "Dry run: yes" in output
    assert "Applied patches: 1" in output
    assert "Conflicts: 0" in output
    assert target.read_text(encoding="utf-8") == original


def test_cli_apply_autofix_returns_conflicts_without_writing_files(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(user_name, '^a')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_conflict",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "user_name = user_name or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", str(manifest)])

    assert exit_code == 1
    assert "Dry run: no" in output
    assert "Applied patches: 0" in output
    assert "Conflicts: 1" in output
    assert "anchor line no longer matches expected_original" in output
    assert target.read_text(encoding="utf-8") == original


def test_cli_apply_autofix_reports_missing_manifest() -> None:
    exit_code, output = run(["apply-autofix", "missing-autofix.json"])

    assert exit_code == 2
    assert "missing-autofix.json" in output


def test_cli_apply_autofix_filters_by_case_id(tmp_path: Path) -> None:
    first = tmp_path / "first.lua"
    second = tmp_path / "second.lua"
    first.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    second.write_text("return string.match(token, '^a')\n", encoding="utf-8")
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
                    "expected_original": "return string.match(username, '^a')",
                },
                {
                    "case_id": "case_second",
                    "file": str(second),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "token = token or ''",
                    "expected_original": "return string.match(token, '^a')",
                },
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", "--case-id", "case_second", str(manifest)])

    assert exit_code == 0
    assert "Applied patches: 1" in output
    assert first.read_text(encoding="utf-8") == "return string.match(username, '^a')\n"
    assert second.read_text(encoding="utf-8") == (
        "token = token or ''\n"
        "return string.match(token, '^a')\n"
    )


def test_cli_export_unified_diff_outputs_patch_text(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(username, '^a')\n", encoding="utf-8")
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
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-unified-diff", str(manifest)])

    assert exit_code == 0
    assert f"--- {target}" in output
    assert f"+++ {target}" in output
    assert "+username = username or ''" in output


def test_cli_export_unified_diff_blocks_on_conflicts(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(user_name, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_diff_conflict",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "user_name = user_name or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-unified-diff", str(manifest)])

    assert exit_code == 1
    assert "Unified diff export blocked." in output
    assert "Conflicts: 1" in output
    assert "anchor line no longer matches expected_original" in output


def test_cli_export_unified_diff_filters_by_file(tmp_path: Path) -> None:
    first = tmp_path / "first.lua"
    second = tmp_path / "second.lua"
    first.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    second.write_text("return string.match(token, '^a')\n", encoding="utf-8")
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
                    "expected_original": "return string.match(username, '^a')",
                },
                {
                    "case_id": "case_second",
                    "file": str(second),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "token = token or ''",
                    "expected_original": "return string.match(token, '^a')",
                },
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-unified-diff", "--file", str(second), str(manifest)])

    assert exit_code == 0
    assert f"--- {second}" in output
    assert f"+++ {second}" in output
    assert "+token = token or ''" in output
    assert str(first) not in output


def test_cli_baseline_create_writes_baseline_file(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"

    exit_code, output = run(["baseline-create", str(tmp_path), str(baseline_path)])

    assert exit_code == 0
    assert "Baseline entries: 1" in output
    assert baseline_path.exists()


def test_cli_report_new_applies_baseline_filter(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"
    create_exit_code, _ = run(["baseline-create", str(tmp_path), str(baseline_path)])
    assert create_exit_code == 0

    exit_code, output = run(["report-new", str(tmp_path), str(baseline_path)])

    assert exit_code == 0
    assert "No reportable findings." in output


def test_cli_refresh_summaries_writes_summary_cache(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local function normalize_name(name, fallback)",
                "  assert(fallback)",
                "  name = name or fallback",
                "  return name",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    summary_path = tmp_path / "data" / "function_summaries.json"

    exit_code, output = run(["refresh-summaries", str(tmp_path), str(summary_path)])

    assert exit_code == 0
    assert "Summary entries: 1" in output
    assert summary_path.exists()


def test_cli_refresh_knowledge_writes_knowledge_cache(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local function normalize_name(name)",
                "  name = name or ''",
                "  return name",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    knowledge_path = tmp_path / "data" / "knowledge.json"

    exit_code, output = run(["refresh-knowledge", str(tmp_path), str(knowledge_path)])

    assert exit_code == 0
    assert "Knowledge entries: 1" in output
    assert knowledge_path.exists()


def test_cli_ci_check_fails_when_new_findings_exist(tmp_path: Path) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("[]", encoding="utf-8")

    exit_code, output = run(["ci-check", str(tmp_path), str(baseline_path)])

    assert exit_code == 1
    assert "New findings: 1" in output


def test_cli_report_accepts_backend_option_and_calls_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    skill_path = tmp_path / "custom-skill.md"
    skill_path.write_text("placeholder", encoding="utf-8")

    def fake_factory(
        name: str,
        *,
        workdir=None,
        model=None,
        skill_path=None,
        strict_skill=True,
        executable=None,
        timeout_seconds=None,
        max_attempts=None,
        config_overrides=(),
    ):
        captured["name"] = name
        captured["workdir"] = workdir
        captured["model"] = model
        captured["skill_path"] = skill_path
        captured["strict_skill"] = strict_skill
        captured["executable"] = executable
        captured["timeout_seconds"] = timeout_seconds
        captured["max_attempts"] = max_attempts
        captured["config_overrides"] = config_overrides
        return None

    monkeypatch.setattr("lua_nil_review_agent.cli.create_adjudication_backend", fake_factory)

    exit_code, output = run(
        [
            "report",
            "--backend",
            "codeagent",
            "--skill",
            str(skill_path),
            "--allow-skill-fallback",
            "--backend-executable",
            "/tmp/codeagent-bin",
            "--backend-timeout",
            "12.5",
            "--backend-attempts",
            "3",
            "--backend-config",
            "model='o3'",
            "--backend-config",
            "features.fast=true",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert captured["name"] == "codeagent"
    assert captured["workdir"] == tmp_path
    assert captured["model"] is None
    assert captured["skill_path"] == skill_path
    assert captured["strict_skill"] is False
    assert captured["executable"] == "/tmp/codeagent-bin"
    assert captured["timeout_seconds"] == 12.5
    assert captured["max_attempts"] == 3
    assert captured["config_overrides"] == ("model='o3'", "features.fast=true")
    assert "# Lua Nil Risk Report" in output


def test_cli_report_surfaces_backend_errors_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    def fake_review(*args, **kwargs):
        raise BackendError("codex backend failed")

    monkeypatch.setattr("lua_nil_review_agent.cli.run_repository_review", fake_review)

    exit_code, output = run(["report", str(tmp_path)])

    assert exit_code == 2
    assert output == "codex backend failed"


def test_cli_report_rejects_invalid_backend_timeout() -> None:
    exit_code, output = run(["report", "--backend-timeout", "0", "demo"])

    assert exit_code == 2
    assert output == "--backend-timeout must be a positive number"


def test_cli_report_rejects_invalid_backend_config() -> None:
    exit_code, output = run(["report", "--backend-config", "reasoning_effort", "demo"])

    assert exit_code == 2
    assert output == "--backend-config must be in KEY=VALUE form"
