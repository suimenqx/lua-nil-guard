from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

import lua_nil_guard.service as service_module
from lua_nil_guard.agent_backend import BackendError, CliAgentBackend, CodexCliBackend
from lua_nil_guard.models import AdjudicationRecord, AutofixPatch, RoleOpinion, Verdict
from lua_nil_guard.models import (
    DomainKnowledgeConfig,
    DomainKnowledgeRule,
    FunctionContract,
    ImprovementProposal,
    SinkRule,
)
from lua_nil_guard.service import (
    apply_autofix_manifest,
    benchmark_cache_compare,
    benchmark_repository_review,
    bootstrap_repository,
    clear_backend_cache,
    draft_function_contracts,
    draft_review_improvements,
    export_autofix_patches,
    export_autofix_unified_diff,
    find_repository_root_for_file,
    review_source,
    run_file_review,
    summarize_improvement_proposals,
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


def test_bootstrap_repository_loads_domain_knowledge_rules(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()
    (config_dir / "sink_rules.json").write_text("[]", encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (config_dir / "domain_knowledge.json").write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "system_name_table_prefix",
                        "action": "skip_candidate",
                        "symbol_regex": "^_name_[A-Z0-9_]+(?:\\\\.[A-Za-z_][A-Za-z0-9_]*)*$",
                        "applies_to_sinks": ["member_access.receiver"],
                        "assumed_non_nil": True,
                        "assumed_kind": "table",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (src_dir / "demo.lua").write_text("return _name_TOYS.car\n", encoding="utf-8")

    snapshot = bootstrap_repository(tmp_path)

    assert len(snapshot.domain_knowledge.rules) == 1
    assert snapshot.domain_knowledge.rules[0].id == "system_name_table_prefix"


def test_review_source_domain_fast_prune_skips_static_ast_build(monkeypatch) -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("assert(x)",),
        ),
    )
    domain_knowledge = DomainKnowledgeConfig(
        rules=(
            DomainKnowledgeRule(
                id="system_name_table_prefix",
                action="skip_candidate",
                symbol_regex=r"^_name_[A-Z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]*)*$",
                applies_to_sinks=("member_access.receiver",),
                assumed_non_nil=True,
                assumed_kind="table",
            ),
        )
    )

    def _fail_if_called(_: str):
        raise AssertionError("build_static_analysis_context should not run for fully-pruned files")

    monkeypatch.setattr(service_module, "build_static_analysis_context", _fail_if_called)

    assessments = review_source(
        Path("foo.lua"),
        "return _name_TOYS.car\n",
        sink_rules,
        domain_knowledge=domain_knowledge,
    )

    assert assessments == ()


def test_review_source_scopes_ast_context_to_enclosing_functions(monkeypatch) -> None:
    sink_rules = (
        SinkRule(
            id="string.match.arg1",
            kind="function_arg",
            qualified_name="string.match",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )
    source = "\n".join(
        [
            "local function parse_name(name, alias)",
            "  local first = string.match(name, '^a')",
            "  local second = string.match(alias, '^b')",
            "  return first or second",
            "end",
            "",
            "local function parse_suffix(suffix)",
            "  return string.match(suffix, '^c')",
            "end",
        ]
    )
    seen_scoped_sources: list[str] = []

    def _record_scope(scoped_source: str):
        seen_scoped_sources.append(scoped_source)
        return None

    monkeypatch.setattr(service_module, "build_static_analysis_context", _record_scope)

    assessments = review_source(Path("foo.lua"), source, sink_rules)

    assert len(assessments) == 3
    assert len(seen_scoped_sources) == 2
    assert seen_scoped_sources[0].startswith("local function parse_name")
    assert seen_scoped_sources[1].startswith("local function parse_suffix")
    assert all(scoped_source.count("local function") == 1 for scoped_source in seen_scoped_sources)


def test_bootstrap_repository_splits_preprocessor_files_and_run_file_review_uses_macro_index(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()
    (config_dir / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.find.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.find",
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
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (config_dir / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/macros.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    macro_file = src_dir / "macros.lua"
    target_file = src_dir / "demo.lua"
    macro_file.write_text("USER_NAME = \"guest\"\n", encoding="utf-8")
    target_file.write_text("return string.find(USER_NAME, '^g')\n", encoding="utf-8")

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(snapshot, target_file)

    assert snapshot.lua_files == (target_file,)
    assert snapshot.preprocessor_files == (macro_file,)
    assert snapshot.macro_index is not None
    assert any(fact.key == "USER_NAME" and fact.provably_non_nil for fact in snapshot.macro_index.facts)
    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")


def test_bootstrap_repository_uses_default_id_globs_without_explicit_preprocessor_config(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()
    (config_dir / "sink_rules.json").write_text("[]", encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    macro_file = src_dir / "id.lua"
    business_file = src_dir / "consumer.lua"
    macro_file.write_text("USER_NAME = \"guest\"\n", encoding="utf-8")
    business_file.write_text("return nil\n", encoding="utf-8")

    snapshot = bootstrap_repository(tmp_path)

    assert snapshot.preprocessor_files == (macro_file,)
    assert snapshot.lua_files == (business_file,)
    assert snapshot.macro_index is not None
    assert any(fact.key == "USER_NAME" for fact in snapshot.macro_index.facts)


def test_bootstrap_repository_reuses_fresh_macro_cache_on_second_load(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()
    (config_dir / "sink_rules.json").write_text("[]", encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    macro_file = src_dir / "id.lua"
    business_file = src_dir / "consumer.lua"
    macro_file.write_text("USER_NAME = \"guest\"\n", encoding="utf-8")
    business_file.write_text("return nil\n", encoding="utf-8")

    first_snapshot = bootstrap_repository(tmp_path)
    second_snapshot = bootstrap_repository(tmp_path)

    assert first_snapshot.macro_cache_status is not None
    assert first_snapshot.macro_cache_status.state == "rebuilt"
    assert second_snapshot.macro_cache_status is not None
    assert second_snapshot.macro_cache_status.state == "fresh"
    assert second_snapshot.macro_index is not None
    assert second_snapshot.macro_index.cache_connection is not None
    assert second_snapshot.macro_index.facts == ()


def test_run_file_review_uses_cached_macro_facts_after_second_bootstrap(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()
    (config_dir / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.find.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.find",
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
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    macro_file = src_dir / "id.lua"
    target_file = src_dir / "consumer.lua"
    macro_file.write_text("USER_NAME = \"guest\"\n", encoding="utf-8")
    target_file.write_text("return string.find(USER_NAME, '^g')\n", encoding="utf-8")

    _first_snapshot = bootstrap_repository(tmp_path)
    second_snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(second_snapshot, target_file)

    assert second_snapshot.macro_cache_status is not None
    assert second_snapshot.macro_cache_status.state == "fresh"
    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")


def test_find_repository_root_for_file_walks_up_to_config_directory(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    nested_dir = tmp_path / "src" / "handlers"
    config_dir.mkdir(parents=True)
    nested_dir.mkdir(parents=True)

    (config_dir / "sink_rules.json").write_text("[]", encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    file_path = nested_dir / "demo.lua"
    file_path.write_text("return nil\n", encoding="utf-8")

    root = find_repository_root_for_file(file_path)

    assert root == tmp_path


def test_run_file_review_uses_repository_context_for_cross_file_function_chains(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  local raw = value",
                "  if raw == nil then",
                "    raw = ''",
                "  end",
                "  raw = string.gsub(raw, '^%s+', '')",
                "  raw = string.gsub(raw, '%s+$', '')",
                "  local trimmed = raw",
                "  if trimmed == '' then",
                "    return coerce_name(trimmed)",
                "  end",
                "  return coerce_name(trimmed)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    seen: dict[str, tuple[str, ...]] = {}

    class SummaryAwareBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["function_summaries"] = packet.function_summaries
            seen["related_function_contexts"] = packet.related_function_contexts
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("summary evidence blocks a clean risk proof",),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("normalize_name summary says it normalizes nil",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("normalize_name summary says it normalizes nil",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    verdicts = run_file_review(snapshot, target_file, backend=SummaryAwareBackend())

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert seen["related_functions"] == ("normalize_name", "coerce_name")
    assert any("normalize_name" in summary for summary in seen["function_summaries"])
    assert any("coerce_name" in summary for summary in seen["function_summaries"])
    assert any("normalize_name @ " in context for context in seen["related_function_contexts"])
    assert any("coerce_name @ " in context for context in seen["related_function_contexts"])
    assert any("return coerce_name(trimmed)" in context for context in seen["related_function_contexts"])
    assert any("value = value or ''" in context for context in seen["related_function_contexts"])


def test_run_file_review_uses_cross_file_transparent_wrappers_for_static_safety(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "assert_present(username)",
                "local normalized = normalize_name(username, '')",
                "local wrapped = wrap_name(normalized)",
                "local final = finalize_name(wrapped)",
                "return string.match(final, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "wrappers.lua").write_text(
        "\n".join(
            [
                "function wrap_name(value)",
                "  return value",
                "end",
                "",
                "function finalize_name(value)",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(snapshot, target_file)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")


def test_run_file_review_uses_cross_file_ast_inlined_guard_helpers_for_static_safety(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
                    "safe_patterns": ["assert(x)"],
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "assert_present(username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "guards.lua").write_text(
        "\n".join(
            [
                "function assert_present(value)",
                "  if not value then",
                "    error('missing')",
                "  end",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(snapshot, target_file)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")


def test_run_file_review_does_not_inline_cross_file_local_guard_helpers(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
                    "safe_patterns": ["assert(x)"],
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "assert_present(username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "guards.lua").write_text(
        "\n".join(
            [
                "local function assert_present(value)",
                "  if not value then",
                "    error('missing')",
                "  end",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(snapshot, target_file, backend=StrictEvidenceBackend())

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_file_review_uses_cross_file_ast_defaulting_wrappers_for_static_safety(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local username = normalize_name(req.params.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  if not value then",
                "    value = ''",
                "  end",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(snapshot, target_file)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")


def test_draft_function_contracts_infers_guard_and_wrapper_drafts_without_mutating_config(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "already_configured",
                    "returns_non_nil": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "helpers.lua").write_text(
        "\n".join(
            [
                "function assert_present(value)",
                "  if not value then",
                "    error('missing')",
                "  end",
                "  return value",
                "end",
                "",
                "function normalize_name(value)",
                "  if not value then",
                "    value = ''",
                "  end",
                "  return value",
                "end",
                "",
                "function wrap_name(value)",
                "  return value",
                "end",
                "",
                "function already_configured(value)",
                "  return value or ''",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    drafts = draft_function_contracts(snapshot)

    draft_by_name = {draft.qualified_name: draft for draft in drafts}

    assert "assert_present" in draft_by_name
    assert draft_by_name["assert_present"].ensures_non_nil_args == (1,)
    assert draft_by_name["assert_present"].notes == "draft:ast_inlined_guard_helper"

    assert "normalize_name" in draft_by_name
    assert draft_by_name["normalize_name"].returns_non_nil is True
    assert draft_by_name["normalize_name"].notes == "draft:ast_defaulting_wrapper"

    assert "wrap_name" in draft_by_name
    assert draft_by_name["wrap_name"].returns_non_nil_from_args == (1,)
    assert (
        draft_by_name["wrap_name"].returns_non_nil_from_args_by_return_slot
        == ((1, (1,)),)
    )
    assert draft_by_name["wrap_name"].notes == "draft:ast_wrapper_passthrough"

    assert "already_configured" not in draft_by_name


def test_draft_review_improvements_links_uncertain_cases_to_patterns_and_drafts(
    tmp_path: Path,
) -> None:
    class AlwaysUncertainBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="medium",
                    risk_path=packet.static_reasoning.get("origin_candidates", ()),
                    safety_evidence=(),
                    missing_evidence=("local proof is incomplete",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=packet.static_reasoning.get("observed_guards", ()),
                    missing_evidence=("needs stronger deterministic proof",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("needs stronger deterministic proof",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    (tmp_path / "src" / "demo_contract.lua").write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo_wrapper.lua").write_text(
        "\n".join(
            [
                "local function parse_other()",
                "  local username = maybe_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "helpers.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  if not value then",
                "    value = ''",
                "  end",
                "  return value",
                "end",
                "",
                "function maybe_name(value)",
                "  log(value)",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    proposals = draft_review_improvements(snapshot, backend=AlwaysUncertainBackend())

    proposal_kinds = {(proposal.kind, proposal.suggested_pattern or "") for proposal in proposals}
    contract_proposals = [
        proposal
        for proposal in proposals
        if proposal.kind == "function_contract" and proposal.suggested_contract is not None
    ]

    assert ("ast_pattern", "no_bounded_ast_proof") in proposal_kinds
    assert ("wrapper_recognizer", "maybe_name") in proposal_kinds
    assert not any(
        proposal.suggested_contract is not None
        and proposal.suggested_contract.qualified_name == "normalize_name"
        for proposal in contract_proposals
    )


def test_draft_review_improvements_skips_wrapper_proposals_for_known_local_helpers(
    tmp_path: Path,
) -> None:
    class AlwaysUncertainBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="medium",
                    risk_path=packet.static_reasoning.get("origin_candidates", ()),
                    safety_evidence=(),
                    missing_evidence=("local proof is incomplete",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=packet.static_reasoning.get("observed_guards", ()),
                    missing_evidence=("needs stronger deterministic proof",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("needs stronger deterministic proof",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    (tmp_path / "config").mkdir(parents=True)
    (tmp_path / "src").mkdir(parents=True)
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
                "local function passthrough_name(value)",
                "  return value",
                "end",
                "",
                "local function parse_user(req)",
                "  local username = passthrough_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    proposals = draft_review_improvements(snapshot, backend=AlwaysUncertainBackend())

    assert not any(
        proposal.kind == "wrapper_recognizer"
        and proposal.suggested_pattern == "passthrough_name"
        for proposal in proposals
    )


def test_summarize_improvement_proposals_groups_counts_stably() -> None:
    analytics = summarize_improvement_proposals(
        (
            ImprovementProposal(
                kind="ast_pattern",
                case_id="case_1",
                file="src/demo.lua",
                status="uncertain",
                confidence="medium",
                reason="fallback blocked proof",
                suggested_pattern="no_bounded_ast_proof",
            ),
            ImprovementProposal(
                kind="ast_pattern",
                case_id="case_2",
                file="src/demo.lua",
                status="uncertain",
                confidence="medium",
                reason="fallback blocked proof",
                suggested_pattern="no_bounded_ast_proof",
            ),
            ImprovementProposal(
                kind="function_contract",
                case_id="case_2",
                file="src/demo.lua",
                status="uncertain",
                confidence="medium",
                reason="review normalize_name",
                suggested_contract=FunctionContract(
                    qualified_name="normalize_name",
                    returns_non_nil=True,
                ),
            ),
        )
    )

    assert analytics.total_proposals == 3
    assert analytics.unique_cases == 2
    assert analytics.unresolved_proposals == 3
    assert analytics.medium_reportable_proposals == 0
    assert analytics.by_kind == (("ast_pattern", 2), ("function_contract", 1))
    assert analytics.by_pattern == (("no_bounded_ast_proof", 2),)
    assert analytics.by_contract == (("normalize_name", 1),)
    assert analytics.unresolved_by_kind == (("ast_pattern", 2), ("function_contract", 1))
    assert analytics.medium_reportable_by_kind == ()


def test_run_file_review_budgets_and_prioritizes_related_function_contexts(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
                "",
                "local function normalize_name(value)",
                "  local normalized = helper_a(value)",
                "  normalized = helper_local(normalized)",
                "  normalized = helper_b(normalized)",
                "  normalized = helper_c(normalized)",
                "  normalized = helper_d(normalized)",
                "  return normalized",
                "end",
                "",
                "local function helper_local(value)",
                "  return value or ''",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    for helper_name in ("helper_a", "helper_b", "helper_c", "helper_d"):
        (tmp_path / "lib" / f"{helper_name}.lua").write_text(
            "\n".join(
                [
                    f"function {helper_name}(value)",
                    "  return value",
                    "end",
                ]
            ),
            encoding="utf-8",
        )

    snapshot = bootstrap_repository(tmp_path)
    seen: dict[str, tuple[str, ...]] = {}

    class BudgetAwareBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["related_function_contexts"] = packet.related_function_contexts
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("test backend",),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("context budget kept top-ranked evidence",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("context budget kept top-ranked evidence",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    verdicts = run_file_review(snapshot, target_file, backend=BudgetAwareBackend())

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert len(seen["related_function_contexts"]) == 4
    assert seen["related_functions"][:4] == (
        "normalize_name",
        "helper_local",
        "helper_a",
        "helper_b",
    )
    assert "normalize_name @ " in seen["related_function_contexts"][0]
    assert any("helper_local @ " in context for context in seen["related_function_contexts"])
    assert not any("helper_d @ " in context for context in seen["related_function_contexts"])


def test_run_file_review_expands_to_second_hop_only_after_uncertain(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return coerce_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  return ensure_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "ensure.lua").write_text(
        "\n".join(
            [
                "function ensure_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)

    class ExpansionAwareBackend:
        supports_expanded_evidence_retry = True

        def __init__(self) -> None:
            self.calls = 0
            self.seen_contexts: list[tuple[str, ...]] = []

        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            self.calls += 1
            self.seen_contexts.append(packet.related_function_contexts)
            if any("ensure_name @ " in context for context in packet.related_function_contexts):
                return AdjudicationRecord(
                    prosecutor=RoleOpinion(
                        role="prosecutor",
                        status="uncertain",
                        confidence="low",
                        risk_path=(),
                        safety_evidence=(),
                        missing_evidence=("second hop found sanitizer",),
                        recommended_next_action="suppress",
                        suggested_fix=None,
                    ),
                    defender=RoleOpinion(
                        role="defender",
                        status="safe",
                        confidence="medium",
                        risk_path=(),
                        safety_evidence=("ensure_name returns a non-nil fallback",),
                        missing_evidence=(),
                        recommended_next_action="suppress",
                        suggested_fix=None,
                    ),
                    judge=Verdict(
                        case_id=packet.case_id,
                        status="safe",
                        confidence="medium",
                        risk_path=(),
                        safety_evidence=("ensure_name returns a non-nil fallback",),
                        counterarguments_considered=(),
                        suggested_fix=None,
                        needs_human=False,
                    ),
                )
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("need deeper call evidence",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("first hop is still inconclusive",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("first hop is still inconclusive",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    backend = ExpansionAwareBackend()
    verdicts = run_file_review(snapshot, target_file, backend=backend)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert backend.calls == 2
    assert not any("ensure_name @ " in context for context in backend.seen_contexts[0])
    assert any("coerce_name @ " in context for context in backend.seen_contexts[0])
    assert any("ensure_name @ " in context for context in backend.seen_contexts[1])


def test_run_file_review_skips_second_hop_when_agent_does_not_request_expansion(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return coerce_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  return ensure_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "ensure.lua").write_text(
        "\n".join(
            [
                "function ensure_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)

    class NoExpansionBackend:
        supports_expanded_evidence_retry = True

        def __init__(self) -> None:
            self.calls = 0
            self.seen_contexts: list[tuple[str, ...]] = []

        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            self.calls += 1
            self.seen_contexts.append(packet.related_function_contexts)
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("stopping after first hop",),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("no additional expansion requested",),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("first hop remains inconclusive",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    backend = NoExpansionBackend()
    verdicts = run_file_review(snapshot, target_file, backend=backend)

    assert len(verdicts) == 1
    assert verdicts[0].status == "uncertain"
    assert backend.calls == 1
    assert any("coerce_name @ " in context for context in backend.seen_contexts[0])
    assert not any("ensure_name @ " in context for context in backend.seen_contexts[0])


def test_run_file_review_disambiguates_same_name_functions_by_module(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = user.normalizer.normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "user_normalizer.lua").write_text(
        "\n".join(
            [
                "module(\"user.normalizer\", package.seeall)",
                "",
                "function normalize_name(value)",
                "  value = value or 'guest'",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "admin_normalizer.lua").write_text(
        "\n".join(
            [
                "module(\"admin.normalizer\", package.seeall)",
                "",
                "function normalize_name(value)",
                "  return nil",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    seen: dict[str, tuple[str, ...]] = {}

    class ModuleAwareBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["function_summaries"] = packet.function_summaries
            seen["related_function_contexts"] = packet.related_function_contexts
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("module-qualified evidence selected",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("module-qualified evidence selected",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("module-qualified evidence selected",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    verdicts = run_file_review(
        snapshot,
        target_file,
        backend=ModuleAwareBackend(),
        only_unknown_for_agent=False,
    )

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert seen["related_functions"] == ("user.normalizer.normalize_name",)
    assert any(
        "user.normalizer.normalize_name params=" in summary
        for summary in seen["function_summaries"]
    )
    assert not any(
        "admin.normalizer.normalize_name params=" in summary
        for summary in seen["function_summaries"]
    )
    assert any(
        "user.normalizer.normalize_name @ " in context
        for context in seen["related_function_contexts"]
    )
    assert not any(
        "admin.normalizer.normalize_name @ " in context
        for context in seen["related_function_contexts"]
    )


def test_run_file_review_respects_global_require_with_module_style_loading(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "require(\"user.normalizer\")",
                "",
                "local function parse_user()",
                "  local username = user.normalizer.normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "user_normalizer.lua").write_text(
        "\n".join(
            [
                "module(\"user.normalizer\", package.seeall)",
                "",
                "function normalize_name(value)",
                "  value = value or 'guest'",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "admin_normalizer.lua").write_text(
        "\n".join(
            [
                "module(\"admin.normalizer\", package.seeall)",
                "",
                "function normalize_name(value)",
                "  return nil",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    seen: dict[str, tuple[str, ...]] = {}

    class RequireAwareBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["function_summaries"] = packet.function_summaries
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("global require keeps explicit module call stable",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("global require keeps explicit module call stable",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("global require keeps explicit module call stable",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    verdicts = run_file_review(
        snapshot,
        target_file,
        backend=RequireAwareBackend(),
        only_unknown_for_agent=False,
    )

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert seen["related_functions"] == ("user.normalizer.normalize_name",)
    assert any(
        "user.normalizer.normalize_name params=" in summary
        for summary in seen["function_summaries"]
    )
    assert not any("require" in summary for summary in seen["function_summaries"])


def test_run_file_review_surfaces_cross_file_maybe_nil_origin_for_string_find(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.find.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.find",
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
    target_file = tmp_path / "src" / "consumer.lua"
    target_file.write_text(
        "\n".join(
            [
                "require(\"user.lookup\")",
                "",
                "local function scan_user(req)",
                "  local nickname = user.lookup.resolve_name(req)",
                "  return string.find(nickname, '^vip')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "lookup.lua").write_text(
        "\n".join(
            [
                "module(\"user.lookup\", package.seeall)",
                "",
                "function resolve_name(req)",
                "  if req.force_nil then",
                "    return nil",
                "  end",
                "  if req.cached_name then",
                "    return req.cached_name",
                "  end",
                "  if req.profile then",
                "    return req.profile.display_name",
                "  end",
                "  return nil",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_file_review(snapshot, target_file)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")

    seen: dict[str, tuple[str, ...]] = {}

    class CrossFileCaptureBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["function_summaries"] = packet.function_summaries
            seen["related_function_contexts"] = packet.related_function_contexts
            seen["origins"] = _tuple_field(packet.static_reasoning, "origin_candidates")
            seen["risk_summaries"] = tuple(signal.summary for signal in packet.static_risk_signals)
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("captured evidence only",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("captured evidence only",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("captured evidence only",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    run_file_review(snapshot, target_file, backend=CrossFileCaptureBackend())

    assert seen["related_functions"] == ("user.lookup.resolve_name",)
    assert any(
        "user.lookup.resolve_name params=" in summary
        for summary in seen["function_summaries"]
    )
    assert any(
        "user.lookup.resolve_name(req)" in origin
        for origin in seen["origins"]
    )
    assert seen["risk_summaries"] == ("user.lookup.resolve_name(...) may return nil into `nickname`",)
    assert any("resolve_name @ " in context for context in seen["related_function_contexts"])
    assert any("return nil" in context for context in seen["related_function_contexts"])
    assert any("return req.cached_name" in context for context in seen["related_function_contexts"])
    assert any(
        "return req.profile.display_name" in context
        for context in seen["related_function_contexts"]
    )


def test_run_file_review_qualifies_bare_calls_inside_module_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "user_profile.lua"
    target_file.write_text(
        "\n".join(
            [
                "module(\"user.profile\", package.seeall)",
                "",
                "function parse_user(req)",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
                "",
                "function normalize_name(value)",
                "  value = value or 'guest'",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "admin_profile.lua").write_text(
        "\n".join(
            [
                "module(\"admin.profile\", package.seeall)",
                "",
                "function normalize_name(value)",
                "  return nil",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    seen: dict[str, tuple[str, ...]] = {}

    class ModuleCallBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["function_summaries"] = packet.function_summaries
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("module-local bare call resolved",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("module-local bare call resolved",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("module-local bare call resolved",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    verdicts = run_file_review(
        snapshot,
        target_file,
        backend=ModuleCallBackend(),
        only_unknown_for_agent=False,
    )

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert seen["related_functions"] == ("user.profile.normalize_name",)
    assert any(
        "user.profile.normalize_name params=" in summary
        for summary in seen["function_summaries"]
    )
    assert not any(
        "admin.profile.normalize_name params=" in summary
        for summary in seen["function_summaries"]
    )


def test_run_file_review_falls_back_to_global_bare_helper_when_module_symbol_missing(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "user_profile.lua"
    target_file.write_text(
        "\n".join(
            [
                "module(\"user.profile\", package.seeall)",
                "",
                "function parse_user(req)",
                "  local username = normalize_global(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "global_helpers.lua").write_text(
        "\n".join(
            [
                "function normalize_global(value)",
                "  value = value or 'guest'",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    seen: dict[str, tuple[str, ...]] = {}

    class GlobalFallbackBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            seen["related_functions"] = packet.related_functions
            seen["function_summaries"] = packet.function_summaries
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("global helper selected",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("global helper selected",),
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=("global helper selected",),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    verdicts = run_file_review(
        snapshot,
        target_file,
        backend=GlobalFallbackBackend(),
        only_unknown_for_agent=False,
    )

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert seen["related_functions"] == ("normalize_global",)
    assert any(
        "normalize_global params=" in summary
        for summary in seen["function_summaries"]
    )
    assert not any(
        "user.profile.normalize_global params=" in summary
        for summary in seen["function_summaries"]
    )


def test_run_file_review_skips_second_hop_for_backends_without_retry_support(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return coerce_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  return ensure_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "ensure.lua").write_text(
        "\n".join(
            [
                "function ensure_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)

    class LocalExpansionBackend:
        def __init__(self) -> None:
            self.calls = 0
            self.seen_contexts: list[tuple[str, ...]] = []

        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            self.calls += 1
            self.seen_contexts.append(packet.related_function_contexts)
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("wants deeper evidence but is not external",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("still inconclusive",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("no retry support",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    backend = LocalExpansionBackend()
    verdicts = run_file_review(snapshot, target_file, backend=backend)

    assert len(verdicts) == 1
    assert verdicts[0].status == "uncertain"
    assert backend.calls == 1
    assert any("coerce_name @ " in context for context in backend.seen_contexts[0])
    assert not any("ensure_name @ " in context for context in backend.seen_contexts[0])


def test_run_file_review_skips_second_hop_for_cli_backends_with_internal_retries(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return coerce_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  return ensure_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "ensure.lua").write_text(
        "\n".join(
            [
                "function ensure_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)

    class RetryingCliBackend(CliAgentBackend):
        def __init__(self) -> None:
            super().__init__(max_attempts=2)
            self.calls = 0
            self.seen_contexts: list[tuple[str, ...]] = []

        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            self.calls += 1
            self.seen_contexts.append(packet.related_function_contexts)
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("CLI backend already has internal retries",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("do not stack a second review retry",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("internal retries already configured",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    backend = RetryingCliBackend()
    verdicts = run_file_review(snapshot, target_file, backend=backend)

    assert len(verdicts) == 1
    assert verdicts[0].status == "uncertain"
    assert backend.calls == 1
    assert any("coerce_name @ " in context for context in backend.seen_contexts[0])
    assert not any("ensure_name @ " in context for context in backend.seen_contexts[0])


def test_run_file_review_allows_explicit_cli_retry_override(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return coerce_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  return ensure_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "ensure.lua").write_text(
        "\n".join(
            [
                "function ensure_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)

    class OverriddenCliBackend(CliAgentBackend):
        def __init__(self) -> None:
            super().__init__(max_attempts=2, expanded_evidence_retry=True)
            self.calls = 0
            self.seen_contexts: list[tuple[str, ...]] = []

        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            del sink_rule
            self.calls += 1
            self.seen_contexts.append(packet.related_function_contexts)
            if any("ensure_name @ " in context for context in packet.related_function_contexts):
                return AdjudicationRecord(
                    prosecutor=RoleOpinion(
                        role="prosecutor",
                        status="uncertain",
                        confidence="low",
                        risk_path=(),
                        safety_evidence=(),
                        missing_evidence=("override enabled deeper evidence",),
                        recommended_next_action="suppress",
                        suggested_fix=None,
                    ),
                    defender=RoleOpinion(
                        role="defender",
                        status="safe",
                        confidence="medium",
                        risk_path=(),
                        safety_evidence=("ensure_name returns a non-nil fallback",),
                        missing_evidence=(),
                        recommended_next_action="suppress",
                        suggested_fix=None,
                    ),
                    judge=Verdict(
                        case_id=packet.case_id,
                        status="safe",
                        confidence="medium",
                        risk_path=(),
                        safety_evidence=("ensure_name returns a non-nil fallback",),
                        counterarguments_considered=(),
                        suggested_fix=None,
                        needs_human=False,
                    ),
                )
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("need deeper call evidence",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("first hop is still inconclusive",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("first hop is still inconclusive",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    backend = OverriddenCliBackend()
    verdicts = run_file_review(snapshot, target_file, backend=backend)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert backend.calls == 2
    assert not any("ensure_name @ " in context for context in backend.seen_contexts[0])
    assert any("ensure_name @ " in context for context in backend.seen_contexts[1])


def test_benchmark_repository_review_reports_semantic_accuracy(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)

    snapshot = bootstrap_repository(runtime_root)
    summary = benchmark_repository_review(snapshot, backend=StrictEvidenceBackend())

    assert summary.total_cases == 18
    assert summary.exact_matches == 13
    assert summary.expected_risky == 5
    assert summary.expected_safe == 8
    assert summary.expected_uncertain == 5
    assert summary.actual_risky == 10
    assert summary.actual_safe == 8
    assert summary.actual_uncertain == 0
    assert summary.false_positive_risks == 5
    assert summary.missed_risks == 0
    assert summary.unresolved_cases == 0
    assert summary.backend_fallbacks == 0
    assert summary.backend_timeouts == 0
    assert summary.backend_cache_hits == 0
    assert summary.backend_cache_misses == 0
    assert summary.backend_calls == 0
    assert summary.backend_warmup_calls == 0
    assert summary.backend_review_calls == 0
    assert summary.backend_total_seconds == 0.0
    assert summary.backend_warmup_total_seconds == 0.0
    assert summary.backend_review_total_seconds == 0.0
    assert summary.backend_average_seconds == 0.0
    assert summary.backend_review_average_seconds == 0.0
    assert summary.ast_primary_cases + summary.ast_fallback_to_legacy_cases + summary.legacy_only_cases == 18
    assert summary.backend_name == "StrictEvidenceBackend"
    assert summary.backend_model is None
    assert summary.backend_executable is None
    assert sum(1 for case in summary.cases if case.matches_expectation) == 13


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
    assert summary.backend_warmup_calls == 0
    assert summary.backend_review_calls == 1
    assert summary.backend_total_seconds >= 0.0
    assert summary.backend_warmup_total_seconds == 0.0
    assert summary.backend_review_total_seconds >= 0.0
    assert summary.backend_average_seconds >= 0.0
    assert summary.backend_review_average_seconds >= 0.0
    assert summary.backend_name == "codex"
    assert summary.backend_executable == "codex"
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
    backend.backend_warmup_call_count = 1
    backend.backend_warmup_total_seconds = 0.25
    summary = benchmark_repository_review(snapshot, backend=backend)

    assert summary.backend_cache_hits == 7
    assert summary.backend_cache_misses == 11
    assert summary.backend_calls == 4
    assert summary.backend_warmup_calls == 1
    assert summary.backend_review_calls == 3
    assert summary.backend_total_seconds == 1.25
    assert summary.backend_warmup_total_seconds == 0.25
    assert summary.backend_review_total_seconds == 1.0
    assert summary.backend_average_seconds == 0.3125
    assert summary.backend_review_average_seconds == pytest.approx(1.0 / 3.0)
    assert summary.backend_name == "StrictEvidenceBackend"


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
    assert comparison.cold.backend_warmup_calls == 0
    assert comparison.cold.backend_review_calls == 18
    assert comparison.warm.backend_cache_hits == 18
    assert comparison.warm.backend_cache_misses == 0
    assert comparison.warm.backend_calls == 0
    assert comparison.warm.backend_warmup_calls == 0
    assert comparison.warm.backend_review_calls == 0


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


def test_export_autofix_patches_writes_patch_file_in_audit_mode(tmp_path: Path) -> None:
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

    patches = export_autofix_patches(snapshot, output_path=output_path, audit_mode=True)

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
