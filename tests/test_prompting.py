from __future__ import annotations

from pathlib import Path

import pytest

from lua_nil_review_agent.models import CandidateCase, SinkRule, StaticProof
from lua_nil_review_agent.pipeline import build_evidence_packet
from lua_nil_review_agent.prompting import build_adjudication_prompt


ROOT = Path(__file__).resolve().parents[1]


def test_build_adjudication_prompt_includes_evidence_and_hard_rules() -> None:
    candidate = CandidateCase(
        case_id="case_007",
        file="foo/bar.lua",
        line=42,
        column=3,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="parse_user",
        static_state="unknown_static",
    )
    packet = build_evidence_packet(
        candidate=candidate,
        local_context="local username = req.params.username",
        related_functions=("normalize_name",),
        function_summaries=("normalize_name always returns string",),
        knowledge_facts=("req.params may be nil",),
        origin_candidates=("req.params.username",),
        observed_guards=("if username then",),
        origin_return_slots=(1,),
        analysis_mode="ast_primary",
        unknown_reason="unsupported_control_flow",
        origin_analysis_mode="ast_origin_fallback_to_legacy",
        origin_unknown_reason="no_bounded_ast_origin",
        related_function_contexts=(
            "normalize_name @ lib/normalizer.lua:1\nfunction normalize_name(value)\n  value = value or ''",
        ),
        static_proofs=(
            StaticProof(
                kind="direct_guard",
                summary="if username then",
                subject="username",
                source_symbol="username",
                provenance=("an active positive branch requires `username` to be truthy",),
            ),
        ),
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''", "assert(x)"),
    )

    prompt = build_adjudication_prompt(packet=packet, sink_rule=rule)

    assert "case_007" in prompt
    assert "foo/bar.lua" in prompt
    assert "string.match" in prompt
    assert "req.params may be nil" in prompt
    assert "origin_return_slots: 1" in prompt
    assert "analysis_mode: ast_primary" in prompt
    assert "unknown_reason: unsupported_control_flow" in prompt
    assert "origin_analysis_mode: ast_origin_fallback_to_legacy" in prompt
    assert "origin_unknown_reason: no_bounded_ast_origin" in prompt
    assert "proof_kinds: direct_guard" in prompt
    assert "Structured static proofs:" in prompt
    assert "Static verification preview:" in prompt
    assert "strongest_proof_kind: direct_guard" in prompt
    assert "[direct_guard] if username then" in prompt
    assert "Calibration examples:" in prompt
    assert "Example (direct_guard):" in prompt
    assert "Example (unsupported_control_flow):" in prompt
    assert "Example (no_bounded_ast_origin):" in prompt
    assert "Example (verification_summary):" in prompt
    assert "Role calibration:" in prompt
    assert "Prosecutor: try to break the current proof chain" in prompt
    assert "Related function contexts:" in prompt
    assert "normalize_name @ lib/normalizer.lua:1" in prompt
    assert "Adjudication policy: lua-nil-adjudicator" in prompt
    assert "Required review order:" in prompt
    assert "Unknown is not risk." in prompt
    assert "Absence of proof is not proof of bug." in prompt


def test_build_adjudication_prompt_uses_compiled_skill_header(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = CandidateCase(
        case_id="case_skill_header",
        file="foo.lua",
        line=1,
        column=1,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="name",
        symbol="name",
        function_scope="demo",
        static_state="unknown_static",
    )
    packet = build_evidence_packet(
        candidate=candidate,
        local_context="return string.match(name, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        origin_candidates=(),
        observed_guards=(),
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=(),
    )

    monkeypatch.setattr(
        "lua_nil_review_agent.prompting.compile_adjudicator_skill_header",
        lambda skill_path=None, strict=True: "SKILL HEADER FOR TESTS",
    )

    prompt = build_adjudication_prompt(packet=packet, sink_rule=rule)

    assert prompt.startswith("SKILL HEADER FOR TESTS")


def test_build_adjudication_prompt_limits_calibration_examples_to_relevant_items() -> None:
    candidate = CandidateCase(
        case_id="case_calibration",
        file="foo.lua",
        line=3,
        column=2,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="value",
        symbol="value",
        function_scope="demo",
        static_state="safe_static",
    )
    packet = build_evidence_packet(
        candidate=candidate,
        local_context="return string.match(value, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        origin_candidates=("normalize_name(req.params.username)",),
        observed_guards=("normalize_name(...) returns non-nil",),
        static_proofs=(
            StaticProof(
                kind="return_contract",
                summary="normalize_name(...) returns non-nil",
                subject="value",
                depth=0,
            ),
            StaticProof(
                kind="wrapper_defaulting",
                summary="wrap_name(...) preserves or defaults to non-nil",
                subject="value",
                depth=1,
            ),
            StaticProof(
                kind="wrapper_defaulting",
                summary="finalize_name(...) preserves or defaults to non-nil",
                subject="value",
                depth=2,
            ),
        ),
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=(),
    )

    prompt = build_adjudication_prompt(packet=packet, sink_rule=rule)

    assert prompt.count("Example (return_contract):") == 1
    assert prompt.count("Example (wrapper_defaulting):") == 1
    assert "Example (proof_depth):" in prompt


def test_skill_file_exists_with_required_frontmatter() -> None:
    skill_path = ROOT / "skills" / "lua-nil-adjudicator" / "SKILL.md"

    assert skill_path.exists()
    content = skill_path.read_text(encoding="utf-8")
    assert content.startswith("---\nname: lua-nil-adjudicator\n")
    assert "skill_contract: lua-nil-adjudicator/v1" in content
    assert "Return `uncertain` when evidence is incomplete." in content
    assert "Unknown is not risk." in content
    assert "Absence of proof is not proof of bug." in content
