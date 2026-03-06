from __future__ import annotations

from lua_nil_guard.models import (
    CandidateCase,
    EvidencePacket,
    EvidenceTarget,
    SinkRule,
    StaticProof,
    StaticRiskSignal,
)
from lua_nil_guard.pipeline import build_evidence_packet
from lua_nil_guard.prompting import build_single_pass_prompt


def _make_rule() -> SinkRule:
    return SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''", "assert(x)"),
    )


def _make_packet(**overrides) -> EvidencePacket:  # type: ignore[no-untyped-def]
    defaults = dict(
        case_id="case_007",
        target=EvidenceTarget(
            file="foo/bar.lua",
            line=42,
            column=3,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="local username = req.params.username\nreturn string.match(username, '^a')",
        related_functions=("normalize_name",),
        function_summaries=("normalize_name always returns string",),
        knowledge_facts=("req.params may be nil",),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
        static_proofs=(),
        static_risk_signals=(),
        related_function_contexts=(),
    )
    defaults.update(overrides)
    return EvidencePacket(**defaults)


def test_prompt_includes_target_metadata() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    assert "case_007" in prompt
    assert "foo/bar.lua" in prompt
    assert "string.match" in prompt
    assert "username" in prompt


def test_prompt_includes_local_context() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    assert "req.params.username" in prompt
    assert "string.match(username" in prompt


def test_prompt_includes_static_reasoning() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    assert "unknown_static" in prompt
    assert "req.params.username" in prompt


def test_prompt_includes_canonical_principles() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    assert "Unknown is not risk." in prompt
    assert "Absence of proof is not proof of bug." in prompt


def test_prompt_does_not_contain_role_words() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    lower = prompt.lower()
    assert "prosecutor" not in lower
    assert "defender" not in lower
    assert "judge" not in lower


def test_prompt_includes_json_schema_requirement() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    assert '"status"' in prompt
    assert '"confidence"' in prompt
    assert '"risk_path"' in prompt
    assert '"safety_evidence"' in prompt


def test_prompt_includes_function_summaries_and_knowledge_facts() -> None:
    prompt = build_single_pass_prompt(packet=_make_packet(), sink_rule=_make_rule())

    assert "normalize_name always returns string" in prompt
    assert "req.params may be nil" in prompt


def test_prompt_includes_related_function_contexts() -> None:
    packet = _make_packet(
        related_function_contexts=(
            "normalize_name @ lib/normalizer.lua:1\nfunction normalize_name(value)\n  value = value or ''",
        ),
    )
    prompt = build_single_pass_prompt(packet=packet, sink_rule=_make_rule())

    assert "normalize_name @ lib/normalizer.lua:1" in prompt


def test_prompt_includes_static_proofs_and_risk_signals() -> None:
    proof = StaticProof(
        kind="direct_guard",
        summary="if username then",
        subject="username",
        source_symbol="username",
    )
    signal = StaticRiskSignal(
        kind="direct_sink_field_path",
        summary="req.params.username reaches string.match directly",
        subject="req.params.username",
    )
    packet = _make_packet(static_proofs=(proof,), static_risk_signals=(signal,))
    prompt = build_single_pass_prompt(packet=packet, sink_rule=_make_rule())

    assert "direct_guard" in prompt
    assert "direct_sink_field_path" in prompt


def test_prompt_empty_knowledge_shows_none() -> None:
    packet = _make_packet(
        knowledge_facts=(),
        function_summaries=(),
        related_function_contexts=(),
    )
    prompt = build_single_pass_prompt(packet=packet, sink_rule=_make_rule())

    # Should have "(none)" for empty sections
    assert "(none)" in prompt
