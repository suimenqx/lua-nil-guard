from __future__ import annotations

from lua_nil_guard.adjudication import adjudicate_packet, adjudicate_single_pass
from lua_nil_guard.models import (
    EvidencePacket,
    EvidenceTarget,
    SinglePassJudgment,
    SinkRule,
    StaticProof,
    StaticRiskSignal,
)


def _make_rule() -> SinkRule:
    return SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("if x then ... end",),
    )


def _make_packet(
    *,
    case_id: str = "case_001",
    observed_guards: tuple[str, ...] = (),
    origin_candidates: tuple[str, ...] = (),
    knowledge_facts: tuple[str, ...] = (),
    static_proofs: tuple[StaticProof, ...] = (),
    static_risk_signals: tuple[StaticRiskSignal, ...] = (),
    local_context: str = "local username = req.params.username\nreturn string.match(username, '^a')",
) -> EvidencePacket:
    return EvidencePacket(
        case_id=case_id,
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=8,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context=local_context,
        related_functions=(),
        function_summaries=(),
        knowledge_facts=knowledge_facts,
        static_reasoning={
            "state": "unknown_static" if not observed_guards else "safe_static",
            "origin_candidates": origin_candidates,
            "observed_guards": observed_guards,
        },
        static_proofs=static_proofs,
        static_risk_signals=static_risk_signals,
    )


def test_single_pass_returns_safe_when_guard_exists() -> None:
    packet = _make_packet(observed_guards=("if username then",))
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert isinstance(result, SinglePassJudgment)
    assert result.verdict.status == "safe"
    assert result.verdict.confidence == "high"
    assert result.verdict.safety_evidence == ("if username then",)


def test_single_pass_returns_risky_when_no_guard_and_no_safety_evidence() -> None:
    packet = _make_packet(origin_candidates=("req.params.username",))
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert result.verdict.status == "risky"
    assert result.verdict.confidence == "medium"
    assert len(result.verdict.risk_path) > 0


def test_single_pass_returns_uncertain_when_evidence_insufficient() -> None:
    packet = _make_packet()
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert result.verdict.status == "uncertain"
    assert result.verdict.confidence == "low"


def test_single_pass_judgment_has_raw_response_and_metadata() -> None:
    packet = _make_packet(observed_guards=("if username then",))
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert isinstance(result.raw_response, str)
    assert isinstance(result.backend_metadata, dict)


def test_single_pass_uses_static_proofs_for_safe_verdict() -> None:
    proof = StaticProof(
        kind="direct_guard",
        summary="if username then",
        subject="username",
        source_symbol="username",
        provenance=("an active positive branch requires `username` to be truthy",),
    )
    packet = _make_packet(
        observed_guards=("if username then",),
        static_proofs=(proof,),
    )
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert result.verdict.status == "safe"


def test_single_pass_uses_risk_signals() -> None:
    signal = StaticRiskSignal(
        kind="direct_sink_field_path",
        summary="req.params.username reaches string.match directly",
        subject="req.params.username",
        source_expression="req.params.username",
    )
    packet = _make_packet(static_risk_signals=(signal,))
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert result.verdict.status == "risky"
    assert result.verdict.confidence == "high"


def test_single_pass_autofix_patch_attached() -> None:
    packet = _make_packet(origin_candidates=("req.params.username",))
    rule = _make_rule()

    result = adjudicate_single_pass(packet, rule)

    assert result.verdict.suggested_fix is not None


def test_single_pass_agrees_with_multi_agent_judge() -> None:
    """Regression: single-pass verdict status should match multi-agent judge status."""
    rule = _make_rule()

    # Case 1: safe with guard
    packet_safe = _make_packet(
        case_id="safe_case",
        observed_guards=("if username then",),
        local_context="if username then\n  return string.match(username, '^a')\nend",
    )
    sp = adjudicate_single_pass(packet_safe, rule)
    ma = adjudicate_packet(packet_safe, rule)
    assert sp.verdict.status == ma.judge.status

    # Case 2: risky with origins
    packet_risky = _make_packet(
        case_id="risky_case",
        origin_candidates=("req.params.username",),
    )
    sp = adjudicate_single_pass(packet_risky, rule)
    ma = adjudicate_packet(packet_risky, rule)
    assert sp.verdict.status == ma.judge.status

    # Case 3: risky with risk signals
    signal = StaticRiskSignal(
        kind="direct_sink_field_path",
        summary="req.params.username reaches string.match directly",
        subject="req.params.username",
        source_expression="req.params.username",
    )
    packet_risk_signal = _make_packet(
        case_id="risk_signal_case",
        static_risk_signals=(signal,),
    )
    sp = adjudicate_single_pass(packet_risk_signal, rule)
    ma = adjudicate_packet(packet_risk_signal, rule)
    assert sp.verdict.status == ma.judge.status

    # Case 4: safe via knowledge fact
    packet_knowledge = _make_packet(
        case_id="knowledge_case",
        knowledge_facts=("normalize_name always returns non-nil string",),
    )
    sp = adjudicate_single_pass(packet_knowledge, rule)
    ma = adjudicate_packet(packet_knowledge, rule)
    assert sp.verdict.status == ma.judge.status
