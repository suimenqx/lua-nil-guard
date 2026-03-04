from __future__ import annotations

from lua_nil_guard.models import CandidateCase, ConfidencePolicy, StaticProof, StaticRiskSignal, Verdict
from lua_nil_guard.pipeline import build_evidence_packet, should_report


def test_build_evidence_packet_preserves_core_case_data() -> None:
    candidate = CandidateCase(
        case_id="case_001",
        file="foo/bar.lua",
        line=18,
        column=9,
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
        knowledge_facts=("normalize_name always returns string", "req.params may be nil"),
        origin_candidates=("req.params.username",),
        observed_guards=(),
        origin_return_slots=(1,),
        analysis_mode="ast_primary",
        unknown_reason="unsupported_control_flow",
        origin_analysis_mode="ast_origin_fallback_to_legacy",
        origin_unknown_reason="no_bounded_ast_origin",
        static_proofs=(
            StaticProof(
                kind="direct_guard",
                summary="if username then",
                subject="username",
                source_symbol="username",
                provenance=("an active positive branch requires `username` to be truthy",),
            ),
        ),
        static_risk_signals=(
            StaticRiskSignal(
                kind="direct_sink_field_path",
                summary="req.params.username reaches string.match directly",
                subject="req.params.username",
            ),
        ),
    )

    assert packet.case_id == "case_001"
    assert packet.target.file == "foo/bar.lua"
    assert packet.target.sink == "string.match"
    assert packet.target.arg_index == 1
    assert packet.static_reasoning["origin_candidates"] == ("req.params.username",)
    assert packet.static_reasoning["origin_return_slots"] == ("1",)
    assert packet.static_reasoning["analysis_mode"] == "ast_primary"
    assert packet.static_reasoning["unknown_reason"] == "unsupported_control_flow"
    assert packet.static_reasoning["origin_analysis_mode"] == "ast_origin_fallback_to_legacy"
    assert packet.static_reasoning["origin_unknown_reason"] == "no_bounded_ast_origin"
    assert packet.static_reasoning["proof_kinds"] == ("direct_guard",)
    assert packet.static_reasoning["proof_summaries"] == ("if username then",)
    assert packet.static_reasoning["risk_kinds"] == ("direct_sink_field_path",)
    assert packet.static_reasoning["risk_summaries"] == ("req.params.username reaches string.match directly",)
    assert packet.static_proofs[0].subject == "username"
    assert packet.static_risk_signals[0].subject == "req.params.username"
    assert packet.knowledge_facts == (
        "normalize_name always returns string",
        "req.params may be nil",
    )


def test_should_report_requires_risky_status_and_threshold() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )

    assert should_report(
        Verdict(
            case_id="case_001",
            status="risky",
            confidence="high",
            risk_path=("username <- req.params.username",),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix="local safe_name = username or ''",
            needs_human=False,
        ),
        policy,
    )
    assert not should_report(
        Verdict(
            case_id="case_002",
            status="uncertain",
            confidence="high",
            risk_path=(),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        ),
        policy,
    )
    assert not should_report(
        Verdict(
            case_id="case_003",
            status="risky",
            confidence="medium",
            risk_path=("maybe nil source",),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        ),
        policy,
    )


def test_should_report_can_include_medium_in_audit_mode() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )

    verdict = Verdict(
        case_id="case_004",
        status="risky",
        confidence="medium",
        risk_path=("username <- maybe_nil()",),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
    )

    assert should_report(verdict, policy, audit_mode=True)
