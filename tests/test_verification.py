from __future__ import annotations

from lua_nil_review_agent.models import (
    EvidencePacket,
    EvidenceTarget,
    StaticProof,
    Verdict,
)
from lua_nil_review_agent.verification import preview_static_verification, verify_verdict


def test_verify_verdict_upgrades_clear_risk_to_risky_verified() -> None:
    verdict = Verdict(
        case_id="case_risky",
        status="risky",
        confidence="medium",
        risk_path=("username <- req.params.username", "no guard before string.match"),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix="local safe_value = username or ''",
        needs_human=False,
    )
    packet = EvidencePacket(
        case_id="case_risky",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="local username = req.params.username\nreturn string.match(username, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "risky_verified"
    assert result.confidence == "high"
    assert result.verification_summary is not None
    assert result.verification_summary.mode == "risk_no_guard"


def test_verify_verdict_upgrades_safe_to_safe_verified_when_guard_exists() -> None:
    verdict = Verdict(
        case_id="case_safe",
        status="safe",
        confidence="medium",
        risk_path=(),
        safety_evidence=("if username then",),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
    )
    packet = EvidencePacket(
        case_id="case_safe",
        target=EvidenceTarget(
            file="demo.lua",
            line=3,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="if username then\n  return string.match(username, '^a')\nend",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "safe_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": ("if username then",),
        },
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "safe_verified"
    assert result.confidence == "high"
    assert result.verification_summary is not None
    assert result.verification_summary.mode == "legacy_observed_guards"


def test_verify_verdict_upgrades_safe_to_safe_verified_for_strong_static_proof() -> None:
    verdict = Verdict(
        case_id="case_safe_structured",
        status="safe",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
    )
    packet = EvidencePacket(
        case_id="case_safe_structured",
        target=EvidenceTarget(
            file="demo.lua",
            line=4,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="if username then\n  return string.match(username, '^a')\nend",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "safe_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": ("if username then",),
        },
        static_proofs=(
            StaticProof(
                kind="direct_guard",
                summary="if username then",
                subject="username",
            ),
        ),
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "safe_verified"
    assert result.confidence == "high"
    assert result.safety_evidence == ("if username then",)
    assert result.verification_summary is not None
    assert result.verification_summary.mode == "structured_static_proof"
    assert result.verification_summary.strongest_proof_kind == "direct_guard"
    assert result.verification_summary.strongest_proof_depth == 0
    assert result.verification_summary.verification_score == 100


def test_preview_static_verification_reports_strongest_proof_and_depth() -> None:
    preview = preview_static_verification(
        (
            StaticProof(
                kind="wrapper_defaulting",
                summary="wrap_name(...) preserves or defaults to non-nil",
                subject="username",
                depth=1,
            ),
            StaticProof(
                kind="direct_guard",
                summary="if username then",
                subject="username",
                depth=0,
            ),
        )
    )

    assert preview is not None
    assert preview.mode == "structured_static_proof_preview"
    assert preview.strongest_proof_kind == "direct_guard"
    assert preview.strongest_proof_depth == 0
    assert preview.verification_score == 100


def test_verify_verdict_elevates_safe_confidence_for_deep_chained_proof() -> None:
    verdict = Verdict(
        case_id="case_safe_chained",
        status="safe",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=True,
    )
    packet = EvidencePacket(
        case_id="case_safe_chained",
        target=EvidenceTarget(
            file="demo.lua",
            line=7,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="final_name",
        ),
        local_context="local final_name = finalize_name(raw_name)\nreturn string.match(final_name, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "safe_static",
            "origin_candidates": ("finalize_name(raw_name)",),
            "observed_guards": ("finalize_name(...) returns non-nil",),
        },
        static_proofs=(
            StaticProof(
                kind="chained_return_contract",
                summary="finalize_name(...) returns non-nil",
                subject="final_name",
                source_call="finalize_name(raw_name)",
                depth=3,
            ),
        ),
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "safe"
    assert result.confidence == "medium"
    assert result.needs_human is True
    assert result.safety_evidence == ("finalize_name(...) returns non-nil",)
    assert result.verification_summary is not None
    assert result.verification_summary.mode == "structured_static_proof"
    assert result.verification_summary.strongest_proof_kind == "chained_return_contract"
    assert result.verification_summary.strongest_proof_depth == 3
    assert result.verification_summary.verification_score == 60


def test_verify_verdict_does_not_let_legacy_guards_override_weak_structured_proof() -> None:
    verdict = Verdict(
        case_id="case_safe_weak_structured",
        status="safe",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
    )
    packet = EvidencePacket(
        case_id="case_safe_weak_structured",
        target=EvidenceTarget(
            file="demo.lua",
            line=9,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="return string.match(wrap_name(username), '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "safe_static",
            "origin_candidates": ("wrap_name(username)",),
            "observed_guards": ("wrap_name(...) preserves non-nil",),
        },
        static_proofs=(
            StaticProof(
                kind="wrapper_passthrough",
                summary="wrap_name(...) preserves non-nil",
                subject="username",
                source_call="wrap_name(username)",
                depth=4,
            ),
        ),
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "safe"
    assert result.confidence == "low"
    assert result.safety_evidence == ()
    assert result.verification_summary is None
