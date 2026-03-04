from __future__ import annotations

from .models import CandidateCase, ConfidencePolicy, EvidencePacket, EvidenceTarget, StaticProof, Verdict


def build_evidence_packet(
    *,
    candidate: CandidateCase,
    local_context: str,
    related_functions: tuple[str, ...],
    function_summaries: tuple[str, ...],
    knowledge_facts: tuple[str, ...],
    origin_candidates: tuple[str, ...],
    observed_guards: tuple[str, ...],
    origin_usage_modes: tuple[str, ...] = (),
    origin_return_slots: tuple[int, ...] = (),
    analysis_mode: str = "legacy_only",
    unknown_reason: str | None = None,
    related_function_contexts: tuple[str, ...] = (),
    static_proofs: tuple[StaticProof, ...] = (),
) -> EvidencePacket:
    """Assemble the normalized context bundle for agent adjudication."""

    return EvidencePacket(
        case_id=candidate.case_id,
        target=EvidenceTarget(
            file=candidate.file,
            line=candidate.line,
            column=candidate.column,
            sink=candidate.sink_name,
            arg_index=candidate.arg_index,
            expression=candidate.expression,
        ),
        local_context=local_context,
        related_functions=tuple(related_functions),
        function_summaries=tuple(function_summaries),
        knowledge_facts=tuple(knowledge_facts),
        static_reasoning={
            "state": candidate.static_state,
            "origin_candidates": tuple(origin_candidates),
            "origin_usage_modes": tuple(origin_usage_modes),
            "origin_return_slots": tuple(str(slot) for slot in origin_return_slots),
            "observed_guards": tuple(observed_guards),
            "proof_kinds": tuple(proof.kind for proof in static_proofs),
            "proof_summaries": tuple(proof.summary for proof in static_proofs),
            "analysis_mode": analysis_mode,
            "unknown_reason": unknown_reason or "",
        },
        related_function_contexts=tuple(related_function_contexts),
        static_proofs=tuple(static_proofs),
    )


def should_report(
    verdict: Verdict,
    policy: ConfidencePolicy,
    *,
    audit_mode: bool = False,
) -> bool:
    """Apply the precision-first reporting threshold."""

    if not verdict.status.startswith("risky"):
        return False

    if audit_mode and policy.default_include_medium_in_audit and verdict.confidence == "medium":
        return True

    return _confidence_rank(verdict.confidence, policy) >= _confidence_rank(
        policy.default_report_min_confidence,
        policy,
    )


def _confidence_rank(level: str, policy: ConfidencePolicy) -> int:
    try:
        return policy.levels.index(level)
    except ValueError:
        return -1
