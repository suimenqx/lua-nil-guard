from __future__ import annotations

from .models import EvidencePacket, StaticProof, Verdict, VerificationSummary


_SAFE_VERIFY_THRESHOLD = 80
_SAFE_ELEVATE_THRESHOLD = 50
_CONFIDENCE_ORDER = ("low", "medium", "high")


def verify_verdict(verdict: Verdict, packet: EvidencePacket) -> Verdict:
    """Apply a lightweight automatic verification pass to a verdict."""

    observed_guards = _tuple_field(packet, "observed_guards")

    if verdict.status == "risky" and not observed_guards and verdict.risk_path:
        return Verdict(
            case_id=verdict.case_id,
            status="risky_verified",
            confidence="high",
            risk_path=verdict.risk_path,
            safety_evidence=verdict.safety_evidence,
            counterarguments_considered=verdict.counterarguments_considered,
            suggested_fix=verdict.suggested_fix,
            needs_human=False,
            autofix_patch=verdict.autofix_patch,
            verification_summary=VerificationSummary(
                mode="risk_no_guard",
                evidence=verdict.risk_path,
            ),
        )

    if verdict.status == "safe":
        proofs = packet.static_proofs
        if proofs:
            strongest_proof = _strongest_safe_proof(proofs)
            strongest_score = _safe_verification_score(proofs)
            proof_summaries = _proof_summaries(proofs)
            safety_evidence = verdict.safety_evidence or proof_summaries
            verification_summary = VerificationSummary(
                mode="structured_static_proof",
                strongest_proof_kind=strongest_proof.kind,
                strongest_proof_depth=strongest_proof.depth,
                strongest_proof_summary=strongest_proof.summary,
                verification_score=strongest_score,
                evidence=proof_summaries,
            )

            if strongest_score >= _SAFE_VERIFY_THRESHOLD:
                return Verdict(
                    case_id=verdict.case_id,
                    status="safe_verified",
                    confidence="high",
                    risk_path=(),
                    safety_evidence=safety_evidence,
                    counterarguments_considered=verdict.counterarguments_considered,
                    suggested_fix=None,
                    needs_human=False,
                    autofix_patch=None,
                    verification_summary=verification_summary,
                )

            if strongest_score >= _SAFE_ELEVATE_THRESHOLD:
                elevated_confidence = _max_confidence(
                    verdict.confidence,
                    _safe_confidence_floor(strongest_score),
                )
                if (
                    elevated_confidence != verdict.confidence
                    or safety_evidence != verdict.safety_evidence
                    or verification_summary != verdict.verification_summary
                ):
                    return Verdict(
                        case_id=verdict.case_id,
                        status="safe",
                        confidence=elevated_confidence,
                        risk_path=verdict.risk_path,
                        safety_evidence=safety_evidence,
                        counterarguments_considered=verdict.counterarguments_considered,
                        suggested_fix=verdict.suggested_fix,
                        needs_human=verdict.needs_human,
                        autofix_patch=verdict.autofix_patch,
                        verification_summary=verification_summary,
                    )
                return verdict

            return verdict

        if observed_guards:
            return Verdict(
                case_id=verdict.case_id,
                status="safe_verified",
                confidence="high",
                risk_path=(),
                safety_evidence=verdict.safety_evidence or observed_guards,
                counterarguments_considered=verdict.counterarguments_considered,
                suggested_fix=None,
                needs_human=False,
                autofix_patch=None,
                verification_summary=VerificationSummary(
                    mode="legacy_observed_guards",
                    evidence=verdict.safety_evidence or observed_guards,
                ),
            )

    return verdict


def _tuple_field(packet: EvidencePacket, key: str) -> tuple[str, ...]:
    value = packet.static_reasoning.get(key, ())
    if isinstance(value, tuple):
        return value
    return ()


def _safe_proof_score(proof: StaticProof) -> int:
    base_scores = {
        "direct_guard": 100,
        "early_exit_guard": 100,
        "assert_guard": 100,
        "contract_guard": 95,
        "local_defaulting": 95,
        "return_contract": 90,
        "wrapper_defaulting": 85,
        "chained_return_contract": 80,
        "wrapper_passthrough": 70,
    }
    base = base_scores.get(proof.kind, 60)
    if proof.kind == "wrapper_defaulting":
        penalty = 5 * max(0, proof.depth)
    elif proof.kind in {"chained_return_contract", "wrapper_passthrough"}:
        penalty = 10 * max(0, proof.depth - 1)
    else:
        penalty = 0
    return max(0, base - penalty)


def _safe_verification_score(proofs: tuple[StaticProof, ...]) -> int:
    scored_proofs = sorted((_safe_proof_score(proof) for proof in proofs), reverse=True)
    strongest_score = scored_proofs[0]
    corroboration_bonus = min(
        10,
        5 * sum(1 for score in scored_proofs[1:] if score >= 60),
    )
    return min(100, strongest_score + corroboration_bonus)


def _strongest_safe_proof(proofs: tuple[StaticProof, ...]) -> StaticProof:
    return max(
        proofs,
        key=lambda proof: (_safe_proof_score(proof), -proof.depth, proof.kind, proof.summary),
    )


def _safe_confidence_floor(score: int) -> str:
    if score >= 70:
        return "high"
    return "medium"


def _proof_summaries(proofs: tuple[StaticProof, ...]) -> tuple[str, ...]:
    ordered_proofs = sorted(
        proofs,
        key=lambda proof: (-_safe_proof_score(proof), proof.depth, proof.kind, proof.summary),
    )
    seen: set[str] = set()
    summaries: list[str] = []
    for proof in ordered_proofs:
        if proof.summary in seen:
            continue
        summaries.append(proof.summary)
        seen.add(proof.summary)
    return tuple(summaries)


def _max_confidence(current: str, minimum: str) -> str:
    try:
        current_rank = _CONFIDENCE_ORDER.index(current)
    except ValueError:
        current_rank = -1
    try:
        minimum_rank = _CONFIDENCE_ORDER.index(minimum)
    except ValueError:
        minimum_rank = -1
    return _CONFIDENCE_ORDER[max(current_rank, minimum_rank)]
