from __future__ import annotations

from .models import EvidencePacket, StaticProof, Verdict


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
        )

    if verdict.status == "safe":
        proofs = packet.static_proofs
        if proofs:
            strongest_score = _safe_verification_score(proofs)
            safety_evidence = verdict.safety_evidence or _proof_summaries(proofs)

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
                )

            if strongest_score >= _SAFE_ELEVATE_THRESHOLD:
                elevated_confidence = _max_confidence(
                    verdict.confidence,
                    _safe_confidence_floor(strongest_score),
                )
                if (
                    elevated_confidence != verdict.confidence
                    or safety_evidence != verdict.safety_evidence
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
