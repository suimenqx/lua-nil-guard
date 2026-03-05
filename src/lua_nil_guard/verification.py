from __future__ import annotations

from .models import EvidencePacket, StaticProof, StaticRiskSignal, Verdict, VerificationSummary


_SAFE_VERIFY_THRESHOLD = 80
_SAFE_ELEVATE_THRESHOLD = 50
_CONFIDENCE_ORDER = ("low", "medium", "high")


def preview_static_verification(proofs: tuple[StaticProof, ...]) -> VerificationSummary | None:
    """Summarize the current structured static proof set before adjudication."""

    if not proofs:
        return None
    strongest_proof = _strongest_safe_proof(proofs)
    strongest_score = _safe_verification_score(proofs)
    proof_summaries = _proof_summaries(proofs)
    return VerificationSummary(
        mode="structured_static_proof_preview",
        strongest_proof_kind=strongest_proof.kind,
        strongest_proof_depth=strongest_proof.depth,
        strongest_proof_summary=strongest_proof.summary,
        verification_score=strongest_score,
        evidence=proof_summaries,
    )


def preview_static_risk(signals: tuple[StaticRiskSignal, ...]) -> VerificationSummary | None:
    """Summarize the current structured local risk signals before adjudication."""

    if not signals:
        return None
    strongest_signal = _strongest_risk_signal(signals)
    strongest_score = _static_risk_score(signals)
    signal_summaries = _risk_summaries(signals)
    return VerificationSummary(
        mode="structured_static_risk_preview",
        strongest_proof_kind=strongest_signal.kind,
        strongest_proof_depth=strongest_signal.depth,
        strongest_proof_summary=strongest_signal.summary,
        verification_score=strongest_score,
        evidence=signal_summaries,
    )


def verify_verdict(verdict: Verdict, packet: EvidencePacket) -> Verdict:
    """Apply a lightweight automatic verification pass to a verdict."""

    observed_guards = _tuple_field(packet, "observed_guards")
    proofs = packet.static_proofs
    risk_signals = packet.static_risk_signals
    proof_preview = preview_static_verification(proofs)
    risk_preview = preview_static_risk(risk_signals)
    proof_score = _preview_score(proof_preview)
    risk_score = _preview_score(risk_preview)

    if _has_strong_conflict(proof_score, risk_score):
        return _downgrade_conflicting_verdict(
            verdict,
            proof_preview=proof_preview,
            risk_preview=risk_preview,
        )

    if verdict.status == "risky" and not observed_guards and verdict.risk_path:
        if risk_preview is not None and risk_score >= _SAFE_VERIFY_THRESHOLD:
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
                    mode="structured_static_risk",
                    strongest_proof_kind=risk_preview.strongest_proof_kind,
                    strongest_proof_depth=risk_preview.strongest_proof_depth,
                    strongest_proof_summary=risk_preview.strongest_proof_summary,
                    verification_score=risk_preview.verification_score,
                    evidence=risk_preview.evidence,
                ),
            )
        if risk_preview is not None:
            elevated_confidence = verdict.confidence
            if risk_score >= _SAFE_ELEVATE_THRESHOLD:
                elevated_confidence = _max_confidence(
                    verdict.confidence,
                    _risk_confidence_floor(risk_score),
                )
            verification_summary = VerificationSummary(
                mode="structured_static_risk",
                strongest_proof_kind=risk_preview.strongest_proof_kind,
                strongest_proof_depth=risk_preview.strongest_proof_depth,
                strongest_proof_summary=risk_preview.strongest_proof_summary,
                verification_score=risk_preview.verification_score,
                evidence=risk_preview.evidence,
            )
            if (
                elevated_confidence != verdict.confidence
                or verification_summary != verdict.verification_summary
            ):
                return Verdict(
                    case_id=verdict.case_id,
                    status="risky",
                    confidence=elevated_confidence,
                    risk_path=verdict.risk_path,
                    safety_evidence=verdict.safety_evidence,
                    counterarguments_considered=verdict.counterarguments_considered,
                    suggested_fix=verdict.suggested_fix,
                    needs_human=verdict.needs_human,
                    autofix_patch=verdict.autofix_patch,
                    verification_summary=verification_summary,
                )
            return verdict
        verification_summary = VerificationSummary(
            mode="risk_no_guard",
            evidence=verdict.risk_path,
        )
        if verdict.verification_summary == verification_summary:
            return verdict
        return Verdict(
            case_id=verdict.case_id,
            status="risky",
            confidence=verdict.confidence,
            risk_path=verdict.risk_path,
            safety_evidence=verdict.safety_evidence,
            counterarguments_considered=verdict.counterarguments_considered,
            suggested_fix=verdict.suggested_fix,
            needs_human=verdict.needs_human,
            autofix_patch=verdict.autofix_patch,
            verification_summary=verification_summary,
        )

    if verdict.status == "uncertain" and proof_preview is not None:
        if proof_score >= _SAFE_VERIFY_THRESHOLD:
            proof_summaries = proof_preview.evidence
            return Verdict(
                case_id=verdict.case_id,
                status="safe_verified",
                confidence="high",
                risk_path=(),
                safety_evidence=verdict.safety_evidence or proof_summaries,
                counterarguments_considered=verdict.counterarguments_considered,
                suggested_fix=None,
                needs_human=False,
                autofix_patch=None,
                verification_summary=VerificationSummary(
                    mode="structured_static_proof_override",
                    strongest_proof_kind=proof_preview.strongest_proof_kind,
                    strongest_proof_depth=proof_preview.strongest_proof_depth,
                    strongest_proof_summary=proof_preview.strongest_proof_summary,
                    verification_score=proof_preview.verification_score,
                    evidence=proof_summaries,
                ),
            )

    if (
        verdict.status == "uncertain"
        and verdict.confidence != "high"
        and not observed_guards
        and not proofs
        and risk_signals
        and risk_preview is not None
    ):
        if risk_score >= _SAFE_VERIFY_THRESHOLD:
            risk_path = verdict.risk_path or risk_preview.evidence
            return Verdict(
                case_id=verdict.case_id,
                status="risky_verified",
                confidence="high",
                risk_path=risk_path,
                safety_evidence=(),
                counterarguments_considered=verdict.counterarguments_considered,
                suggested_fix=verdict.suggested_fix,
                needs_human=False,
                autofix_patch=verdict.autofix_patch,
                verification_summary=VerificationSummary(
                    mode="structured_static_risk_override",
                    strongest_proof_kind=risk_preview.strongest_proof_kind,
                    strongest_proof_depth=risk_preview.strongest_proof_depth,
                    strongest_proof_summary=risk_preview.strongest_proof_summary,
                    verification_score=risk_preview.verification_score,
                    evidence=risk_preview.evidence,
                ),
            )

    if verdict.status == "safe":
        if proofs:
            strongest_score = proof_score
            proof_summaries = proof_preview.evidence if proof_preview is not None else ()
            safety_evidence = verdict.safety_evidence or proof_summaries
            verification_summary = VerificationSummary(
                mode="structured_static_proof",
                strongest_proof_kind=(
                    proof_preview.strongest_proof_kind if proof_preview is not None else None
                ),
                strongest_proof_depth=(
                    proof_preview.strongest_proof_depth if proof_preview is not None else None
                ),
                strongest_proof_summary=(
                    proof_preview.strongest_proof_summary if proof_preview is not None else None
                ),
                verification_score=(
                    proof_preview.verification_score if proof_preview is not None else None
                ),
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


def _preview_score(preview: VerificationSummary | None) -> int:
    if preview is None:
        return 0
    return int(preview.verification_score or 0)


def _has_strong_conflict(proof_score: int, risk_score: int) -> bool:
    return proof_score >= _SAFE_VERIFY_THRESHOLD and risk_score >= _SAFE_VERIFY_THRESHOLD


def _downgrade_conflicting_verdict(
    verdict: Verdict,
    *,
    proof_preview: VerificationSummary | None,
    risk_preview: VerificationSummary | None,
) -> Verdict:
    evidence: list[str] = [
        "conflicting high-confidence static evidence detected",
        f"safe_score={_preview_score(proof_preview)}",
        f"risk_score={_preview_score(risk_preview)}",
    ]
    if proof_preview is not None and proof_preview.strongest_proof_summary:
        evidence.append(f"safe:{proof_preview.strongest_proof_summary}")
    if risk_preview is not None and risk_preview.strongest_proof_summary:
        evidence.append(f"risk:{risk_preview.strongest_proof_summary}")
    risk_path = verdict.risk_path
    if not risk_path and risk_preview is not None:
        risk_path = risk_preview.evidence
    safety_evidence = verdict.safety_evidence
    if not safety_evidence and proof_preview is not None:
        safety_evidence = proof_preview.evidence
    counterarguments = tuple(
        dict.fromkeys(
            (
                *verdict.counterarguments_considered,
                "strong structured proof and risk signals conflict; downgraded to uncertain",
            )
        )
    )
    return Verdict(
        case_id=verdict.case_id,
        status="uncertain",
        confidence="low",
        risk_path=risk_path,
        safety_evidence=safety_evidence,
        counterarguments_considered=counterarguments,
        suggested_fix=verdict.suggested_fix if verdict.status.startswith("risky") else None,
        needs_human=True,
        autofix_patch=None,
        verification_summary=VerificationSummary(
            mode="structured_conflict_downgrade",
            strongest_proof_kind="conflicting_static_evidence",
            verification_score=max(_preview_score(proof_preview), _preview_score(risk_preview)),
            evidence=tuple(evidence),
        ),
    )


def _safe_proof_score(proof: StaticProof) -> int:
    base_scores = {
        "direct_guard": 100,
        "loop_exit_guard": 100,
        "loop_break_guard": 100,
        "loop_index_guard": 100,
        "early_exit_guard": 100,
        "assert_guard": 100,
        "contract_guard": 95,
        "required_module_guard": 95,
        "guarded_field_origin": 95,
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


def _safe_risk_signal_score(signal: StaticRiskSignal) -> int:
    base_scores = {
        "direct_nil_literal": 98,
        "direct_sink_field_path": 95,
        "unguarded_field_origin": 90,
        "wrapper_field_path_risk": 90,
        "call_nil_return_branch": 92,
        "coalescing_call_nil_branch": 92,
    }
    base = base_scores.get(signal.kind, 70)
    penalty = 5 * max(0, signal.depth)
    return max(0, base - penalty)


def _static_risk_score(signals: tuple[StaticRiskSignal, ...]) -> int:
    scored_signals = sorted((_safe_risk_signal_score(signal) for signal in signals), reverse=True)
    strongest_score = scored_signals[0]
    corroboration_bonus = min(
        10,
        5 * sum(1 for score in scored_signals[1:] if score >= 70),
    )
    return min(100, strongest_score + corroboration_bonus)


def _strongest_risk_signal(signals: tuple[StaticRiskSignal, ...]) -> StaticRiskSignal:
    return max(
        signals,
        key=lambda signal: (
            _safe_risk_signal_score(signal),
            -signal.depth,
            signal.kind,
            signal.summary,
        ),
    )


def _safe_confidence_floor(score: int) -> str:
    if score >= _SAFE_VERIFY_THRESHOLD:
        return "high"
    return "medium"


def _risk_confidence_floor(score: int) -> str:
    if score >= _SAFE_VERIFY_THRESHOLD:
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


def _risk_summaries(signals: tuple[StaticRiskSignal, ...]) -> tuple[str, ...]:
    ordered_signals = sorted(
        signals,
        key=lambda signal: (
            -_safe_risk_signal_score(signal),
            signal.depth,
            signal.kind,
            signal.summary,
        ),
    )
    seen: set[str] = set()
    summaries: list[str] = []
    for signal in ordered_signals:
        if signal.summary in seen:
            continue
        summaries.append(signal.summary)
        seen.add(signal.summary)
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
