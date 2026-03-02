from __future__ import annotations

from .models import EvidencePacket, Verdict


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

    if verdict.status == "safe" and observed_guards:
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
