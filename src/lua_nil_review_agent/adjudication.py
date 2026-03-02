from __future__ import annotations

from .models import AdjudicationRecord, EvidencePacket, RoleOpinion, SinkRule, Verdict


def adjudicate_packet(packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
    """Run the default multi-role adjudication flow for a single evidence packet."""

    prosecutor = _prosecutor_opinion(packet, sink_rule)
    defender = _defender_opinion(packet)
    judge = _judge_verdict(packet, prosecutor, defender)
    return AdjudicationRecord(
        prosecutor=prosecutor,
        defender=defender,
        judge=judge,
    )


def _prosecutor_opinion(packet: EvidencePacket, sink_rule: SinkRule) -> RoleOpinion:
    observed_guards = _tuple_field(packet, "observed_guards")
    origins = _tuple_field(packet, "origin_candidates")

    if observed_guards or _has_explicit_safety_fact(packet):
        return RoleOpinion(
            role="prosecutor",
            status="uncertain",
            confidence="low",
            risk_path=(),
            safety_evidence=(),
            missing_evidence=("safety evidence blocks a clean risk proof",),
            recommended_next_action="suppress",
            suggested_fix=None,
        )

    return RoleOpinion(
        role="prosecutor",
        status="risky",
        confidence="medium",
        risk_path=origins + (f"no guard before {sink_rule.qualified_name}",),
        safety_evidence=(),
        missing_evidence=(),
        recommended_next_action="report",
        suggested_fix=_suggested_fix(packet, sink_rule),
    )


def _defender_opinion(packet: EvidencePacket) -> RoleOpinion:
    observed_guards = _tuple_field(packet, "observed_guards")
    if observed_guards:
        return RoleOpinion(
            role="defender",
            status="safe",
            confidence="high",
            risk_path=(),
            safety_evidence=observed_guards,
            missing_evidence=(),
            recommended_next_action="suppress",
            suggested_fix=None,
        )

    safety_facts = tuple(fact for fact in packet.knowledge_facts if _looks_like_safety_fact(fact))
    if safety_facts:
        return RoleOpinion(
            role="defender",
            status="safe",
            confidence="medium",
            risk_path=(),
            safety_evidence=safety_facts,
            missing_evidence=(),
            recommended_next_action="suppress",
            suggested_fix=None,
        )

    return RoleOpinion(
        role="defender",
        status="uncertain",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        missing_evidence=("no explicit guard or trusted non-nil contract found",),
        recommended_next_action="expand_context",
        suggested_fix=None,
    )


def _judge_verdict(
    packet: EvidencePacket,
    prosecutor: RoleOpinion,
    defender: RoleOpinion,
) -> Verdict:
    if defender.status == "safe":
        return Verdict(
            case_id=packet.case_id,
            status="safe",
            confidence="high" if defender.confidence == "high" else "medium",
            risk_path=(),
            safety_evidence=defender.safety_evidence,
            counterarguments_considered=prosecutor.risk_path,
            suggested_fix=None,
            needs_human=False,
        )

    if prosecutor.status == "risky":
        return Verdict(
            case_id=packet.case_id,
            status="risky",
            confidence=prosecutor.confidence,
            risk_path=prosecutor.risk_path,
            safety_evidence=(),
            counterarguments_considered=defender.missing_evidence,
            suggested_fix=prosecutor.suggested_fix,
            needs_human=False,
        )

    return Verdict(
        case_id=packet.case_id,
        status="uncertain",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=defender.missing_evidence + prosecutor.missing_evidence,
        suggested_fix=None,
        needs_human=False,
    )


def _tuple_field(packet: EvidencePacket, key: str) -> tuple[str, ...]:
    value = packet.static_reasoning.get(key, ())
    if isinstance(value, tuple):
        return value
    return ()


def _has_explicit_safety_fact(packet: EvidencePacket) -> bool:
    return any(_looks_like_safety_fact(fact) for fact in packet.knowledge_facts)


def _looks_like_safety_fact(fact: str) -> bool:
    lowered = fact.lower()
    return "always returns string" in lowered or "always returns table" in lowered or "non-nil" in lowered


def _suggested_fix(packet: EvidencePacket, sink_rule: SinkRule) -> str | None:
    expression = packet.target.expression

    if sink_rule.qualified_name.startswith("string."):
        return f"local safe_value = {expression} or ''"

    if sink_rule.qualified_name in {"table.insert", "pairs", "ipairs"}:
        return f"local safe_value = {expression} or {{}}"

    if sink_rule.kind == "unary_operand" and sink_rule.qualified_name == "#":
        return f"local safe_value = {expression} or {{}}"

    if sink_rule.kind == "receiver" or sink_rule.qualified_name == "member_access":
        return f"if not {expression} then return nil end"

    return None
