from __future__ import annotations

import re

from .models import AdjudicationRecord, EvidencePacket, RoleOpinion, SinkRule, Verdict


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOT_PATH_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"
)


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
    if sink_rule.qualified_name.startswith("string."):
        return _coalesce_fix(packet, sink_rule, "''")

    if sink_rule.qualified_name in {"table.insert", "pairs", "ipairs"}:
        return _coalesce_fix(packet, sink_rule, "{}")

    if sink_rule.kind == "unary_operand" and sink_rule.qualified_name == "#":
        return _coalesce_fix(packet, sink_rule, "{}")

    expression = packet.target.expression
    if sink_rule.kind == "receiver" or sink_rule.qualified_name == "member_access":
        return f"if not {expression} then return nil end"

    return None


def _coalesce_fix(
    packet: EvidencePacket,
    sink_rule: SinkRule,
    fallback_literal: str,
) -> str:
    expression = packet.target.expression
    if _IDENTIFIER_RE.match(expression):
        return f"{expression} = {expression} or {fallback_literal}"

    alias = _suggest_local_alias(expression)
    if alias is not None:
        alias_line = f"local {alias} = {expression} or {fallback_literal}"
        snippet = _build_contextual_fix_snippet(packet, sink_rule, alias, fallback_literal)
        if snippet is not None:
            return snippet
        return alias_line

    return f"local safe_value = {expression} or {fallback_literal}"


def _suggest_local_alias(expression: str) -> str | None:
    if not _DOT_PATH_RE.match(expression):
        return None

    alias = expression.rsplit(".", 1)[-1]
    if not _IDENTIFIER_RE.match(alias):
        return None
    return alias


def _find_target_line(
    packet: EvidencePacket,
    sink_rule: SinkRule,
) -> str | None:
    target_index = _find_target_line_index(packet, sink_rule)
    if target_index is None:
        return None
    return packet.local_context.splitlines()[target_index]


def _find_target_line_index(
    packet: EvidencePacket,
    sink_rule: SinkRule,
) -> int | None:
    expression = packet.target.expression
    for index, line in enumerate(packet.local_context.splitlines()):
        if expression not in line:
            continue
        if sink_rule.kind == "function_arg" and sink_rule.qualified_name not in line:
            continue
        if sink_rule.kind == "unary_operand" and "#" not in line:
            continue
        return index
    return None


def _leading_indent(line: str) -> str:
    stripped = line.lstrip(" \t")
    return line[: len(line) - len(stripped)]


def _build_contextual_fix_snippet(
    packet: EvidencePacket,
    sink_rule: SinkRule,
    alias: str,
    fallback_literal: str,
) -> str | None:
    lines = packet.local_context.splitlines()
    bounds = _find_snippet_bounds(packet, sink_rule)
    if bounds is None:
        return None

    start_index, target_index, end_index = bounds
    anchor_line = lines[start_index]
    alias_indent = _leading_indent(anchor_line)
    alias_line = f"{alias_indent}local {alias} = {packet.target.expression} or {fallback_literal}"

    snippet_lines = [alias_line]
    for index in range(start_index, end_index + 1):
        current = lines[index]
        if index == target_index:
            current = current.replace(packet.target.expression, alias, 1)
        snippet_lines.append(current)
    return "\n".join(snippet_lines)


def _find_snippet_bounds(
    packet: EvidencePacket,
    sink_rule: SinkRule,
) -> tuple[int, int, int] | None:
    lines = packet.local_context.splitlines()
    target_index = _find_target_line_index(packet, sink_rule)
    if target_index is None:
        return None

    target_line = lines[target_index].strip()
    if _is_repeat_until_line(target_line):
        start_index = _find_repeat_start_index(lines, target_index)
        if start_index is not None:
            return (start_index, target_index, target_index)
        return (target_index, target_index, target_index)

    if _opens_block(target_line):
        end_index = _find_snippet_end_index(lines, target_index)
        return (target_index, target_index, end_index)

    return (target_index, target_index, target_index)


def _find_snippet_end_index(lines: list[str], target_index: int) -> int:
    target_line = lines[target_index].strip()
    if not _opens_block(target_line):
        return target_index

    depth = 1
    for index in range(target_index + 1, len(lines)):
        stripped = lines[index].strip()
        if _opens_block(stripped):
            depth += 1
        if _closes_block(stripped):
            depth -= 1
            if depth == 0:
                return index
    return target_index


def _opens_block(stripped_line: str) -> bool:
    return (
        stripped_line.startswith("for ") and stripped_line.endswith(" do")
    ) or (
        stripped_line.startswith("if ") and stripped_line.endswith(" then")
    ) or (
        stripped_line.startswith("while ") and stripped_line.endswith(" do")
    ) or (
        _is_repeat_open(stripped_line)
    ) or (
        stripped_line == "do"
    ) or (
        _is_function_open(stripped_line)
    )


def _closes_block(stripped_line: str) -> bool:
    return stripped_line == "end" or _is_repeat_until_line(stripped_line)


def _is_repeat_open(stripped_line: str) -> bool:
    return stripped_line == "repeat" or stripped_line.startswith("repeat ")


def _is_repeat_until_line(stripped_line: str) -> bool:
    return stripped_line.startswith("until ")


def _is_function_open(stripped_line: str) -> bool:
    return bool(
        re.match(r"^(?:local\s+)?function\b", stripped_line)
        or re.search(r"(?:=\s*|return\s+)function\b", stripped_line)
    )


def _find_repeat_start_index(lines: list[str], target_index: int) -> int | None:
    depth = 1
    for index in range(target_index - 1, -1, -1):
        stripped = lines[index].strip()
        if _is_repeat_until_line(stripped):
            depth += 1
            continue
        if _is_repeat_open(stripped):
            depth -= 1
            if depth == 0:
                return index
    return None
