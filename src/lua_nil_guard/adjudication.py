from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import re

from .models import AdjudicationRecord, AutofixPatch, EvidencePacket, RoleOpinion, SinglePassJudgment, SinkRule, Verdict


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOT_PATH_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"
)


def adjudicate_packet(packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
    """Run v3 single-pass adjudication and return a compatibility record."""

    verdict = adjudicate_single_pass(packet, sink_rule).verdict
    return _single_pass_as_record(verdict)


def route_adjudication(
    packet: EvidencePacket,
    sink_rule: SinkRule,
    *,
    mode: str = "single_pass",
    ab_seed: int | None = None,
) -> Verdict:
    """Route adjudication and return the final verdict.

    LuaNilGuard v3 is single-pass only, so legacy mode values are rejected.
    """

    _ = ab_seed
    if mode != "single_pass":
        raise ValueError("LuaNilGuard v3 supports only adjudication mode: single_pass")
    return adjudicate_single_pass(packet, sink_rule).verdict


def adjudicate_single_pass(packet: EvidencePacket, sink_rule: SinkRule) -> SinglePassJudgment:
    """Run a single-pass structured adjudication (V3 replacement for multi-role).

    This combines the prosecutor/defender/judge logic into a single deterministic
    pass that considers both attack and defence evidence at once.
    """

    observed_guards = _tuple_field(packet, "observed_guards")
    origins = _tuple_field(packet, "origin_candidates")
    risk_signals = packet.static_risk_signals

    # Defence: explicit guards or safety facts
    if observed_guards or _has_explicit_safety_fact(packet):
        safety_evidence = observed_guards or tuple(
            f for f in packet.knowledge_facts if _looks_like_safety_fact(f)
        )
        verdict = Verdict(
            case_id=packet.case_id,
            status="safe",
            confidence="high" if observed_guards else "medium",
            risk_path=(),
            safety_evidence=safety_evidence,
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        )
        verdict = attach_autofix_patch(verdict, packet, sink_rule)
        return SinglePassJudgment(
            verdict=verdict,
            raw_response="",
            backend_metadata={},
        )

    # Attack: structured risk signals are strong evidence
    if risk_signals:
        risk_summaries = tuple(signal.summary for signal in risk_signals)
        risk_path = risk_summaries + (f"no guard before {sink_rule.qualified_name}",)
        verdict = Verdict(
            case_id=packet.case_id,
            status="risky",
            confidence="high",
            risk_path=risk_path,
            safety_evidence=(),
            counterarguments_considered=("no explicit guard or trusted non-nil contract found",),
            suggested_fix=_suggested_fix(packet, sink_rule),
            needs_human=False,
        )
        verdict = attach_autofix_patch(verdict, packet, sink_rule)
        return SinglePassJudgment(
            verdict=verdict,
            raw_response="",
            backend_metadata={},
        )

    # Attack: origin candidates but no safety evidence
    if origins:
        risk_path = origins + (f"no guard before {sink_rule.qualified_name}",)
        verdict = Verdict(
            case_id=packet.case_id,
            status="risky",
            confidence="high",
            risk_path=risk_path,
            safety_evidence=(),
            counterarguments_considered=("no explicit guard or trusted non-nil contract found",),
            suggested_fix=_suggested_fix(packet, sink_rule),
            needs_human=False,
        )
        verdict = attach_autofix_patch(verdict, packet, sink_rule)
        return SinglePassJudgment(
            verdict=verdict,
            raw_response="",
            backend_metadata={},
        )

    # Insufficient evidence
    verdict = Verdict(
        case_id=packet.case_id,
        status="uncertain",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=("no explicit guard or trusted non-nil contract found",),
        suggested_fix=None,
        needs_human=False,
    )
    return SinglePassJudgment(
        verdict=verdict,
        raw_response="",
        backend_metadata={},
    )


def attach_autofix_patch(
    verdict: Verdict,
    packet: EvidencePacket,
    sink_rule: SinkRule,
) -> Verdict:
    """Attach a machine-applicable autofix patch when the current verdict supports one."""

    if verdict.autofix_patch is not None or verdict.suggested_fix is None:
        return verdict
    patch = _build_autofix_patch(packet, sink_rule, verdict.suggested_fix)
    if patch is None:
        return verdict
    return replace(verdict, autofix_patch=patch)


def _single_pass_as_record(verdict: Verdict) -> AdjudicationRecord:
    if verdict.status == "safe":
        prosecutor = RoleOpinion(
            role="prosecutor",
            status="uncertain",
            confidence="low",
            risk_path=(),
            safety_evidence=(),
            missing_evidence=("safety evidence blocks a clean risk proof",),
            recommended_next_action="suppress",
            suggested_fix=None,
        )
        defender = RoleOpinion(
            role="defender",
            status="safe",
            confidence=verdict.confidence,
            risk_path=(),
            safety_evidence=verdict.safety_evidence,
            missing_evidence=(),
            recommended_next_action="suppress",
            suggested_fix=None,
        )
        return AdjudicationRecord(
            prosecutor=prosecutor,
            defender=defender,
            judge=verdict,
        )

    if verdict.status == "risky":
        prosecutor = RoleOpinion(
            role="prosecutor",
            status="risky",
            confidence=verdict.confidence,
            risk_path=verdict.risk_path,
            safety_evidence=(),
            missing_evidence=(),
            recommended_next_action="report",
            suggested_fix=verdict.suggested_fix,
        )
        defender = RoleOpinion(
            role="defender",
            status="uncertain",
            confidence="low",
            risk_path=(),
            safety_evidence=(),
            missing_evidence=("no explicit guard or trusted non-nil contract found",),
            recommended_next_action="expand_context",
            suggested_fix=None,
        )
        return AdjudicationRecord(
            prosecutor=prosecutor,
            defender=defender,
            judge=verdict,
        )

    uncertain = RoleOpinion(
        role="single_pass",
        status="uncertain",
        confidence=verdict.confidence,
        risk_path=verdict.risk_path,
        safety_evidence=verdict.safety_evidence,
        missing_evidence=("insufficient evidence",),
        recommended_next_action="expand_context",
        suggested_fix=None,
    )
    return AdjudicationRecord(
        prosecutor=uncertain,
        defender=uncertain,
        judge=verdict,
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

    if sink_rule.kind == "binary_operand" and sink_rule.qualified_name == "..":
        return _coalesce_fix(packet, sink_rule, "''")

    if sink_rule.kind == "binary_operand":
        return _coalesce_fix(packet, sink_rule, "0")

    if sink_rule.qualified_name in {"table.insert", "pairs", "ipairs"}:
        return _coalesce_fix(packet, sink_rule, "{}")

    if sink_rule.kind == "unary_operand" and sink_rule.qualified_name == "#":
        return _coalesce_fix(packet, sink_rule, "{}")

    if sink_rule.kind == "receiver" or sink_rule.qualified_name == "member_access":
        return _receiver_fix(packet, sink_rule)

    return None


def _coalesce_fix(
    packet: EvidencePacket,
    sink_rule: SinkRule,
    fallback_literal: str,
) -> str:
    expression = packet.target.expression
    target_line = _find_target_line(packet, sink_rule)
    if _IDENTIFIER_RE.match(expression):
        return f"{expression} = {expression} or {fallback_literal}"

    alias = _suggest_local_alias(expression)
    if alias is not None:
        alias_indent = _leading_indent(target_line) if target_line is not None else ""
        alias_line = f"{alias_indent}local {alias} = {expression} or {fallback_literal}"
        if target_line is not None and _is_elseif_line(target_line.strip()):
            return alias_line
        snippet = _build_contextual_fix_snippet(packet, sink_rule, alias, fallback_literal)
        if snippet is not None:
            return snippet
        return alias_line

    return f"local safe_value = {expression} or {fallback_literal}"


def _build_autofix_patch(
    packet: EvidencePacket,
    sink_rule: SinkRule,
    suggested_fix: str | None,
) -> AutofixPatch | None:
    if not suggested_fix:
        return None

    target_line = _find_target_line(packet, sink_rule)
    if target_line is None:
        return None

    if "\n" not in suggested_fix:
        expression = packet.target.expression
        stripped = target_line.strip()
        if _is_elseif_line(stripped):
            return None
        if not _IDENTIFIER_RE.match(expression):
            return None
        expected_prefix = f"{expression} = {expression} or "
        if not suggested_fix.startswith(expected_prefix):
            return None
        return AutofixPatch(
            case_id=packet.case_id,
            file=packet.target.file,
            action="insert_before",
            start_line=packet.target.line,
            end_line=packet.target.line,
            replacement=suggested_fix,
            expected_original=target_line,
        )

    bounds = _find_snippet_bounds(packet, sink_rule)
    if bounds is None:
        return None

    start_index, target_index, end_index = bounds
    start_line = packet.target.line - (target_index - start_index)
    end_line = packet.target.line + (end_index - target_index)
    return AutofixPatch(
        case_id=packet.case_id,
        file=packet.target.file,
        action="replace_range",
        start_line=start_line,
        end_line=end_line,
        replacement=suggested_fix,
        expected_original="\n".join(packet.local_context.splitlines()[start_index : end_index + 1]),
    )


def _receiver_fix(
    packet: EvidencePacket,
    sink_rule: SinkRule,
) -> str:
    expression = packet.target.expression
    target_line = _find_target_line(packet, sink_rule)
    if target_line is not None and _is_elseif_line(target_line.strip()):
        return f"if not {expression} then return nil end"

    if _IDENTIFIER_RE.match(expression):
        snippet = _build_contextual_receiver_fix_snippet(
            packet=packet,
            sink_rule=sink_rule,
            guard_expression=expression,
        )
        if snippet is not None:
            return snippet
        return f"if not {expression} then return nil end"

    alias = _suggest_local_alias(expression)
    if alias is not None:
        snippet = _build_contextual_receiver_fix_snippet(
            packet=packet,
            sink_rule=sink_rule,
            guard_expression=alias,
            alias_line_builder=lambda indent: f"{indent}local {alias} = {expression}",
            replacement=alias,
        )
        if snippet is not None:
            return snippet
        return f"local {alias} = {expression}\nif not {alias} then return nil end"

    return f"if not {expression} then return nil end"


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
        if sink_rule.kind == "binary_operand" and sink_rule.qualified_name not in line:
            continue
        if sink_rule.kind == "unary_operand" and "#" not in line:
            continue
        return index
    return None


def _leading_indent(line: str) -> str:
    stripped = line.lstrip(" \t")
    return line[: len(line) - len(stripped)]


def _nested_indent(indent: str) -> str:
    if indent.endswith("\t"):
        return f"{indent}\t"
    return f"{indent}  "


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
    target_line = lines[target_index]
    alias_indent = _leading_indent(target_line)
    alias_line = f"{alias_indent}local {alias} = {packet.target.expression} or {fallback_literal}"
    insert_after_start = _is_else_line(lines[start_index].strip())

    snippet_lines: list[str] = []
    if not insert_after_start:
        snippet_lines.append(alias_line)
    for index in range(start_index, end_index + 1):
        current = lines[index]
        if index == target_index:
            current = current.replace(packet.target.expression, alias, 1)
        snippet_lines.append(current)
        if insert_after_start and index == start_index:
            snippet_lines.append(alias_line)
    return "\n".join(snippet_lines)


def _build_contextual_receiver_fix_snippet(
    packet: EvidencePacket,
    sink_rule: SinkRule,
    guard_expression: str,
    alias_line_builder: Callable[[str], str] | None = None,
    replacement: str | None = None,
) -> str | None:
    lines = packet.local_context.splitlines()
    bounds = _find_snippet_bounds(packet, sink_rule)
    if bounds is None:
        return None

    start_index, target_index, end_index = bounds
    target_line = lines[target_index]
    base_indent = _leading_indent(target_line)
    child_indent = _nested_indent(base_indent)
    prelude_lines: list[str] = []
    if alias_line_builder is not None:
        prelude_lines.append(alias_line_builder(base_indent))
    prelude_lines.extend(
        (
            f"{base_indent}if not {guard_expression} then",
            f"{child_indent}return nil",
            f"{base_indent}end",
        )
    )

    insert_after_start = _is_else_line(lines[start_index].strip())
    snippet_lines: list[str] = []
    if not insert_after_start:
        snippet_lines.extend(prelude_lines)
    for index in range(start_index, end_index + 1):
        current = lines[index]
        if replacement is not None and index == target_index:
            current = current.replace(packet.target.expression, replacement, 1)
        snippet_lines.append(current)
        if insert_after_start and index == start_index:
            snippet_lines.extend(prelude_lines)
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

    else_bounds = _find_enclosing_else_branch_bounds(lines, target_index)
    if else_bounds is not None:
        return else_bounds

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


def _is_if_open(stripped_line: str) -> bool:
    return stripped_line.startswith("if ") and stripped_line.endswith(" then")


def _is_elseif_line(stripped_line: str) -> bool:
    return stripped_line.startswith("elseif ") and stripped_line.endswith(" then")


def _is_else_line(stripped_line: str) -> bool:
    return stripped_line == "else"


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


def _find_enclosing_else_branch_bounds(
    lines: list[str],
    target_index: int,
) -> tuple[int, int, int] | None:
    stack: list[dict[str, int | str]] = []

    for index in range(target_index):
        stripped = lines[index].strip()

        if _is_if_open(stripped):
            stack.append(
                {
                    "type": "if",
                    "start_index": index,
                    "branch": "if",
                    "branch_index": index,
                }
            )
            continue

        if _is_elseif_line(stripped):
            if stack and stack[-1]["type"] == "if":
                stack[-1]["branch"] = "elseif"
                stack[-1]["branch_index"] = index
            continue

        if _is_else_line(stripped):
            if stack and stack[-1]["type"] == "if":
                stack[-1]["branch"] = "else"
                stack[-1]["branch_index"] = index
            continue

        if _is_repeat_open(stripped):
            stack.append({"type": "repeat", "start_index": index})
            continue

        if _opens_block(stripped):
            stack.append({"type": "block", "start_index": index})
            continue

        if _is_repeat_until_line(stripped):
            _pop_last_matching_block(stack, "repeat")
            continue

        if stripped == "end" and stack:
            stack.pop()

    if not stack:
        return None

    entry = stack[-1]
    if entry["type"] != "if" or entry.get("branch") != "else":
        return None

    start_index = int(entry["branch_index"])
    end_index = _find_snippet_end_index(lines, int(entry["start_index"]))
    return (start_index, target_index, end_index)


def _pop_last_matching_block(stack: list[dict[str, int | str]], block_type: str) -> None:
    while stack:
        entry = stack.pop()
        if entry["type"] == block_type:
            return
