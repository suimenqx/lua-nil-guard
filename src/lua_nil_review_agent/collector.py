from __future__ import annotations

import re
from pathlib import Path

from .models import CandidateCase, SinkRule
from .parser_backend import (
    collect_call_sites,
    collect_length_operands,
    collect_receiver_accesses,
)


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FUNCTION_NAME_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_.:]*)\s*\(",
)
_ANONYMOUS_FUNCTION_RE = re.compile(r"(?:=\s*|return\s+)function\b")
_MODULE_DECLARATION_RE = re.compile(
    r"^\s*module\s*\(\s*(['\"])([^'\"]+)\1(?:\s*,\s*package\.seeall)?\s*\)\s*$",
)


def collect_candidates(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
) -> tuple[CandidateCase, ...]:
    """Collect nil-sensitive call sites using deterministic lightweight parsing."""

    path_text = str(file_path)
    candidates: list[CandidateCase] = []

    for sink_rule in sink_rules:
        if sink_rule.kind == "function_arg":
            for call_site in collect_call_sites(source, sink_rule.qualified_name):
                if sink_rule.arg_index < 1 or len(call_site.args) < sink_rule.arg_index:
                    continue

                expression = call_site.args[sink_rule.arg_index - 1].strip()
                line, column = call_site.line, call_site.column
                function_scope = _find_enclosing_function(source[: call_site.offset])
                symbol = expression if _IDENTIFIER_RE.match(expression) else expression
                case_id = f"{path_text}:{line}:{column}:{sink_rule.id}"

                candidates.append(
                    CandidateCase(
                        case_id=case_id,
                        file=path_text,
                        line=line,
                        column=column,
                        sink_rule_id=sink_rule.id,
                        sink_name=sink_rule.qualified_name,
                        arg_index=sink_rule.arg_index,
                        expression=expression,
                        symbol=symbol,
                        function_scope=function_scope,
                        static_state="unknown_static",
                    )
                )
            continue

        if sink_rule.kind != "receiver":
            if sink_rule.kind != "unary_operand":
                continue

            for operand in collect_length_operands(source):
                expression = operand.operand
                line, column = operand.line, operand.column
                function_scope = _find_enclosing_function(source[: operand.offset])
                symbol = expression if _IDENTIFIER_RE.match(expression) else expression
                case_id = f"{path_text}:{line}:{column}:{sink_rule.id}"

                candidates.append(
                    CandidateCase(
                        case_id=case_id,
                        file=path_text,
                        line=line,
                        column=column,
                        sink_rule_id=sink_rule.id,
                        sink_name=sink_rule.qualified_name,
                        arg_index=sink_rule.arg_index,
                        expression=expression,
                        symbol=symbol,
                        function_scope=function_scope,
                        static_state="unknown_static",
                    )
                )
            continue

        for access in collect_receiver_accesses(source):
            expression = access.receiver
            line, column = access.line, access.column
            function_scope = _find_enclosing_function(source[: access.offset])
            symbol = expression if _IDENTIFIER_RE.match(expression) else expression
            case_id = f"{path_text}:{line}:{column}:{sink_rule.id}"

            candidates.append(
                CandidateCase(
                    case_id=case_id,
                    file=path_text,
                    line=line,
                    column=column,
                    sink_rule_id=sink_rule.id,
                    sink_name=sink_rule.qualified_name,
                    arg_index=sink_rule.arg_index,
                    expression=expression,
                    symbol=symbol,
                    function_scope=function_scope,
                    static_state="unknown_static",
                )
            )

    candidates.sort(key=lambda item: (item.line, item.column, item.sink_rule_id))
    return tuple(candidates)


def _find_enclosing_function(prefix: str) -> str:
    scope_stack: list[str] = []
    block_stack: list[str] = []
    module_name: str | None = None
    for line in prefix.splitlines():
        code = _strip_lua_comment(line)
        stripped = code.strip()
        if not stripped:
            continue
        module_match = _MODULE_DECLARATION_RE.match(code.strip())
        if module_match is not None:
            module_name = module_match.group(2)
            continue

        match = _FUNCTION_NAME_RE.match(code)
        if match:
            scope_stack.append(_qualify_function_name(match.group(1), module_name))
            block_stack.append("function")
            continue

        if _ANONYMOUS_FUNCTION_RE.search(stripped):
            block_stack.append("anon_function")
            continue
        if stripped == "repeat":
            block_stack.append("repeat")
            continue
        if _opens_non_function_block(stripped):
            block_stack.append("block")
            continue
        if stripped == "end":
            if not block_stack:
                continue
            closing = block_stack.pop()
            if closing == "function" and scope_stack:
                scope_stack.pop()
            continue
        if stripped.startswith("until "):
            if block_stack and block_stack[-1] == "repeat":
                block_stack.pop()

    if scope_stack:
        return scope_stack[-1]
    return "main"


def _qualify_function_name(defined_name: str, module_name: str | None) -> str:
    normalized = defined_name.strip().replace(":", ".")
    if "." in normalized:
        return normalized
    if module_name:
        return f"{module_name}.{normalized}"
    return normalized


def _strip_lua_comment(line: str) -> str:
    comment_index = line.find("--")
    if comment_index == -1:
        return line
    return line[:comment_index]


def _opens_non_function_block(stripped_line: str) -> bool:
    return (
        (stripped_line.startswith("if ") and stripped_line.endswith(" then"))
        or (stripped_line.startswith("elseif ") and stripped_line.endswith(" then"))
        or (stripped_line.startswith("for ") and stripped_line.endswith(" do"))
        or (stripped_line.startswith("while ") and stripped_line.endswith(" do"))
        or stripped_line == "do"
    )
