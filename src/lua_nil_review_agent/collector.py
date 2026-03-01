from __future__ import annotations

import re
from pathlib import Path

from .models import CandidateCase, SinkRule


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FUNCTION_NAME_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
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
        if sink_rule.kind != "function_arg":
            continue

        pattern = re.compile(rf"\b{re.escape(sink_rule.qualified_name)}\s*\(")
        for match in pattern.finditer(source):
            open_paren_index = source.find("(", match.start())
            close_paren_index = _find_matching_paren(source, open_paren_index)
            if close_paren_index == -1:
                continue

            args_text = source[open_paren_index + 1 : close_paren_index]
            args = _split_top_level_args(args_text)
            if sink_rule.arg_index < 1 or len(args) < sink_rule.arg_index:
                continue

            expression = args[sink_rule.arg_index - 1].strip()
            line, column = _line_and_column(source, match.start())
            function_scope = _find_enclosing_function(source[: match.start()])
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


def _find_matching_paren(source: str, open_paren_index: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False

    for index in range(open_paren_index, len(source)):
        char = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index

    return -1


def _split_top_level_args(args_text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(args_text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            args.append(args_text[start:index].strip())
            start = index + 1

    tail = args_text[start:].strip()
    if tail:
        args.append(tail)
    return args


def _line_and_column(source: str, offset: int) -> tuple[int, int]:
    before = source[:offset]
    line = before.count("\n") + 1
    column = offset - before.rfind("\n")
    return line, column


def _find_enclosing_function(prefix: str) -> str:
    function_name = "main"
    for line in prefix.splitlines():
        match = _FUNCTION_NAME_RE.match(line)
        if match:
            function_name = match.group(1)
    return function_name
