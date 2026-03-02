from __future__ import annotations

import re

from .models import CandidateCase, StaticAnalysisResult


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def analyze_candidate(source: str, candidate: CandidateCase) -> StaticAnalysisResult:
    """Apply bounded local heuristics before escalating to agent review."""

    if not _IDENTIFIER_RE.match(candidate.symbol):
        return StaticAnalysisResult(
            state="unknown_static",
            observed_guards=(),
            origin_candidates=(candidate.expression,),
        )

    lines = source.splitlines()
    prior_lines = lines[: max(0, candidate.line - 1)]
    origin = _find_last_assignment(prior_lines, candidate.symbol)
    observed_guards: list[str] = []

    if _has_active_positive_guard(prior_lines, candidate.symbol):
        observed_guards.append(f"if {candidate.symbol} then")
    if _has_early_exit_guard(prior_lines, candidate.symbol):
        observed_guards.append(f"if not {candidate.symbol} then return")
    if _has_assert(prior_lines, candidate.symbol):
        observed_guards.append(f"assert({candidate.symbol})")
    if _has_defaulting_origin(origin):
        observed_guards.append(f"{candidate.symbol} = {candidate.symbol} or ...")

    state = "safe_static" if observed_guards else "unknown_static"
    origins = (origin,) if origin is not None else (candidate.expression,)
    return StaticAnalysisResult(
        state=state,
        observed_guards=tuple(observed_guards),
        origin_candidates=origins,
    )


def _find_last_assignment(lines: list[str], symbol: str) -> str | None:
    single_pattern = re.compile(
        rf"^\s*(?:local\s+)?{re.escape(symbol)}\s*=\s*(.+?)\s*$",
    )
    multi_pattern = re.compile(
        r"^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*=\s*(.+?)\s*$",
    )

    for line in reversed(lines):
        match = single_pattern.match(line)
        if match:
            return match.group(1)
        match = multi_pattern.match(line)
        if match:
            names = [name.strip() for name in match.group(1).split(",")]
            if symbol not in names:
                continue

            values = _split_top_level_values(match.group(2))
            if not values:
                continue

            position = names.index(symbol)
            if position < len(values):
                return values[position]
            if len(values) == 1:
                # A single function call can populate multiple targets in Lua.
                return values[0]
    return None


def _has_active_positive_guard(lines: list[str], symbol: str) -> bool:
    stack: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if "symbol_if" in stack and _assigns_symbol(stripped, symbol):
            stack = ["if" if entry == "symbol_if" else entry for entry in stack]
            continue

        if _is_if_open_for_symbol(stripped, symbol):
            stack.append("symbol_if")
            continue
        if _is_if_open(stripped):
            stack.append("if")
            continue
        if _is_elseif_line(stripped):
            if stack and stack[-1] in {"if", "symbol_if"}:
                stack[-1] = "symbol_if" if _is_elseif_for_symbol(stripped, symbol) else "if"
            continue
        if stripped == "else":
            if stack and stack[-1] in {"if", "symbol_if"}:
                stack[-1] = "if"
            continue
        if _opens_non_if_block(stripped):
            stack.append("block")
            continue
        if _closes_block(stripped) and stack:
            stack.pop()

    return "symbol_if" in stack


def _has_early_exit_guard(lines: list[str], symbol: str) -> bool:
    stack: list[dict[str, int | str]] = []
    valid_guard_paths: list[tuple[int, ...]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if stack and stack[-1]["type"] == "neg_guard_pending":
            if _is_early_exit_statement(stripped):
                stack[-1]["type"] = "neg_guard_exit"
                continue
            if stripped != "end":
                stack[-1]["type"] = "if_family"

        if valid_guard_paths and _assigns_symbol(stripped, symbol):
            valid_guard_paths.clear()

        if _is_negative_guard_for_symbol(stripped, symbol):
            stack.append({"type": "neg_guard_pending", "branch": 0})
            continue
        if _is_if_open_for_symbol(stripped, symbol):
            stack.append({"type": "if_family", "branch": 0})
            continue
        if _is_if_open(stripped):
            stack.append({"type": "if_family", "branch": 0})
            continue
        if _is_elseif_line(stripped):
            if stack and stack[-1]["type"] in {"if_family", "neg_guard_pending", "neg_guard_exit"}:
                stack[-1]["type"] = "if_family"
                stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            continue
        if stripped == "else":
            if stack and stack[-1]["type"] in {"if_family", "neg_guard_pending", "neg_guard_exit"}:
                stack[-1]["type"] = "if_family"
                stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            continue
        if _opens_non_if_block(stripped):
            stack.append({"type": "block"})
            continue
        if _closes_block(stripped) and stack:
            closing = stack.pop()
            if closing["type"] == "neg_guard_exit":
                valid_guard_paths.append(_current_if_branch_path(stack))

    current_path = _current_if_branch_path(stack)
    return any(_branch_path_is_prefix(path, current_path) for path in valid_guard_paths)


def _has_assert(lines: list[str], symbol: str) -> bool:
    pattern = re.compile(rf"\bassert\s*\(\s*{re.escape(symbol)}(?:\s*[,)\]])")
    return any(pattern.search(line) for line in lines)


def _has_defaulting_origin(origin: str | None) -> bool:
    if origin is None:
        return False
    if " or " not in origin:
        return False
    # Lua's common ternary idiom `cond and nil or value` can still yield nil on a
    # reachable branch, so it is not equivalent to a non-nil defaulting guard.
    if " and nil or " in origin:
        return False
    return True


def _split_top_level_values(values_text: str) -> list[str]:
    values: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(values_text):
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
            values.append(values_text[start:index].strip())
            start = index + 1

    tail = values_text[start:].strip()
    if tail:
        values.append(tail)
    return values


def _is_if_open_for_symbol(stripped_line: str, symbol: str) -> bool:
    if not _is_if_open(stripped_line):
        return False
    condition = stripped_line[len("if ") : -len(" then")].strip()
    return condition == symbol or condition == f"{symbol} ~= nil"


def _is_if_open(stripped_line: str) -> bool:
    return stripped_line.startswith("if ") and stripped_line.endswith(" then")


def _is_elseif_line(stripped_line: str) -> bool:
    return stripped_line.startswith("elseif ") and stripped_line.endswith(" then")


def _is_elseif_for_symbol(stripped_line: str, symbol: str) -> bool:
    condition = stripped_line[len("elseif ") : -len(" then")].strip()
    return condition == symbol or condition == f"{symbol} ~= nil"


def _opens_non_if_block(stripped_line: str) -> bool:
    return (
        (stripped_line.startswith("for ") and stripped_line.endswith(" do"))
        or (stripped_line.startswith("while ") and stripped_line.endswith(" do"))
        or stripped_line == "do"
        or stripped_line == "repeat"
        or bool(re.match(r"^(?:local\s+)?function\b", stripped_line))
        or bool(re.search(r"(?:=\s*|return\s+)function\b", stripped_line))
    )


def _closes_block(stripped_line: str) -> bool:
    return stripped_line == "end" or stripped_line.startswith("until ")


def _is_negative_guard_for_symbol(stripped_line: str, symbol: str) -> bool:
    return (
        stripped_line == f"if not {symbol} then"
        or stripped_line == f"if {symbol} == nil then"
    )


def _is_early_exit_statement(stripped_line: str) -> bool:
    return (
        stripped_line == "return"
        or stripped_line.startswith("return ")
        or stripped_line.startswith("error(")
        or stripped_line.startswith("assert(false")
    )


def _assigns_symbol(stripped_line: str, symbol: str) -> bool:
    single_pattern = re.compile(
        rf"^(?:local\s+)?{re.escape(symbol)}\s*=\s*.+$",
    )
    if single_pattern.match(stripped_line):
        return True

    multi_pattern = re.compile(
        r"^(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*=\s*.+$",
    )
    match = multi_pattern.match(stripped_line)
    if match is None:
        return False
    names = [name.strip() for name in match.group(1).split(",")]
    return symbol in names


def _current_if_branch_path(stack: list[dict[str, int | str]]) -> tuple[int, ...]:
    return tuple(
        int(entry["branch"])
        for entry in stack
        if entry["type"] in {"if_family", "neg_guard_pending", "neg_guard_exit"}
    )


def _branch_path_is_prefix(path: tuple[int, ...], current_path: tuple[int, ...]) -> bool:
    if len(path) > len(current_path):
        return False
    return current_path[: len(path)] == path
