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

    if _has_guard(prior_lines, candidate.symbol):
        observed_guards.append(f"if {candidate.symbol} then")
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


def _has_guard(lines: list[str], symbol: str) -> bool:
    pattern = re.compile(rf"^\s*if\s+{re.escape(symbol)}\s+then\s*$")
    return any(pattern.match(line) for line in lines)


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
