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
    if origin is not None and " or " in origin:
        observed_guards.append(f"{candidate.symbol} = {candidate.symbol} or ...")

    state = "safe_static" if observed_guards else "unknown_static"
    origins = (origin,) if origin is not None else (candidate.expression,)
    return StaticAnalysisResult(
        state=state,
        observed_guards=tuple(observed_guards),
        origin_candidates=origins,
    )


def _find_last_assignment(lines: list[str], symbol: str) -> str | None:
    pattern = re.compile(
        rf"^\s*(?:local\s+)?{re.escape(symbol)}\s*=\s*(.+?)\s*$",
    )

    for line in reversed(lines):
        match = pattern.match(line)
        if match:
            return match.group(1)
    return None


def _has_guard(lines: list[str], symbol: str) -> bool:
    pattern = re.compile(rf"^\s*if\s+{re.escape(symbol)}\s+then\s*$")
    return any(pattern.match(line) for line in lines)


def _has_assert(lines: list[str], symbol: str) -> bool:
    pattern = re.compile(rf"\bassert\s*\(\s*{re.escape(symbol)}(?:\s*[,)\]])")
    return any(pattern.search(line) for line in lines)
