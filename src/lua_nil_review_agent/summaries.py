from __future__ import annotations

import json
import re
from pathlib import Path

from .models import FunctionSummary


_FUNCTION_START_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*$",
)


class SummaryStore:
    """Persist function summaries as JSON."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> tuple[FunctionSummary, ...]:
        if not self.path.exists():
            return ()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return tuple(
            FunctionSummary(
                function_id=item["function_id"],
                file=item["file"],
                function_name=item["function_name"],
                line=item["line"],
                params=dict(item["params"]),
                guards=tuple(item["guards"]),
                returns=tuple(item["returns"]),
                confidence=item["confidence"],
                source=item["source"],
            )
            for item in data
        )

    def save(self, summaries: tuple[FunctionSummary, ...]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "function_id": summary.function_id,
                "file": summary.file,
                "function_name": summary.function_name,
                "line": summary.line,
                "params": summary.params,
                "guards": list(summary.guards),
                "returns": list(summary.returns),
                "confidence": summary.confidence,
                "source": summary.source,
            }
            for summary in summaries
        ]
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def summarize_source(file_path: str | Path, source: str) -> tuple[FunctionSummary, ...]:
    """Extract lightweight function summaries from Lua source."""

    file_text = str(file_path)
    lines = source.splitlines()
    summaries: list[FunctionSummary] = []
    index = 0

    while index < len(lines):
        match = _FUNCTION_START_RE.match(lines[index])
        if match is None:
            index += 1
            continue

        function_name = match.group(1)
        params = _parse_params(match.group(2))
        body_lines, end_index = _capture_function_body(lines, index + 1)
        guard_lines: list[str] = []
        returns: list[str] = []

        for body_line in body_lines:
            stripped = body_line.strip()
            if stripped.startswith("assert("):
                for param in params:
                    if re.search(rf"\bassert\s*\(\s*{re.escape(param)}(?:\s*[,)\]])", stripped):
                        params[param] = "non_nil_required"
                        guard_lines.append(stripped)
            for param in params:
                if re.match(rf"^{re.escape(param)}\s*=\s*{re.escape(param)}\s+or\s+.+$", stripped):
                    if params[param] != "non_nil_required":
                        params[param] = "non_nil_if_guarded"
                    guard_lines.append(stripped)
            if stripped.startswith("return "):
                returns.append(stripped[len("return ") :].strip())

        summaries.append(
            FunctionSummary(
                function_id=f"{file_text}::{function_name}:{index + 1}",
                file=file_text,
                function_name=function_name,
                line=index + 1,
                params=params,
                guards=tuple(dict.fromkeys(guard_lines)),
                returns=tuple(returns),
                confidence="medium",
                source="static",
            )
        )
        index = end_index + 1

    return tuple(summaries)


def _parse_params(raw: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for token in raw.split(","):
        name = token.strip()
        if name:
            params[name] = "unknown"
    return params


def _capture_function_body(lines: list[str], start: int) -> tuple[list[str], int]:
    body: list[str] = []
    depth = 1
    index = start

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if _FUNCTION_START_RE.match(line):
            depth += 1
        elif stripped == "end":
            depth -= 1
            if depth == 0:
                return body, index
        body.append(line)
        index += 1

    return body, len(lines) - 1
