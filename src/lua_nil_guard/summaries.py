from __future__ import annotations

import json
import re
from pathlib import Path

from .models import FunctionSummary


_FUNCTION_START_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_.:]*)\s*\((.*?)\)\s*$",
)
_MODULE_DECLARATION_RE = re.compile(
    r"^\s*module\s*\(\s*(['\"])([^'\"]+)\1(?:\s*,\s*package\.seeall)?\s*\)\s*$",
)
_REQUIRE_DECLARATION_RE = re.compile(
    r"^\s*require(?:\s*\(\s*(['\"])([^'\"]+)\1\s*\)|\s+(['\"])([^'\"]+)\3)\s*$"
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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
                qualified_name=item.get("qualified_name", item["function_name"]),
                line=item["line"],
                params=dict(item["params"]),
                guards=tuple(item["guards"]),
                returns=tuple(item["returns"]),
                confidence=item["confidence"],
                source=item["source"],
                module_name=item.get("module_name"),
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
                "qualified_name": summary.qualified_name,
                "line": summary.line,
                "params": summary.params,
                "guards": list(summary.guards),
                "returns": list(summary.returns),
                "confidence": summary.confidence,
                "source": summary.source,
                "module_name": summary.module_name,
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
    module_name = detect_module_name(source)

    while index < len(lines):
        match = _FUNCTION_START_RE.match(lines[index])
        if match is None:
            index += 1
            continue

        defined_name = match.group(1)
        function_name = _short_function_name(defined_name)
        qualified_name = _qualify_function_name(defined_name, module_name)
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
                function_id=f"{file_text}::{qualified_name}:{index + 1}",
                file=file_text,
                function_name=function_name,
                qualified_name=qualified_name,
                line=index + 1,
                params=params,
                guards=tuple(dict.fromkeys(guard_lines)),
                returns=tuple(returns),
                confidence="medium",
                source="static",
                module_name=module_name,
            )
        )
        index = end_index + 1

    return tuple(summaries)


def detect_module_name(source: str) -> str | None:
    """Return the legacy module name declared via module(..., package.seeall)."""

    for line in source.splitlines():
        code = _strip_lua_comment(line)
        if not code.strip():
            continue
        match = _MODULE_DECLARATION_RE.match(code.strip())
        if match is not None:
            return match.group(2)
    return None


def detect_required_module_line(line: str) -> str | None:
    """Return the required module from a bare global require statement."""

    code = _strip_lua_comment(line)
    if not code.strip():
        return None
    match = _REQUIRE_DECLARATION_RE.match(code.strip())
    if match is None:
        return None
    return match.group(2) or match.group(4)


def detect_required_modules(source: str) -> tuple[str, ...]:
    """Return globally required modules declared via bare require(...) statements."""

    modules: list[str] = []
    for line in source.splitlines():
        module_name = detect_required_module_line(line)
        if module_name is None:
            continue
        modules.append(module_name)
    return tuple(dict.fromkeys(modules))


def module_receiver_symbols(module_name: str) -> tuple[str, ...]:
    """Expand a module name into receiver symbol prefixes (for example a.b -> a, a.b)."""

    parts = [part.strip() for part in module_name.split(".") if part.strip()]
    if not parts or any(_IDENTIFIER_RE.match(part) is None for part in parts):
        return ()
    symbols: list[str] = []
    for index in range(1, len(parts) + 1):
        symbols.append(".".join(parts[:index]))
    return tuple(symbols)


def required_module_symbol_map(source: str) -> dict[str, tuple[str, ...]]:
    """Map receiver symbols to global modules declared via bare require(...) lines."""

    symbol_to_modules: dict[str, list[str]] = {}
    for module_name in detect_required_modules(source):
        symbols = module_receiver_symbols(module_name)
        if not symbols:
            continue
        for symbol in symbols:
            symbol_to_modules.setdefault(symbol, []).append(module_name)
    return {
        symbol: tuple(dict.fromkeys(modules))
        for symbol, modules in symbol_to_modules.items()
    }


def _parse_params(raw: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for token in raw.split(","):
        name = token.strip()
        if name:
            params[name] = "unknown"
    return params


def _qualify_function_name(defined_name: str, module_name: str | None) -> str:
    normalized = _normalize_callable_name(defined_name)
    if "." in normalized:
        return normalized
    if module_name:
        return f"{module_name}.{normalized}"
    return normalized


def _short_function_name(defined_name: str) -> str:
    normalized = _normalize_callable_name(defined_name)
    return normalized.rsplit(".", 1)[-1]


def _normalize_callable_name(name: str) -> str:
    return name.strip().replace(":", ".")


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


def _strip_lua_comment(line: str) -> str:
    comment_index = line.find("--")
    if comment_index == -1:
        return line
    return line[:comment_index]
