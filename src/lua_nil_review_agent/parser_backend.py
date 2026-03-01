from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import re


@dataclass(frozen=True, slots=True)
class ParserBackendInfo:
    """Describe the active parser backend and its capabilities."""

    name: str
    tree_sitter_available: bool


@dataclass(frozen=True, slots=True)
class CallSite:
    """A normalized function call discovered by the active parser backend."""

    callee: str
    offset: int
    line: int
    column: int
    args: tuple[str, ...]


def get_parser_backend_info() -> ParserBackendInfo:
    """Return the active parser backend description."""

    tree_sitter_available = (
        importlib.util.find_spec("tree_sitter") is not None
        and importlib.util.find_spec("tree_sitter_lua") is not None
    )
    if tree_sitter_available:
        return ParserBackendInfo(name="tree_sitter", tree_sitter_available=True)
    return ParserBackendInfo(name="regex_fallback", tree_sitter_available=False)


def collect_call_sites(source: str, qualified_name: str) -> tuple[CallSite, ...]:
    """Collect call sites for a qualified name using the active backend."""

    return _collect_call_sites_fallback(source, qualified_name)


def _collect_call_sites_fallback(source: str, qualified_name: str) -> tuple[CallSite, ...]:
    pattern = re.compile(rf"\b{re.escape(qualified_name)}\s*\(")
    calls: list[CallSite] = []

    for match in pattern.finditer(source):
        open_paren_index = source.find("(", match.start())
        close_paren_index = _find_matching_paren(source, open_paren_index)
        if close_paren_index == -1:
            continue

        args_text = source[open_paren_index + 1 : close_paren_index]
        line, column = _line_and_column(source, match.start())
        calls.append(
            CallSite(
                callee=qualified_name,
                offset=match.start(),
                line=line,
                column=column,
                args=tuple(_split_top_level_args(args_text)),
            )
        )

    return tuple(calls)


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
