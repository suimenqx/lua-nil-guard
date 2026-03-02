from __future__ import annotations

import ctypes
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import warnings


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VENDOR_LUA_SRC_DIR = PROJECT_ROOT / "vendor" / "tree-sitter-lua" / "src"
TREE_SITTER_BUILD_DIR = Path.home() / ".cache" / "lua-nil-review-agent" / "tree_sitter"
TREE_SITTER_LUA_LIBRARY = TREE_SITTER_BUILD_DIR / "tree_sitter_lua.so"

_LANGUAGE_CACHE = None
_CDLL_CACHE = None


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


@dataclass(frozen=True, slots=True)
class ReceiverAccess:
    """A normalized non-call member access discovered by the active backend."""

    receiver: str
    expression: str
    offset: int
    line: int
    column: int


def get_parser_backend_info() -> ParserBackendInfo:
    """Return the active parser backend description."""

    if _load_lua_language() is not None:
        return ParserBackendInfo(name="tree_sitter_local", tree_sitter_available=True)
    return ParserBackendInfo(name="regex_fallback", tree_sitter_available=False)


def collect_call_sites(source: str, qualified_name: str) -> tuple[CallSite, ...]:
    """Collect call sites for a qualified name using the active backend."""

    language = _load_lua_language()
    if language is not None:
        tree_sitter_calls = _collect_call_sites_tree_sitter(source, qualified_name, language)
        if tree_sitter_calls is not None:
            return tree_sitter_calls
    return _collect_call_sites_fallback(source, qualified_name)


def collect_receiver_accesses(source: str) -> tuple[ReceiverAccess, ...]:
    """Collect non-call member access expressions using the active backend."""

    language = _load_lua_language()
    if language is not None:
        tree_sitter_accesses = _collect_receiver_accesses_tree_sitter(source, language)
        if tree_sitter_accesses is not None:
            return tree_sitter_accesses
    return _collect_receiver_accesses_fallback(source)


def _load_lua_language():
    global _LANGUAGE_CACHE
    if _LANGUAGE_CACHE is not None:
        return _LANGUAGE_CACHE

    if importlib.util.find_spec("tree_sitter") is None:
        return None

    language = _load_local_compiled_language()
    if language is not None:
        _LANGUAGE_CACHE = language
        return _LANGUAGE_CACHE

    try:
        from tree_sitter import Language
        import tree_sitter_lua

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            language = Language(tree_sitter_lua.language())
    except Exception:
        return None

    _LANGUAGE_CACHE = language
    return _LANGUAGE_CACHE


def _load_local_compiled_language():
    library_path = _ensure_local_language_library()
    if library_path is None:
        return None

    try:
        from tree_sitter import Language
    except Exception:
        return None

    try:
        global _CDLL_CACHE
        _CDLL_CACHE = ctypes.CDLL(str(library_path))
        language_fn = _CDLL_CACHE.tree_sitter_lua
        language_fn.restype = ctypes.c_void_p
        ptr = language_fn()
        if not ptr:
            return None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return Language(ptr)
    except Exception:
        return None


def _ensure_local_language_library() -> Path | None:
    parser_c = VENDOR_LUA_SRC_DIR / "parser.c"
    scanner_c = VENDOR_LUA_SRC_DIR / "scanner.c"
    header_dir = VENDOR_LUA_SRC_DIR / "tree_sitter"
    header_paths = (
        header_dir / "parser.h",
        header_dir / "alloc.h",
        header_dir / "array.h",
    )
    if not parser_c.exists() or not scanner_c.exists() or any(not path.exists() for path in header_paths):
        return None
    if shutil.which("cc") is None:
        return None

    source_paths = (parser_c, scanner_c) + header_paths
    if TREE_SITTER_LUA_LIBRARY.exists():
        built_mtime = TREE_SITTER_LUA_LIBRARY.stat().st_mtime
        source_mtime = max(path.stat().st_mtime for path in source_paths)
        if built_mtime >= source_mtime:
            return TREE_SITTER_LUA_LIBRARY

    TREE_SITTER_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        "cc",
        "-shared",
        "-fPIC",
        "-O2",
        f"-I{VENDOR_LUA_SRC_DIR}",
        "-o",
        str(TREE_SITTER_LUA_LIBRARY),
        str(parser_c),
        str(scanner_c),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        return None
    return TREE_SITTER_LUA_LIBRARY


def _collect_call_sites_tree_sitter(
    source: str,
    qualified_name: str,
    language,
) -> tuple[CallSite, ...] | None:
    try:
        from tree_sitter import Parser
    except Exception:
        return None

    parser = Parser()
    parser.language = language
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    calls: list[CallSite] = []
    stack = [tree.root_node]

    while stack:
        node = stack.pop()
        if node.type == "function_call":
            call_site = _call_site_from_tree_sitter_node(node, source_bytes)
            if call_site is not None and call_site.callee == qualified_name:
                calls.append(call_site)
        stack.extend(reversed(node.children))

    return tuple(calls)


def _collect_receiver_accesses_tree_sitter(
    source: str,
    language,
) -> tuple[ReceiverAccess, ...] | None:
    try:
        from tree_sitter import Parser
    except Exception:
        return None

    parser = Parser()
    parser.language = language
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    accesses: list[ReceiverAccess] = []
    stack = [tree.root_node]

    while stack:
        node = stack.pop()
        if node.type in {"dot_index_expression", "bracket_index_expression"}:
            access = _receiver_access_from_tree_sitter_node(node, source_bytes)
            if access is not None:
                accesses.append(access)
        stack.extend(reversed(node.children))

    accesses.sort(key=lambda item: (item.line, item.column))
    return tuple(accesses)


def _call_site_from_tree_sitter_node(node, source_bytes: bytes) -> CallSite | None:
    arguments_node = None
    for child in node.children:
        if child.type == "arguments":
            arguments_node = child
            break
    if arguments_node is None or not node.children:
        return None

    callee_text = _decode_bytes(source_bytes, node.children[0].start_byte, node.children[0].end_byte)
    args = tuple(
        _decode_bytes(source_bytes, child.start_byte, child.end_byte).strip()
        for child in arguments_node.named_children
    )
    start_point = node.start_point
    offset = len(source_bytes[: node.start_byte].decode("utf-8"))
    return CallSite(
        callee=callee_text,
        offset=offset,
        line=start_point.row + 1,
        column=start_point.column + 1,
        args=args,
    )


def _receiver_access_from_tree_sitter_node(node, source_bytes: bytes) -> ReceiverAccess | None:
    if node.parent is not None and node.parent.type in {
        "dot_index_expression",
        "bracket_index_expression",
    }:
        return None

    expression_text = _decode_bytes(source_bytes, node.start_byte, node.end_byte).strip()
    if _is_immediately_called(source_bytes, node.end_byte):
        return None

    named_children = list(node.named_children)
    if not named_children:
        return None

    receiver_node = named_children[0]
    receiver_text = _decode_bytes(
        source_bytes,
        receiver_node.start_byte,
        receiver_node.end_byte,
    ).strip()
    if not receiver_text:
        return None

    start_point = receiver_node.start_point
    offset = len(source_bytes[: receiver_node.start_byte].decode("utf-8"))
    return ReceiverAccess(
        receiver=receiver_text,
        expression=expression_text,
        offset=offset,
        line=start_point.row + 1,
        column=start_point.column + 1,
    )


def _decode_bytes(source_bytes: bytes, start: int, end: int) -> str:
    return source_bytes[start:end].decode("utf-8")


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


def _collect_receiver_accesses_fallback(source: str) -> tuple[ReceiverAccess, ...]:
    accesses: list[ReceiverAccess] = []
    index = 0

    while index < len(source):
        if not _is_identifier_start(source[index]):
            index += 1
            continue
        if index > 0 and _is_identifier_part(source[index - 1]):
            index += 1
            continue

        parsed = _parse_access_chain(source, index)
        if parsed is None:
            index += 1
            continue

        access, next_index = parsed
        if access is not None:
            accesses.append(access)
        index = max(index + 1, next_index)

    return tuple(accesses)


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


def _parse_access_chain(source: str, start: int) -> tuple[ReceiverAccess | None, int] | None:
    identifier, index = _read_identifier(source, start)
    if identifier is None:
        return None

    current = identifier
    chain_start = start
    last_access: ReceiverAccess | None = None

    while index < len(source):
        if source[index] == ".":
            member, next_index = _read_identifier(source, index + 1)
            if member is None:
                break
            expression = f"{current}.{member}"
            line, column = _line_and_column(source, chain_start)
            last_access = ReceiverAccess(
                receiver=current,
                expression=expression,
                offset=chain_start,
                line=line,
                column=column,
            )
            current = expression
            index = next_index
            continue

        if source[index] == "[":
            close_index = _find_matching_bracket(source, index)
            if close_index == -1:
                break
            inner = source[index + 1 : close_index]
            expression = f"{current}[{inner}]"
            line, column = _line_and_column(source, chain_start)
            last_access = ReceiverAccess(
                receiver=current,
                expression=expression,
                offset=chain_start,
                line=line,
                column=column,
            )
            current = expression
            index = close_index + 1
            continue

        break

    if last_access is None:
        return None
    if _is_immediately_called_text(source, index):
        return (None, index)
    return (last_access, index)


def _read_identifier(source: str, start: int) -> tuple[str | None, int]:
    if start >= len(source) or not _is_identifier_start(source[start]):
        return (None, start)

    index = start + 1
    while index < len(source) and _is_identifier_part(source[index]):
        index += 1
    return (source[start:index], index)


def _find_matching_bracket(source: str, open_bracket_index: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False

    for index in range(open_bracket_index, len(source)):
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
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index

    return -1


def _is_immediately_called(source_bytes: bytes, end_byte: int) -> bool:
    index = end_byte
    while index < len(source_bytes) and chr(source_bytes[index]).isspace():
        index += 1
    if index >= len(source_bytes):
        return False
    return chr(source_bytes[index]) in {"(", ":"}


def _is_immediately_called_text(source: str, index: int) -> bool:
    while index < len(source) and source[index].isspace():
        index += 1
    if index >= len(source):
        return False
    return source[index] in {"(", ":"}


def _is_identifier_start(char: str) -> bool:
    return char == "_" or char.isalpha()


def _is_identifier_part(char: str) -> bool:
    return char == "_" or char.isalnum()


def _line_and_column(source: str, offset: int) -> tuple[int, int]:
    before = source[:offset]
    line = before.count("\n") + 1
    column = offset - before.rfind("\n")
    return line, column
