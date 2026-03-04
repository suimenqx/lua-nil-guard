from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import warnings


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VENDOR_LUA_SRC_DIR = PROJECT_ROOT / "vendor" / "tree-sitter-lua" / "src"
TREE_SITTER_BUILD_DIR = Path.home() / ".cache" / "lua-nil-guard" / "tree_sitter"
TREE_SITTER_LUA_LIBRARY = TREE_SITTER_BUILD_DIR / "tree_sitter_lua.so"
TREE_SITTER_LUA_BUILD_INFO = TREE_SITTER_BUILD_DIR / "tree_sitter_lua.json"
COMPILER_CANDIDATES = ("cc", "gcc", "clang")

_LANGUAGE_CACHE = None
_CDLL_CACHE = None
_BACKEND_INFO_CACHE = None
_LANGUAGE_LOAD_ATTEMPTED = False


@dataclass(frozen=True, slots=True)
class ParserBackendInfo:
    """Describe the active parser backend and its capabilities."""

    name: str
    tree_sitter_available: bool
    reason: str
    selected_compiler: str | None = None
    local_library_path: str | None = None
    tree_sitter_python_available: bool = False


class ParserBackendUnavailableError(ValueError):
    """Raised when Tree-sitter-backed parsing is required but unavailable."""


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


@dataclass(frozen=True, slots=True)
class LengthOperand:
    """A normalized Lua length-operator operand discovered by the active backend."""

    operand: str
    offset: int
    line: int
    column: int


def get_parser_backend_info() -> ParserBackendInfo:
    """Return the active parser backend description."""

    _load_lua_language()
    if _BACKEND_INFO_CACHE is not None:
        return _BACKEND_INFO_CACHE
    return ParserBackendInfo(
        name="unavailable",
        tree_sitter_available=False,
        reason="parser backend state unavailable",
    )


def collect_call_sites(source: str, qualified_name: str) -> tuple[CallSite, ...]:
    """Collect call sites for a qualified name using the active backend."""

    language = _require_tree_sitter_language()
    tree_sitter_calls = _collect_call_sites_tree_sitter(source, qualified_name, language)
    if tree_sitter_calls is None:
        raise ParserBackendUnavailableError("tree_sitter Parser unavailable for call-site collection")
    return tree_sitter_calls


def collect_receiver_accesses(source: str) -> tuple[ReceiverAccess, ...]:
    """Collect non-call member access expressions using the active backend."""

    language = _require_tree_sitter_language()
    tree_sitter_accesses = _collect_receiver_accesses_tree_sitter(source, language)
    if tree_sitter_accesses is None:
        raise ParserBackendUnavailableError(
            "tree_sitter Parser unavailable for receiver-access collection"
        )
    return tree_sitter_accesses


def collect_length_operands(source: str) -> tuple[LengthOperand, ...]:
    """Collect length-operator operands using the active backend."""

    language = _require_tree_sitter_language()
    tree_sitter_operands = _collect_length_operands_tree_sitter(source, language)
    if tree_sitter_operands is None:
        raise ParserBackendUnavailableError(
            "tree_sitter Parser unavailable for length-operand collection"
        )
    return tree_sitter_operands


def _require_tree_sitter_language():
    language = _load_lua_language()
    if language is not None:
        return language
    backend_info = get_parser_backend_info()
    raise ParserBackendUnavailableError(
        f"Tree-sitter parser backend unavailable: {backend_info.reason}"
    )


def _load_lua_language():
    global _LANGUAGE_CACHE, _LANGUAGE_LOAD_ATTEMPTED
    if _LANGUAGE_LOAD_ATTEMPTED:
        return _LANGUAGE_CACHE
    _LANGUAGE_LOAD_ATTEMPTED = True

    compiler_name, compiler_path = _find_available_c_compiler()
    selected_compiler = (
        f"{compiler_name} ({compiler_path})"
        if compiler_name is not None and compiler_path is not None
        else None
    )

    if importlib.util.find_spec("tree_sitter") is None:
        _set_backend_info(
            ParserBackendInfo(
                name="unavailable",
                tree_sitter_available=False,
                reason="tree_sitter Python package not installed",
                selected_compiler=selected_compiler,
                tree_sitter_python_available=False,
            )
        )
        return None

    language, local_reason, library_path = _load_local_compiled_language(
        compiler_name,
        selected_compiler,
    )
    if language is not None:
        _LANGUAGE_CACHE = language
        _set_backend_info(
            ParserBackendInfo(
                name="tree_sitter_local",
                tree_sitter_available=True,
                reason="using locally built tree-sitter grammar",
                selected_compiler=selected_compiler,
                local_library_path=str(library_path) if library_path is not None else None,
                tree_sitter_python_available=True,
            )
        )
        return _LANGUAGE_CACHE

    reason = local_reason or "local tree-sitter grammar unavailable"
    _set_backend_info(
        ParserBackendInfo(
            name="unavailable",
            tree_sitter_available=False,
            reason=reason,
            selected_compiler=selected_compiler,
            local_library_path=str(library_path) if library_path is not None else None,
            tree_sitter_python_available=True,
        )
    )
    return None


def _load_local_compiled_language(
    compiler_name: str | None,
    selected_compiler: str | None,
):
    library_path, reason = _ensure_local_language_library(compiler_name)
    if library_path is None:
        return None, reason, None

    try:
        from tree_sitter import Language
    except Exception as exc:
        return (
            None,
            f"tree_sitter Python import failed while loading local grammar: {exc}",
            library_path,
        )

    try:
        global _CDLL_CACHE
        _CDLL_CACHE = ctypes.CDLL(str(library_path))
        language_fn = _CDLL_CACHE.tree_sitter_lua
        language_fn.restype = ctypes.c_void_p
        ptr = language_fn()
        if not ptr:
            return None, "local tree-sitter library returned a null language pointer", library_path
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return Language(ptr), None, library_path
    except Exception as exc:
        compiler_hint = f" via {selected_compiler}" if selected_compiler else ""
        return (
            None,
            f"failed to load local tree-sitter library{compiler_hint}: {exc}",
            library_path,
        )


def _ensure_local_language_library(compiler_name: str | None) -> tuple[Path | None, str | None]:
    parser_c = VENDOR_LUA_SRC_DIR / "parser.c"
    scanner_c = VENDOR_LUA_SRC_DIR / "scanner.c"
    header_dir = VENDOR_LUA_SRC_DIR / "tree_sitter"
    header_paths = (
        header_dir / "parser.h",
        header_dir / "alloc.h",
        header_dir / "array.h",
    )
    if not parser_c.exists() or not scanner_c.exists() or any(not path.exists() for path in header_paths):
        return None, "vendored tree-sitter-lua grammar sources not found"

    source_paths = (parser_c, scanner_c) + header_paths
    source_signature = _tree_sitter_source_signature(source_paths)
    if TREE_SITTER_LUA_LIBRARY.exists():
        if _tree_sitter_build_info_matches(compiler_name, source_signature):
            return TREE_SITTER_LUA_LIBRARY, None

    if compiler_name is None:
        return None, (
            "no C compiler found (tried: "
            + ", ".join(COMPILER_CANDIDATES)
            + ")"
        )

    TREE_SITTER_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        compiler_name,
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
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or exc.stdout or "").strip()
        detail = stderr.splitlines()[0] if stderr else f"exit code {exc.returncode}"
        return None, f"failed to build local tree-sitter grammar with {compiler_name}: {detail}"
    _write_tree_sitter_build_info(compiler_name, source_signature)
    return TREE_SITTER_LUA_LIBRARY, None


def _find_available_c_compiler() -> tuple[str | None, str | None]:
    for compiler_name in COMPILER_CANDIDATES:
        compiler_path = shutil.which(compiler_name)
        if compiler_path:
            return compiler_name, compiler_path
    return None, None


def _set_backend_info(info: ParserBackendInfo) -> None:
    global _BACKEND_INFO_CACHE
    _BACKEND_INFO_CACHE = info


def _tree_sitter_source_signature(source_paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in source_paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _tree_sitter_build_info_matches(
    compiler_name: str | None,
    source_signature: str,
) -> bool:
    if compiler_name is None:
        return False
    if not TREE_SITTER_LUA_BUILD_INFO.exists():
        return False
    try:
        payload = json.loads(TREE_SITTER_LUA_BUILD_INFO.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        payload.get("compiler") == compiler_name
        and payload.get("source_signature") == source_signature
    )


def _write_tree_sitter_build_info(compiler_name: str, source_signature: str) -> None:
    payload = {
        "compiler": compiler_name,
        "source_signature": source_signature,
    }
    TREE_SITTER_LUA_BUILD_INFO.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )


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


def _collect_length_operands_tree_sitter(
    source: str,
    language,
) -> tuple[LengthOperand, ...] | None:
    try:
        from tree_sitter import Parser
    except Exception:
        return None

    parser = Parser()
    parser.language = language
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    operands: list[LengthOperand] = []
    stack = [tree.root_node]

    while stack:
        node = stack.pop()
        if node.type == "unary_expression":
            operand = _length_operand_from_tree_sitter_node(node, source_bytes)
            if operand is not None:
                operands.append(operand)
        stack.extend(reversed(node.children))

    operands.sort(key=lambda item: (item.line, item.column))
    return tuple(operands)


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


def _length_operand_from_tree_sitter_node(node, source_bytes: bytes) -> LengthOperand | None:
    if len(node.children) < 2 or node.children[0].type != "#":
        return None

    named_children = list(node.named_children)
    if not named_children:
        return None

    operand_node = named_children[0]
    if operand_node.type == "parenthesized_expression":
        nested = list(operand_node.named_children)
        if len(nested) != 1:
            return None
        operand_node = nested[0]

    operand_text = _decode_bytes(
        source_bytes,
        operand_node.start_byte,
        operand_node.end_byte,
    ).strip()
    if not operand_text:
        return None

    start_point = node.start_point
    offset = len(source_bytes[: node.start_byte].decode("utf-8"))
    return LengthOperand(
        operand=operand_text,
        offset=offset,
        line=start_point.row + 1,
        column=start_point.column + 1,
    )


def _decode_bytes(source_bytes: bytes, start: int, end: int) -> str:
    return source_bytes[start:end].decode("utf-8")


def _is_immediately_called(source_bytes: bytes, end_byte: int) -> bool:
    index = end_byte
    while index < len(source_bytes) and chr(source_bytes[index]).isspace():
        index += 1
    if index >= len(source_bytes):
        return False
    return chr(source_bytes[index]) in {"(", ":"}
