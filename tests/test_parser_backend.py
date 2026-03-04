from __future__ import annotations

import lua_nil_guard.parser_backend as parser_backend
import pytest
from lua_nil_guard.parser_backend import (
    _find_available_c_compiler,
    _tree_sitter_build_info_matches,
    _tree_sitter_source_signature,
    _write_tree_sitter_build_info,
    ParserBackendInfo,
    collect_binary_operands,
    ParserBackendUnavailableError,
    collect_call_sites,
    collect_length_operands,
    get_parser_backend_info,
)


def test_get_parser_backend_info_prefers_local_tree_sitter_backend() -> None:
    info = get_parser_backend_info()

    assert info.name == "tree_sitter_local"
    assert info.tree_sitter_available is True
    assert info.reason


def test_find_available_c_compiler_falls_back_to_gcc_then_clang(monkeypatch) -> None:
    compiler_paths = {
        "gcc": "/usr/bin/gcc",
        "clang": "/usr/bin/clang",
    }
    monkeypatch.setattr(
        parser_backend.shutil,
        "which",
        lambda name: compiler_paths.get(name),
    )

    compiler_name, compiler_path = _find_available_c_compiler()

    assert compiler_name == "gcc"
    assert compiler_path == "/usr/bin/gcc"


def test_collect_call_sites_finds_function_calls_with_tree_sitter_backend() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "return string.match(username, '^a')",
        ]
    )

    calls = collect_call_sites(source, "string.match")

    assert len(calls) == 1
    assert calls[0].line == 2
    assert calls[0].callee == "string.match"


def test_collect_length_operands_finds_length_operators_with_tree_sitter_backend() -> None:
    source = "\n".join(
        [
            "local count = #items",
            "local nested = #(req.items)",
        ]
    )

    operands = collect_length_operands(source)

    assert len(operands) == 2
    assert operands[0].line == 1
    assert operands[0].operand == "items"
    assert operands[1].line == 2
    assert operands[1].operand == "req.items"


def test_collect_binary_operands_finds_concat_compare_and_arithmetic() -> None:
    source = "\n".join(
        [
            "local message = prefix .. suffix",
            "if score >= limit then return message end",
            "local total = count + bonus",
        ]
    )

    concat_operands = collect_binary_operands(source, "..")
    compare_operands = collect_binary_operands(source, ">=")
    arithmetic_operands = collect_binary_operands(source, "+")

    assert len(concat_operands) == 1
    assert concat_operands[0].left == "prefix"
    assert concat_operands[0].right == "suffix"
    assert concat_operands[0].operator == ".."

    assert len(compare_operands) == 1
    assert compare_operands[0].left == "score"
    assert compare_operands[0].right == "limit"
    assert compare_operands[0].operator == ">="

    assert len(arithmetic_operands) == 1
    assert arithmetic_operands[0].left == "count"
    assert arithmetic_operands[0].right == "bonus"
    assert arithmetic_operands[0].operator == "+"


def test_collect_call_sites_requires_tree_sitter_backend(
    monkeypatch,
) -> None:
    monkeypatch.setattr(parser_backend, "_LANGUAGE_LOAD_ATTEMPTED", True)
    monkeypatch.setattr(parser_backend, "_LANGUAGE_CACHE", None)
    monkeypatch.setattr(
        parser_backend,
        "_BACKEND_INFO_CACHE",
        ParserBackendInfo(
            name="unavailable",
            tree_sitter_available=False,
            reason="tree_sitter Python package not installed",
        ),
    )

    with pytest.raises(ParserBackendUnavailableError):
        collect_call_sites("return string.match(name, '^a')", "string.match")


def test_get_parser_backend_info_reports_local_build_failure_without_python_fallback(
    monkeypatch,
) -> None:
    monkeypatch.setattr(parser_backend, "_LANGUAGE_LOAD_ATTEMPTED", False)
    monkeypatch.setattr(parser_backend, "_LANGUAGE_CACHE", None)
    monkeypatch.setattr(parser_backend, "_BACKEND_INFO_CACHE", None)
    monkeypatch.setattr(
        parser_backend.importlib.util,
        "find_spec",
        lambda name: object() if name == "tree_sitter" else None,
    )
    monkeypatch.setattr(
        parser_backend,
        "_find_available_c_compiler",
        lambda: ("gcc", "/usr/bin/gcc"),
    )
    monkeypatch.setattr(
        parser_backend,
        "_load_local_compiled_language",
        lambda compiler_name, selected_compiler: (
            None,
            "failed to build local tree-sitter grammar with gcc: missing header",
            None,
        ),
    )

    info = get_parser_backend_info()

    assert info.name == "unavailable"
    assert info.tree_sitter_available is False
    assert info.reason == "failed to build local tree-sitter grammar with gcc: missing header"
    assert info.selected_compiler == "gcc (/usr/bin/gcc)"
    assert info.tree_sitter_python_available is True


def test_tree_sitter_build_info_requires_matching_compiler_and_source_signature(
    monkeypatch,
    tmp_path,
) -> None:
    build_info_path = tmp_path / "tree_sitter_lua.json"
    monkeypatch.setattr(parser_backend, "TREE_SITTER_LUA_BUILD_INFO", build_info_path)

    parser_c = tmp_path / "parser.c"
    scanner_c = tmp_path / "scanner.c"
    parser_c.write_text("parser", encoding="utf-8")
    scanner_c.write_text("scanner", encoding="utf-8")

    signature = _tree_sitter_source_signature((parser_c, scanner_c))
    _write_tree_sitter_build_info("gcc", signature)

    assert _tree_sitter_build_info_matches("gcc", signature) is True
    assert _tree_sitter_build_info_matches("clang", signature) is False
    assert _tree_sitter_build_info_matches("gcc", "different-signature") is False
