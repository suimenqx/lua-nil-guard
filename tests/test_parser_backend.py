from __future__ import annotations

import lua_nil_guard.parser_backend as parser_backend
import pytest
from lua_nil_guard.parser_backend import (
    _find_available_c_compiler,
    ParserBackendInfo,
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
