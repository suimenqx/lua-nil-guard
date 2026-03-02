from __future__ import annotations

from lua_nil_review_agent.parser_backend import (
    collect_call_sites,
    collect_length_operands,
    get_parser_backend_info,
)


def test_get_parser_backend_info_prefers_local_tree_sitter_backend() -> None:
    info = get_parser_backend_info()

    assert info.name == "tree_sitter_local"
    assert info.tree_sitter_available is True


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
