from __future__ import annotations

from lua_nil_review_agent.parser_backend import (
    collect_call_sites,
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
