from __future__ import annotations

from lua_nil_review_agent.parser_backend import (
    collect_call_sites,
    get_parser_backend_info,
)


def test_get_parser_backend_info_uses_regex_fallback_when_tree_sitter_missing() -> None:
    info = get_parser_backend_info()

    assert info.name == "regex_fallback"
    assert info.tree_sitter_available is False


def test_collect_call_sites_finds_function_calls_with_fallback_backend() -> None:
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
