from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.collector import collect_candidates
from lua_nil_review_agent.models import SinkRule


def test_collect_candidates_finds_configured_function_sinks() -> None:
    sink_rules = (
        SinkRule(
            id="string.match.arg1",
            kind="function_arg",
            qualified_name="string.match",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )
    source = "\n".join(
        [
            "local username = req.params.username",
            "return string.match(username, '^a')",
        ]
    )

    candidates = collect_candidates(Path("foo/bar.lua"), source, sink_rules)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "foo/bar.lua"
    assert candidate.line == 2
    assert candidate.sink_rule_id == "string.match.arg1"
    assert candidate.sink_name == "string.match"
    assert candidate.expression == "username"
    assert candidate.symbol == "username"
    assert candidate.static_state == "unknown_static"


def test_collect_candidates_tracks_enclosing_function_name() -> None:
    sink_rules = (
        SinkRule(
            id="string.find.arg1",
            kind="function_arg",
            qualified_name="string.find",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("assert(x)",),
        ),
    )
    source = "\n".join(
        [
            "local function parse_name(name)",
            "  return string.find(name, 'x')",
            "end",
        ]
    )

    candidates = collect_candidates(Path("demo.lua"), source, sink_rules)

    assert len(candidates) == 1
    assert candidates[0].function_scope == "parse_name"
