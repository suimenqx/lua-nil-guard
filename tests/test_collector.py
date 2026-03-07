from __future__ import annotations

from pathlib import Path

from lua_nil_guard.collector import collect_candidates
from lua_nil_guard.models import DomainKnowledgeConfig, DomainKnowledgeRule, SinkRule


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
    assert candidate.candidate_source == "ast_exact"


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


def test_collect_candidates_tracks_module_qualified_enclosing_function_name() -> None:
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
            "module(\"account.profile\", package.seeall)",
            "",
            "function parse_name(name)",
            "  return string.find(name, 'x')",
            "end",
        ]
    )

    candidates = collect_candidates(Path("demo.lua"), source, sink_rules)

    assert len(candidates) == 1
    assert candidates[0].function_scope == "account.profile.parse_name"


def test_collect_candidates_resets_to_top_level_after_function_end() -> None:
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
            "",
            "local top_name = req.params.name",
            "return string.find(top_name, 'x')",
        ]
    )

    candidates = collect_candidates(Path("demo.lua"), source, sink_rules)

    assert len(candidates) == 2
    assert candidates[0].function_scope == "parse_name"
    assert candidates[1].function_scope == "main"


def test_collect_candidates_finds_configured_receiver_sinks() -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("if x then ... end",),
        ),
    )
    source = "\n".join(
        [
            "local profile = req.profile",
            "return profile.name",
        ]
    )

    candidates = collect_candidates(Path("foo/member.lua"), source, sink_rules)

    assert len(candidates) == 2
    expressions = {candidate.expression for candidate in candidates}
    assert expressions == {"req", "profile"}
    assert all(candidate.sink_rule_id == "member_access.receiver" for candidate in candidates)
    assert all(candidate.sink_name == "member_access" for candidate in candidates)


def test_collect_candidates_skips_member_access_used_as_direct_call_callee() -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("if x then ... end",),
        ),
    )
    source = "return string.match(name, '^a')"

    candidates = collect_candidates(Path("foo/member.lua"), source, sink_rules)

    assert candidates == ()


def test_collect_candidates_skips_package_seeall_in_module_declaration() -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("if x then ... end",),
        ),
    )
    source = "\n".join(
        [
            "module(\"account.profile\", package.seeall)",
            "return profile.name",
        ]
    )

    candidates = collect_candidates(Path("foo/module.lua"), source, sink_rules)

    assert len(candidates) == 1
    assert candidates[0].expression == "profile"


def test_collect_candidates_domain_knowledge_skips_system_table_prefix_receivers() -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("if x then ... end",),
        ),
    )
    domain = DomainKnowledgeConfig(
        rules=(
            DomainKnowledgeRule(
                id="system_name_table_prefix",
                action="skip_candidate",
                symbol_regex=r"^_name_[A-Z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]*)*$",
                applies_to_sinks=("member_access.receiver",),
                assumed_non_nil=True,
                assumed_kind="table",
            ),
            DomainKnowledgeRule(
                id="system_cmd_table_prefix",
                action="skip_candidate",
                symbol_regex=r"^_cmd_[A-Z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]*)*$",
                applies_to_sinks=("member_access.receiver",),
                assumed_non_nil=True,
                assumed_kind="table",
            ),
        )
    )
    source = "\n".join(
        [
            "local _name_TOYS = {}",
            "local _cmd_TASKS = {}",
            "return _name_TOYS.car, _cmd_TASKS.run",
        ]
    )

    candidates = collect_candidates(
        Path("foo/member.lua"),
        source,
        sink_rules,
        domain_knowledge=domain,
    )

    assert len(candidates) == 2
    assert all(candidate.static_state == "pruned_static" for candidate in candidates)
    assert {candidate.prune_reason for candidate in candidates} == {
        "system_name_table_prefix",
        "system_cmd_table_prefix",
    }


def test_collect_candidates_domain_knowledge_skips_uppercase_macro_symbols() -> None:
    sink_rules = (
        SinkRule(
            id="string.find.arg1",
            kind="function_arg",
            qualified_name="string.find",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )
    domain = DomainKnowledgeConfig(
        rules=(
            DomainKnowledgeRule(
                id="uppercase_macro_non_nil",
                action="skip_candidate",
                symbol_regex=r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$",
                applies_to_sinks=(),
                assumed_non_nil=True,
                assumed_kind="macro",
            ),
        )
    )
    source = "return string.find(USER_NAME, '^g')"

    candidates = collect_candidates(
        Path("foo/macro.lua"),
        source,
        sink_rules,
        domain_knowledge=domain,
    )

    assert len(candidates) == 1
    assert candidates[0].static_state == "pruned_static"
    assert candidates[0].prune_reason == "uppercase_macro_non_nil"


def test_collect_candidates_finds_configured_length_operator_sinks() -> None:
    sink_rules = (
        SinkRule(
            id="length.operand",
            kind="unary_operand",
            qualified_name="#",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or {}",),
        ),
    )
    source = "\n".join(
        [
            "local items = req.items",
            "return #items",
        ]
    )

    candidates = collect_candidates(Path("foo/length.lua"), source, sink_rules)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.sink_rule_id == "length.operand"
    assert candidate.sink_name == "#"
    assert candidate.expression == "items"
    assert candidate.symbol == "items"


def test_collect_candidates_finds_binary_operand_sinks() -> None:
    sink_rules = (
        SinkRule(
            id="concat.left",
            kind="binary_operand",
            qualified_name="..",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
        SinkRule(
            id="compare.gte.right",
            kind="binary_operand",
            qualified_name=">=",
            arg_index=2,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or 0",),
        ),
        SinkRule(
            id="arithmetic.add.left",
            kind="binary_operand",
            qualified_name="+",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or 0",),
        ),
    )
    source = "\n".join(
        [
            "local message = prefix .. suffix",
            "if score >= limit then return message end",
            "local total = count + bonus",
        ]
    )

    candidates = collect_candidates(Path("foo/binary.lua"), source, sink_rules)

    assert len(candidates) == 3
    assert [candidate.sink_rule_id for candidate in candidates] == [
        "concat.left",
        "compare.gte.right",
        "arithmetic.add.left",
    ]
    assert [candidate.expression for candidate in candidates] == ["prefix", "limit", "count"]
    assert [candidate.sink_name for candidate in candidates] == [
        "concat.left",
        "compare.gte.right",
        "arithmetic.add.left",
    ]


def test_collect_candidates_skips_non_nil_literal_binary_operands() -> None:
    sink_rules = (
        SinkRule(
            id="concat.left",
            kind="binary_operand",
            qualified_name="..",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
        SinkRule(
            id="concat.right",
            kind="binary_operand",
            qualified_name="..",
            arg_index=2,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )

    candidates = collect_candidates(Path("foo/concat.lua"), "return 'x' .. suffix", sink_rules)

    assert len(candidates) == 1
    assert candidates[0].expression == "suffix"


def test_collect_candidates_finds_nested_binary_operand_sinks() -> None:
    sink_rules = (
        SinkRule(
            id="concat.right",
            kind="binary_operand",
            qualified_name="..",
            arg_index=2,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )

    candidates = collect_candidates(
        Path("foo/nested_concat.lua"),
        "return (prefix .. suffix) .. tail",
        sink_rules,
    )

    assert len(candidates) == 2
    assert {candidate.expression for candidate in candidates} == {"suffix", "tail"}
