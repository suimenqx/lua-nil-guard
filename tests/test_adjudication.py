from __future__ import annotations

from lua_nil_review_agent.adjudication import adjudicate_packet
from lua_nil_review_agent.models import EvidencePacket, EvidenceTarget, SinkRule


def test_adjudicate_packet_prefers_explicit_safety_evidence() -> None:
    packet = EvidencePacket(
        case_id="case_safe",
        target=EvidenceTarget(
            file="demo.lua",
            line=3,
            column=10,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="if username then\n  return string.match(username, '^a')\nend",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "safe_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": ("if username then",),
        },
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("if x then ... end",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.prosecutor.status == "uncertain"
    assert record.defender.status == "safe"
    assert record.judge.status == "safe"
    assert record.judge.confidence == "high"
    assert record.judge.safety_evidence == ("if username then",)


def test_adjudicate_packet_reports_risk_when_no_safety_evidence_exists() -> None:
    packet = EvidencePacket(
        case_id="case_risky",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=8,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="local username = req.params.username\nreturn string.match(username, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.prosecutor.status == "risky"
    assert record.defender.status == "uncertain"
    assert record.judge.status == "risky"
    assert record.judge.confidence == "medium"
    assert "no guard before string.match" in record.judge.risk_path[-1]
    assert record.judge.suggested_fix == "username = username or ''"


def test_adjudicate_packet_uses_knowledge_facts_as_safety_support() -> None:
    packet = EvidencePacket(
        case_id="case_fact",
        target=EvidenceTarget(
            file="demo.lua",
            line=5,
            column=4,
            sink="string.match",
            arg_index=1,
            expression="normalized",
        ),
        local_context="local normalized = normalize_name(name)\nreturn string.match(normalized, '^a')",
        related_functions=("normalize_name",),
        function_summaries=("normalize_name returns normalized string",),
        knowledge_facts=("normalize_name always returns string",),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("normalize_name(name)",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.defender.status == "safe"
    assert record.judge.status == "safe"
    assert "normalize_name always returns string" in record.judge.safety_evidence


def test_adjudicate_packet_uses_table_fix_for_collection_sinks() -> None:
    packet = EvidencePacket(
        case_id="case_table",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=3,
            sink="table.insert",
            arg_index=1,
            expression="names",
        ),
        local_context='table.insert(names, "guest")',
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.names",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="table.insert.arg1",
        kind="function_arg",
        qualified_name="table.insert",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or {}",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == "names = names or {}"


def test_adjudicate_packet_uses_guard_fix_for_receiver_sinks() -> None:
    packet = EvidencePacket(
        case_id="case_receiver",
        target=EvidenceTarget(
            file="demo.lua",
            line=4,
            column=10,
            sink="member_access",
            arg_index=0,
            expression="profile",
        ),
        local_context="return profile.name",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.profile",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="member_access.receiver",
        kind="receiver",
        qualified_name="member_access",
        arg_index=0,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("if x then ... end",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == "if not profile then return nil end"


def test_adjudicate_packet_uses_table_fix_for_length_sinks() -> None:
    packet = EvidencePacket(
        case_id="case_length",
        target=EvidenceTarget(
            file="demo.lua",
            line=3,
            column=10,
            sink="#",
            arg_index=1,
            expression="items",
        ),
        local_context="return #items",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.items",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="length.operand",
        kind="unary_operand",
        qualified_name="#",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or {}",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == "items = items or {}"


def test_adjudicate_packet_uses_field_alias_for_dot_path_collection_expression() -> None:
    packet = EvidencePacket(
        case_id="case_pairs",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=18,
            sink="pairs",
            arg_index=1,
            expression="req.items",
        ),
        local_context=(
            "  for _, item in pairs(req.items) do\n"
            "    local function use_item()\n"
            "      if item then\n"
            "        return item\n"
            "      end\n"
            "    end\n"
            "    return use_item()\n"
            "  end"
        ),
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.items",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="pairs.arg1",
        kind="function_arg",
        qualified_name="pairs",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or {}",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == (
        "  local items = req.items or {}\n"
        "  for _, item in pairs(items) do\n"
        "    local function use_item()\n"
        "      if item then\n"
        "        return item\n"
        "      end\n"
        "    end\n"
        "    return use_item()\n"
        "  end"
    )


def test_adjudicate_packet_keeps_safe_value_for_non_aliasable_collection_expression() -> None:
    packet = EvidencePacket(
        case_id="case_pairs_index",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=18,
            sink="pairs",
            arg_index=1,
            expression="req.items_by_id[user_id]",
        ),
        local_context="for _, item in pairs(req.items_by_id[user_id]) do\n  return item\nend",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.items_by_id[user_id]",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="pairs.arg1",
        kind="function_arg",
        qualified_name="pairs",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or {}",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == "local safe_value = req.items_by_id[user_id] or {}"


def test_adjudicate_packet_rewrites_target_line_for_dot_path_string_expression() -> None:
    packet = EvidencePacket(
        case_id="case_string_field",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=10,
            sink="string.match",
            arg_index=1,
            expression="req.params.username",
        ),
        local_context='  return string.match(req.params.username, "^guest")',
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == (
        "  local username = req.params.username or ''\n"
        '  return string.match(username, "^guest")'
    )


def test_adjudicate_packet_expands_repeat_until_for_closing_target_line() -> None:
    packet = EvidencePacket(
        case_id="case_repeat_until",
        target=EvidenceTarget(
            file="demo.lua",
            line=4,
            column=9,
            sink="#",
            arg_index=1,
            expression="req.items",
        ),
        local_context=(
            "  repeat\n"
            "    req = refresh(req)\n"
            "  until #req.items > 0"
        ),
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.items",),
            "observed_guards": (),
        },
    )
    rule = SinkRule(
        id="length.operand",
        kind="unary_operand",
        qualified_name="#",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or {}",),
    )

    record = adjudicate_packet(packet, rule)

    assert record.judge.status == "risky"
    assert record.judge.suggested_fix == (
        "  local items = req.items or {}\n"
        "  repeat\n"
        "    req = refresh(req)\n"
        "  until #items > 0"
    )
