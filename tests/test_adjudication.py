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
    assert record.judge.suggested_fix == "local safe_value = username or ''"


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
    assert record.judge.suggested_fix == "local safe_value = names or {}"


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
    assert record.judge.suggested_fix == "local safe_value = items or {}"
