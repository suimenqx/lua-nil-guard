from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.knowledge import (
    KnowledgeBase,
    KnowledgeFact,
    derive_facts_from_contracts,
    derive_facts_from_summaries,
    facts_for_subject,
)
from lua_nil_review_agent.models import FunctionContract
from lua_nil_review_agent.summaries import summarize_source


def test_knowledge_base_round_trips_json(tmp_path: Path) -> None:
    store = KnowledgeBase(tmp_path / "knowledge.json")
    facts = (
        KnowledgeFact(
            key="normalize_name.returns",
            subject="normalize_name",
            statement="normalize_name always returns string",
            confidence="medium",
            source="human",
        ),
    )

    store.save(facts)
    loaded = store.load()

    assert loaded == facts


def test_facts_for_subject_filters_relevant_entries() -> None:
    facts = (
        KnowledgeFact(
            key="normalize_name.returns",
            subject="normalize_name",
            statement="normalize_name always returns string",
            confidence="medium",
            source="human",
        ),
        KnowledgeFact(
            key="parse_user.req",
            subject="parse_user",
            statement="req may be nil",
            confidence="low",
            source="agent",
        ),
    )

    filtered = facts_for_subject(facts, "normalize_name")

    assert filtered == ("normalize_name always returns string",)


def test_derive_facts_from_summaries_supports_first_value_of_multi_return() -> None:
    source = "\n".join(
        [
            "local function normalize_pair(name)",
            "  name = name or 'guest'",
            "  return name, 'fallback'",
            "end",
        ]
    )

    summaries = summarize_source(Path("demo.lua"), source)
    facts = derive_facts_from_summaries(summaries)

    assert len(facts) == 1
    assert facts[0].subject == "normalize_pair"
    assert facts[0].statement == "normalize_pair returns non-nil value"


def test_derive_facts_from_summaries_uses_qualified_module_names() -> None:
    source = "\n".join(
        [
            "module('account.profile', package.seeall)",
            "function normalize_name(name)",
            "  name = name or 'guest'",
            "  return name",
            "end",
        ]
    )

    summaries = summarize_source(Path("profile.lua"), source)
    facts = derive_facts_from_summaries(summaries)

    assert len(facts) == 1
    assert facts[0].subject == "account.profile.normalize_name"
    assert facts[0].statement == "account.profile.normalize_name returns non-nil value"


def test_derive_facts_from_contracts_emits_high_confidence_non_nil_fact() -> None:
    contracts = (
        FunctionContract(
            qualified_name="user.profile.normalize_name",
            returns_non_nil=True,
            notes="normalizes nil usernames",
        ),
    )

    facts = derive_facts_from_contracts(contracts)

    assert len(facts) == 1
    assert facts[0].subject == "user.profile.normalize_name"
    assert facts[0].confidence == "high"
    assert facts[0].source == "config"


def test_derive_facts_from_contracts_filters_scoped_contracts_by_module() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_in_modules=("user.profile",),
        ),
    )

    assert derive_facts_from_contracts(contracts) == ()
    scoped = derive_facts_from_contracts(contracts, current_module="user.profile")

    assert len(scoped) == 1
    assert scoped[0].subject == "normalize_name"


def test_derive_facts_from_contracts_filters_scoped_contracts_by_function_scope() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_in_function_scopes=("parse_user",),
        ),
    )

    assert derive_facts_from_contracts(contracts) == ()
    scoped = derive_facts_from_contracts(
        contracts,
        current_function_scope="parse_user",
    )

    assert len(scoped) == 1
    assert scoped[0].subject == "normalize_name"


def test_derive_facts_from_contracts_filters_scoped_contracts_by_scope_kind() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_to_scope_kinds=("function_body",),
        ),
    )

    assert derive_facts_from_contracts(contracts) == ()
    scoped = derive_facts_from_contracts(
        contracts,
        current_scope_kind="function_body",
    )

    assert len(scoped) == 1
    assert scoped[0].subject == "normalize_name"


def test_derive_facts_from_contracts_filters_scoped_contracts_by_top_level_phase() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_to_top_level_phases=("post_definitions",),
        ),
    )

    assert derive_facts_from_contracts(contracts) == ()
    scoped = derive_facts_from_contracts(
        contracts,
        current_top_level_phase="post_definitions",
    )

    assert len(scoped) == 1
    assert scoped[0].subject == "normalize_name"


def test_derive_facts_from_contracts_filters_scoped_contracts_by_sink() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_to_sinks=("string.match.arg1",),
        ),
    )

    assert derive_facts_from_contracts(contracts) == ()
    assert (
        derive_facts_from_contracts(
            contracts,
            current_sink_rule_id="string.find.arg1",
            current_sink_name="string.find",
        )
        == ()
    )

    scoped = derive_facts_from_contracts(
        contracts,
        current_sink_rule_id="string.match.arg1",
        current_sink_name="string.match",
    )

    assert len(scoped) == 1
    assert scoped[0].subject == "normalize_name"


def test_derive_facts_from_contracts_skips_call_shaped_contracts_without_call_context() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_with_arg_count=2,
        ),
    )

    facts = derive_facts_from_contracts(contracts)

    assert facts == ()


def test_derive_facts_from_contracts_skips_literal_scoped_contracts_without_call_context() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            required_literal_args=((2, ("''",)),),
        ),
    )

    facts = derive_facts_from_contracts(contracts)

    assert facts == ()


def test_derive_facts_from_contracts_skips_role_scoped_contracts_without_call_context() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_to_call_roles=("assignment_origin",),
        ),
    )

    facts = derive_facts_from_contracts(contracts)

    assert facts == ()


def test_derive_facts_from_contracts_skips_usage_scoped_contracts_without_call_context() -> None:
    contracts = (
        FunctionContract(
            qualified_name="normalize_name",
            returns_non_nil=True,
            applies_to_usage_modes=("single_assignment",),
        ),
    )

    facts = derive_facts_from_contracts(contracts)

    assert facts == ()
