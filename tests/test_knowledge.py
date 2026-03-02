from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.knowledge import (
    KnowledgeBase,
    KnowledgeFact,
    derive_facts_from_summaries,
    facts_for_subject,
)
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
