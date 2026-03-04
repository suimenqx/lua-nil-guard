from __future__ import annotations

from pathlib import Path

from lua_nil_guard.summaries import SummaryStore, summarize_source


def test_summarize_source_extracts_basic_function_contracts() -> None:
    source = "\n".join(
        [
            "local function normalize_name(name, fallback)",
            "  assert(fallback)",
            "  name = name or fallback",
            "  return name",
            "end",
        ]
    )

    summaries = summarize_source(Path("demo.lua"), source)

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.function_name == "normalize_name"
    assert summary.qualified_name == "normalize_name"
    assert summary.function_id == "demo.lua::normalize_name:1"
    assert summary.params["name"] == "non_nil_if_guarded"
    assert summary.params["fallback"] == "non_nil_required"
    assert "assert(fallback)" in summary.guards
    assert "name = name or fallback" in summary.guards


def test_summarize_source_qualifies_module_functions() -> None:
    source = "\n".join(
        [
            "module(\"account.profile\", package.seeall)",
            "",
            "function normalize_name(name)",
            "  name = name or 'guest'",
            "  return name",
            "end",
        ]
    )

    summaries = summarize_source(Path("profile.lua"), source)

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.function_name == "normalize_name"
    assert summary.qualified_name == "account.profile.normalize_name"
    assert summary.module_name == "account.profile"
    assert summary.function_id == "profile.lua::account.profile.normalize_name:3"


def test_summary_store_round_trips_json(tmp_path: Path) -> None:
    store = SummaryStore(tmp_path / "function_summaries.json")
    source = "\n".join(
        [
            "local function normalize_name(name)",
            "  name = name or ''",
            "  return name",
            "end",
        ]
    )
    summaries = summarize_source(Path("demo.lua"), source)

    store.save(summaries)
    loaded = store.load()

    assert loaded == summaries
