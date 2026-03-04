from __future__ import annotations

import json
from pathlib import Path

from lua_nil_guard.knowledge import KnowledgeBase
from lua_nil_guard.service import bootstrap_repository, refresh_knowledge_base


def test_refresh_knowledge_base_derives_non_nil_return_facts(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local function normalize_name(name)",
                "  name = name or ''",
                "  return name",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    facts = refresh_knowledge_base(snapshot)

    assert len(facts) == 1
    assert facts[0].subject == "normalize_name"
    assert "non-nil" in facts[0].statement
    persisted = KnowledgeBase(tmp_path / "data" / "knowledge.json").load()
    assert persisted == facts
