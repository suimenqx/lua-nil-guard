from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_review_agent.config_loader import (
    ConfigError,
    load_confidence_policy,
    load_sink_rules,
)


ROOT = Path(__file__).resolve().parents[1]


def test_load_sink_rules_reads_built_in_rules() -> None:
    rules = load_sink_rules(ROOT / "config" / "sink_rules.json")

    assert len(rules) >= 4
    assert len({rule.id for rule in rules}) == len(rules)
    assert any(rule.id == "string.match.arg1" for rule in rules)


def test_load_sink_rules_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    data = [
        {
            "id": "dup.rule",
            "kind": "function_arg",
            "qualified_name": "string.match",
            "arg_index": 1,
            "nil_sensitive": True,
            "failure_mode": "runtime_error",
            "default_severity": "high",
            "safe_patterns": [],
        },
        {
            "id": "dup.rule",
            "kind": "function_arg",
            "qualified_name": "string.find",
            "arg_index": 1,
            "nil_sensitive": True,
            "failure_mode": "runtime_error",
            "default_severity": "high",
            "safe_patterns": [],
        },
    ]
    config_path = tmp_path / "sink_rules.json"
    config_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ConfigError, match="Duplicate sink rule id"):
        load_sink_rules(config_path)


def test_load_confidence_policy_reads_defaults() -> None:
    policy = load_confidence_policy(ROOT / "config" / "confidence_policy.json")

    assert policy.default_report_min_confidence == "high"
    assert policy.default_include_medium_in_audit is True
    assert policy.levels == ("low", "medium", "high")
