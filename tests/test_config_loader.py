from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_review_agent.config_loader import (
    ConfigError,
    load_confidence_policy,
    load_function_contracts,
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


def test_load_function_contracts_reads_defaults() -> None:
    contracts = load_function_contracts(ROOT / "config" / "function_contracts.json")

    assert contracts == []


def test_load_function_contracts_rejects_duplicate_names(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {"qualified_name": "user.profile.normalize_name", "returns_non_nil": True},
                {"qualified_name": "user.profile.normalize_name", "returns_non_nil": True},
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Duplicate function contract"):
        load_function_contracts(config_path)


def test_load_function_contracts_allows_guard_only_contracts(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_profile",
                    "ensures_non_nil_args": [1],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].returns_non_nil is False
    assert contracts[0].ensures_non_nil_args == (1,)


def test_load_function_contracts_allows_return_normalizer_contracts(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args": [1],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].returns_non_nil is False
    assert contracts[0].returns_non_nil_from_args == (1,)


def test_load_function_contracts_reads_module_scope_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_in_modules": ["user.profile", "user.settings"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_in_modules == ("user.profile", "user.settings")


def test_load_function_contracts_reads_sink_scope_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_sinks": ["string.match.arg1", "string.match"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_to_sinks == ("string.match.arg1", "string.match")


def test_load_function_contracts_reads_call_shape_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_with_arg_count": 2,
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_with_arg_count == 2


def test_load_function_contracts_reads_literal_arg_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_literal_args": {
                        "2": ["''", '""'],
                        "3": "false",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].required_literal_args == (
        (2, ("''", '""')),
        (3, ("false",)),
    )


def test_load_function_contracts_reads_arg_shape_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_shapes": {
                        "1": ["member_access", "identifier"],
                        "2": "literal",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].required_arg_shapes == (
        (1, ("member_access", "identifier")),
        (2, ("literal",)),
    )


def test_load_function_contracts_reads_arg_root_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_roots": {
                        "1": ["req", "ngx"],
                        "2": "fallbacks",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].required_arg_roots == (
        (1, ("req", "ngx")),
        (2, ("fallbacks",)),
    )


def test_load_function_contracts_reads_arg_prefix_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_prefixes": {
                        "1": ["req.params", "ngx.var"],
                        "2": "fallbacks.names",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].required_arg_prefixes == (
        (1, ("req.params", "ngx.var")),
        (2, ("fallbacks.names",)),
    )


def test_load_function_contracts_reads_call_role_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_call_roles": ["assignment_origin", "sink_expression"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_to_call_roles == ("assignment_origin", "sink_expression")


def test_load_function_contracts_reads_usage_mode_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_usage_modes": ["single_assignment", "direct_sink"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_to_usage_modes == ("single_assignment", "direct_sink")


def test_load_function_contracts_reads_function_scope_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_in_function_scopes": ["parse_user", "main"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_in_function_scopes == ("parse_user", "main")


def test_load_function_contracts_reads_scope_kind_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_scope_kinds": ["top_level", "function_body"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_to_scope_kinds == ("top_level", "function_body")


def test_load_function_contracts_reads_top_level_phase_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_top_level_phases": ["init", "post_definitions"],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_to_top_level_phases == ("init", "post_definitions")
