from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_guard.config_loader import (
    ConfigError,
    default_preprocessor_config,
    load_backend_config,
    load_confidence_policy,
    load_domain_knowledge_config,
    load_function_contracts,
    load_preprocessor_config,
    load_sink_rules,
)


ROOT = Path(__file__).resolve().parents[1]


def test_load_sink_rules_reads_built_in_rules() -> None:
    rules = load_sink_rules(ROOT / "config" / "sink_rules.json")

    assert len(rules) >= 4
    assert len({rule.id for rule in rules}) == len(rules)
    assert any(rule.id == "string.match.arg1" for rule in rules)
    assert any(rule.id == "concat.left" for rule in rules)
    assert any(rule.id == "compare.gte.left" for rule in rules)
    assert any(rule.id == "arithmetic.add.left" for rule in rules)
    assert any(rule.id == "string.lower.arg1" for rule in rules)
    assert all(rule.id != "member_access.receiver" for rule in rules)


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


def test_load_preprocessor_config_reads_defaults() -> None:
    config = load_preprocessor_config(ROOT / "config" / "preprocessor_files.json")

    assert config.preprocessor_files == ()
    assert config.preprocessor_globs == ()
    assert config.skip_review_files == ()
    assert config.skip_review_globs == ("id.lua", "*_id.lua")


def test_load_backend_config_reads_defaults() -> None:
    backend_name = load_backend_config(ROOT / "config" / "backend.json")

    assert backend_name == "codex"


def test_load_backend_config_rejects_missing_default_backend(tmp_path: Path) -> None:
    config_path = tmp_path / "backend.json"
    config_path.write_text("{}", encoding="utf-8")

    with pytest.raises(ConfigError, match="default_backend"):
        load_backend_config(config_path)


def test_load_backend_config_rejects_unknown_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "backend.json"
    config_path.write_text(
        json.dumps({"default_backend": "gemini", "model": "gemini-3.1-pro-preview"}),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Unsupported backend config fields"):
        load_backend_config(config_path)


def test_default_preprocessor_config_matches_template_defaults() -> None:
    config = default_preprocessor_config()

    assert config.preprocessor_files == ()
    assert config.preprocessor_globs == ()
    assert config.skip_review_files == ()
    assert config.skip_review_globs == ("id.lua", "*_id.lua")


def test_load_preprocessor_config_reads_explicit_files_and_globs(tmp_path: Path) -> None:
    config_path = tmp_path / "preprocessor_files.json"
    config_path.write_text(
        json.dumps(
            {
                "preprocessor_files": ["src/macros.lua", "src/macros.lua"],
                "preprocessor_globs": ["legacy/*.lua"],
                "skip_review_files": ["src/legacy.lua", "src/legacy.lua"],
                "skip_review_globs": ["vendor/**"],
            }
        ),
        encoding="utf-8",
    )

    config = load_preprocessor_config(config_path)

    assert config.preprocessor_files == ("src/macros.lua",)
    assert config.preprocessor_globs == ("legacy/*.lua",)
    assert config.skip_review_files == ("src/legacy.lua",)
    assert config.skip_review_globs == ("vendor/**",)


def test_load_domain_knowledge_config_reads_defaults() -> None:
    config = load_domain_knowledge_config(ROOT / "config" / "domain_knowledge.json")

    assert len(config.rules) >= 3
    assert any(rule.id == "system_name_table_prefix" for rule in config.rules)
    assert any(rule.id == "system_cmd_table_prefix" for rule in config.rules)
    assert any(rule.id == "uppercase_macro_non_nil" for rule in config.rules)


def test_load_domain_knowledge_config_missing_file_returns_empty(tmp_path: Path) -> None:
    config = load_domain_knowledge_config(tmp_path / "missing.json")

    assert config.rules == ()


def test_load_domain_knowledge_config_rejects_invalid_regex(tmp_path: Path) -> None:
    config_path = tmp_path / "domain_knowledge.json"
    config_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "bad",
                        "action": "skip_candidate",
                        "symbol_regex": "[",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Invalid domain knowledge regex"):
        load_domain_knowledge_config(config_path)


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


def test_load_function_contracts_reads_arg_access_path_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_access_paths": {
                        "1": ["req.params.user", "ngx.var.user"],
                        "2": "fallbacks.names.primary",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].required_arg_access_paths == (
        (1, ("req.params.user", "ngx.var.user")),
        (2, ("fallbacks.names.primary",)),
    )


def test_load_function_contracts_reads_return_slot_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil": True,
                    "applies_to_return_slots": [1, 3],
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].applies_to_return_slots == (1, 3)


def test_load_function_contracts_reads_return_args_by_slot_restrictions(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                        "2": [1, 3],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].returns_non_nil_from_args_by_return_slot == (
        (1, (2,)),
        (2, (1, 3)),
    )


def test_load_function_contracts_reads_guard_requirements_by_return_slot(tmp_path: Path) -> None:
    config_path = tmp_path / "function_contracts.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil_from_args_by_return_slot": {"2": [2]},
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                        "2": [1, 3],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    contracts = load_function_contracts(config_path)

    assert len(contracts) == 1
    assert contracts[0].requires_guarded_args_by_return_slot == (
        (1, (1,)),
        (2, (1, 3)),
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
