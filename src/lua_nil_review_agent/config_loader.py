from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ConfidencePolicy, FunctionContract, SinkRule


class ConfigError(ValueError):
    """Raised when project configuration is malformed."""


def initialize_repository_config(
    root: str | Path,
    *,
    force: bool = False,
) -> tuple[Path, Path, Path]:
    """Write the default review config into a target repository root."""

    root_path = Path(root)
    template_root = _default_config_template_root()
    sink_source = template_root / "sink_rules.json"
    policy_source = template_root / "confidence_policy.json"
    contracts_source = template_root / "function_contracts.json"

    for source_path in (sink_source, policy_source, contracts_source):
        if not source_path.is_file():
            raise ConfigError(f"Default config template not found: {source_path}")

    config_dir = root_path / "config"
    sink_target = config_dir / "sink_rules.json"
    policy_target = config_dir / "confidence_policy.json"
    contracts_target = config_dir / "function_contracts.json"

    for target_path in (sink_target, policy_target, contracts_target):
        if target_path.exists() and not force:
            raise ConfigError(
                f"Config file already exists: {target_path} (use --force to overwrite)"
            )

    config_dir.mkdir(parents=True, exist_ok=True)
    sink_target.write_text(sink_source.read_text(encoding="utf-8"), encoding="utf-8")
    policy_target.write_text(policy_source.read_text(encoding="utf-8"), encoding="utf-8")
    contracts_target.write_text(contracts_source.read_text(encoding="utf-8"), encoding="utf-8")
    return sink_target, policy_target, contracts_target


def load_sink_rules(path: str | Path) -> list[SinkRule]:
    """Load and validate the sink rule catalog."""

    data = _read_json(path)
    if not isinstance(data, list):
        raise ConfigError("Sink rules config must be a JSON array")

    rules: list[SinkRule] = []
    seen_ids: set[str] = set()
    for item in data:
        rule = _parse_sink_rule(item)
        if rule.id in seen_ids:
            raise ConfigError(f"Duplicate sink rule id: {rule.id}")
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules


def load_confidence_policy(path: str | Path) -> ConfidencePolicy:
    """Load and validate confidence thresholds."""

    data = _read_json(path)
    if not isinstance(data, dict):
        raise ConfigError("Confidence policy config must be a JSON object")

    levels = data.get("levels")
    report_min = data.get("default_report_min_confidence")
    include_medium = data.get("default_include_medium_in_audit")

    if not isinstance(levels, list) or not levels or any(not isinstance(x, str) for x in levels):
        raise ConfigError("Confidence policy levels must be a non-empty string array")
    if report_min not in levels:
        raise ConfigError("default_report_min_confidence must be one of the configured levels")
    if not isinstance(include_medium, bool):
        raise ConfigError("default_include_medium_in_audit must be a boolean")

    return ConfidencePolicy(
        levels=tuple(levels),
        default_report_min_confidence=report_min,
        default_include_medium_in_audit=include_medium,
    )


def load_function_contracts(path: str | Path) -> list[FunctionContract]:
    """Load and validate user-defined function contracts."""

    data = _read_json(path)
    if not isinstance(data, list):
        raise ConfigError("Function contracts config must be a JSON array")

    contracts: list[FunctionContract] = []
    seen_names: set[str] = set()
    for item in data:
        contract = _parse_function_contract(item)
        if contract.qualified_name in seen_names:
            raise ConfigError(f"Duplicate function contract: {contract.qualified_name}")
        seen_names.add(contract.qualified_name)
        contracts.append(contract)
    return contracts


def _parse_sink_rule(data: Any) -> SinkRule:
    if not isinstance(data, dict):
        raise ConfigError("Each sink rule must be a JSON object")

    try:
        rule_id = _require_str(data, "id")
        kind = _require_str(data, "kind")
        qualified_name = _require_str(data, "qualified_name")
        arg_index = _require_int(data, "arg_index")
        nil_sensitive = _require_bool(data, "nil_sensitive")
        failure_mode = _require_str(data, "failure_mode")
        default_severity = _require_str(data, "default_severity")
        safe_patterns = _require_str_list(data, "safe_patterns")
    except KeyError as exc:
        raise ConfigError(f"Missing required sink rule field: {exc.args[0]}") from exc

    return SinkRule(
        id=rule_id,
        kind=kind,
        qualified_name=qualified_name,
        arg_index=arg_index,
        nil_sensitive=nil_sensitive,
        failure_mode=failure_mode,
        default_severity=default_severity,
        safe_patterns=tuple(safe_patterns),
    )


def _parse_function_contract(data: Any) -> FunctionContract:
    if not isinstance(data, dict):
        raise ConfigError("Each function contract must be a JSON object")

    try:
        qualified_name = _require_str(data, "qualified_name")
    except KeyError as exc:
        raise ConfigError(f"Missing required function contract field: {exc.args[0]}") from exc

    returns_non_nil = data.get("returns_non_nil", False)
    if not isinstance(returns_non_nil, bool):
        raise ConfigError("Function contract field 'returns_non_nil' must be a boolean")
    ensures_non_nil_args = _optional_positive_int_list(data, "ensures_non_nil_args")
    returns_non_nil_from_args = _optional_positive_int_list(data, "returns_non_nil_from_args")
    applies_in_modules = _optional_str_list(data, "applies_in_modules")
    applies_to_sinks = _optional_str_list(data, "applies_to_sinks")
    applies_with_arg_count = _optional_positive_int(data, "applies_with_arg_count")
    required_literal_args = _optional_literal_arg_map(data, "required_literal_args")

    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise ConfigError("Function contract field 'notes' must be a string when provided")

    if not returns_non_nil and not ensures_non_nil_args and not returns_non_nil_from_args:
        raise ConfigError(
            f"Function contract for {qualified_name} must enable at least one supported contract flag"
        )

    return FunctionContract(
        qualified_name=qualified_name,
        returns_non_nil=returns_non_nil,
        ensures_non_nil_args=tuple(ensures_non_nil_args),
        returns_non_nil_from_args=tuple(returns_non_nil_from_args),
        applies_in_modules=tuple(applies_in_modules),
        applies_to_sinks=tuple(applies_to_sinks),
        applies_with_arg_count=applies_with_arg_count,
        required_literal_args=required_literal_args,
        notes=notes,
    )


def _read_json(path: str | Path) -> Any:
    config_path = Path(path)
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in config file: {config_path}") from exc


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data[key]
    if not isinstance(value, str) or not value:
        raise ConfigError(f"Sink rule field '{key}' must be a non-empty string")
    return value


def _require_int(data: dict[str, Any], key: str) -> int:
    value = data[key]
    if not isinstance(value, int):
        raise ConfigError(f"Sink rule field '{key}' must be an integer")
    return value


def _require_bool(data: dict[str, Any], key: str) -> bool:
    value = data[key]
    if not isinstance(value, bool):
        raise ConfigError(f"Sink rule field '{key}' must be a boolean")
    return value


def _require_str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data[key]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"Sink rule field '{key}' must be a string array")
    return value


def _optional_positive_int_list(data: dict[str, Any], key: str) -> list[int]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, int) or item < 1 for item in value):
        raise ConfigError(f"Function contract field '{key}' must be a positive integer array")
    return value


def _optional_positive_int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or value < 1:
        raise ConfigError(f"Function contract field '{key}' must be a positive integer")
    return value


def _optional_literal_arg_map(
    data: dict[str, Any],
    key: str,
) -> tuple[tuple[int, tuple[str, ...]], ...]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(
            f"Function contract field '{key}' must be an object mapping argument indexes to literal strings"
        )

    pairs: list[tuple[int, tuple[str, ...]]] = []
    for raw_index, raw_literals in value.items():
        if not isinstance(raw_index, str) or not raw_index.isdigit() or int(raw_index) < 1:
            raise ConfigError(
                f"Function contract field '{key}' must use positive integer string keys"
            )
        arg_index = int(raw_index)
        if isinstance(raw_literals, str) and raw_literals:
            literals = (raw_literals,)
        elif (
            isinstance(raw_literals, list)
            and raw_literals
            and all(isinstance(item, str) and item for item in raw_literals)
        ):
            literals = tuple(dict.fromkeys(raw_literals))
        else:
            raise ConfigError(
                f"Function contract field '{key}' values must be a non-empty string or string array"
            )
        pairs.append((arg_index, literals))

    pairs.sort(key=lambda item: item[0])
    return tuple(pairs)


def _optional_str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ConfigError(f"Function contract field '{key}' must be a non-empty string array")
    return value


def _default_config_template_root() -> Path:
    return Path(__file__).resolve().parents[2] / "config"
