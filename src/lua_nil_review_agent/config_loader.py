from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ConfidencePolicy, SinkRule


class ConfigError(ValueError):
    """Raised when project configuration is malformed."""


def initialize_repository_config(
    root: str | Path,
    *,
    force: bool = False,
) -> tuple[Path, Path]:
    """Write the default review config into a target repository root."""

    root_path = Path(root)
    template_root = _default_config_template_root()
    sink_source = template_root / "sink_rules.json"
    policy_source = template_root / "confidence_policy.json"

    for source_path in (sink_source, policy_source):
        if not source_path.is_file():
            raise ConfigError(f"Default config template not found: {source_path}")

    config_dir = root_path / "config"
    sink_target = config_dir / "sink_rules.json"
    policy_target = config_dir / "confidence_policy.json"

    for target_path in (sink_target, policy_target):
        if target_path.exists() and not force:
            raise ConfigError(
                f"Config file already exists: {target_path} (use --force to overwrite)"
            )

    config_dir.mkdir(parents=True, exist_ok=True)
    sink_target.write_text(sink_source.read_text(encoding="utf-8"), encoding="utf-8")
    policy_target.write_text(policy_source.read_text(encoding="utf-8"), encoding="utf-8")
    return sink_target, policy_target


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


def _default_config_template_root() -> Path:
    return Path(__file__).resolve().parents[2] / "config"
