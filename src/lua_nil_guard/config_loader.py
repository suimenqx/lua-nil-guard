from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .models import (
    AdjudicationPolicy,
    ConfidencePolicy,
    DomainKnowledgeConfig,
    DomainKnowledgeRule,
    FunctionContract,
    PreprocessorConfig,
    SinkRule,
)

_SUPPORTED_ADJUDICATION_MODES = frozenset({"single_pass"})


class ConfigError(ValueError):
    """Raised when project configuration is malformed."""


_SUPPORTED_CALL_ROLES = frozenset({"assignment_origin", "sink_expression", "guard_call"})
_SUPPORTED_USAGE_MODES = frozenset({"single_assignment", "multi_assignment", "direct_sink"})
_SUPPORTED_SCOPE_KINDS = frozenset({"top_level", "function_body"})
_SUPPORTED_TOP_LEVEL_PHASES = frozenset({"init", "post_definitions"})
_SUPPORTED_ARG_SHAPES = frozenset(
    {"identifier", "member_access", "indexed_access", "literal", "call", "expression"}
)
_DEFAULT_PREPROCESSOR_FILES: tuple[str, ...] = ()
_DEFAULT_PREPROCESSOR_GLOBS: tuple[str, ...] = ()
_DEFAULT_SKIP_REVIEW_FILES: tuple[str, ...] = ()
_DEFAULT_SKIP_REVIEW_GLOBS: tuple[str, ...] = ("id.lua", "*_id.lua")


def initialize_repository_config(
    root: str | Path,
    *,
    force: bool = False,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    """Write the default review config into a target repository root."""

    root_path = Path(root)
    template_root = _default_config_template_root()
    sink_source = template_root / "sink_rules.json"
    policy_source = template_root / "confidence_policy.json"
    contracts_source = template_root / "function_contracts.json"
    preprocessor_source = template_root / "preprocessor_files.json"
    domain_source = template_root / "domain_knowledge.json"
    backend_source = template_root / "backend.json"

    for source_path in (
        sink_source,
        policy_source,
        contracts_source,
        preprocessor_source,
        domain_source,
        backend_source,
    ):
        if not source_path.is_file():
            raise ConfigError(f"Default config template not found: {source_path}")

    config_dir = root_path / "config"
    sink_target = config_dir / "sink_rules.json"
    policy_target = config_dir / "confidence_policy.json"
    contracts_target = config_dir / "function_contracts.json"
    preprocessor_target = config_dir / "preprocessor_files.json"
    domain_target = config_dir / "domain_knowledge.json"
    backend_target = config_dir / "backend.json"

    config_dir.mkdir(parents=True, exist_ok=True)
    for source_path, target_path in (
        (sink_source, sink_target),
        (policy_source, policy_target),
        (contracts_source, contracts_target),
        (preprocessor_source, preprocessor_target),
        (domain_source, domain_target),
        (backend_source, backend_target),
    ):
        if target_path.exists() and not force:
            continue
        target_path.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")
    return (
        sink_target,
        policy_target,
        contracts_target,
        preprocessor_target,
        domain_target,
        backend_target,
    )


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


def load_preprocessor_config(path: str | Path) -> PreprocessorConfig:
    """Load optional preprocessor dictionary file classification config."""

    data = _read_json(path)
    if not isinstance(data, dict):
        raise ConfigError("Preprocessor config must be a JSON object")

    explicit_files = _optional_str_list(data, "preprocessor_files")
    globs = _optional_str_list(data, "preprocessor_globs")
    skip_files = _optional_str_list(data, "skip_review_files")
    skip_globs = _optional_str_list(data, "skip_review_globs")

    return PreprocessorConfig(
        preprocessor_files=tuple(dict.fromkeys(explicit_files)),
        preprocessor_globs=tuple(dict.fromkeys(globs)),
        skip_review_files=tuple(dict.fromkeys(skip_files)),
        skip_review_globs=tuple(dict.fromkeys(skip_globs)),
    )


def load_domain_knowledge_config(path: str | Path) -> DomainKnowledgeConfig:
    """Load optional domain-specific fast-pruning rules."""

    file_path = Path(path)
    if not file_path.is_file():
        return DomainKnowledgeConfig()
    data = _read_json(file_path)
    if not isinstance(data, dict):
        raise ConfigError("Domain knowledge config must be a JSON object")

    rules_payload = data.get("rules", [])
    if not isinstance(rules_payload, list):
        raise ConfigError("Domain knowledge field 'rules' must be a JSON array")

    rules: list[DomainKnowledgeRule] = []
    seen_ids: set[str] = set()
    for item in rules_payload:
        rule = _parse_domain_knowledge_rule(item)
        if rule.id in seen_ids:
            raise ConfigError(f"Duplicate domain knowledge rule id: {rule.id}")
        seen_ids.add(rule.id)
        rules.append(rule)
    return DomainKnowledgeConfig(rules=tuple(rules))


def load_adjudication_policy(path: str | Path) -> AdjudicationPolicy:
    """Load adjudication mode and calibration policy.

    Returns the default policy when the file does not exist.
    """

    file_path = Path(path)
    if not file_path.is_file():
        return AdjudicationPolicy()

    data = _read_json(file_path)
    if not isinstance(data, dict):
        raise ConfigError("Adjudication policy config must be a JSON object")

    mode = data.get("adjudication_mode", "single_pass")
    if mode not in _SUPPORTED_ADJUDICATION_MODES:
        raise ConfigError(
            f"Unsupported adjudication_mode: {mode!r}. "
            f"Must be one of: {', '.join(sorted(_SUPPORTED_ADJUDICATION_MODES))}"
        )
    allowed_keys = {"adjudication_mode", "calibration"}
    unknown_keys = sorted(set(data) - allowed_keys)
    if unknown_keys:
        raise ConfigError(
            "Unsupported adjudication policy fields: "
            + ", ".join(unknown_keys)
        )
    calibration = data.get("calibration", {})

    return AdjudicationPolicy(
        adjudication_mode=mode,
        calibration_cold_start_threshold=int(calibration.get("cold_start_threshold", 30)),
        calibration_recalibrate_interval_runs=int(calibration.get("recalibrate_interval_runs", 5)),
    )


def load_backend_config(path: str | Path) -> str:
    """Load the repository default adjudication backend name."""

    data = _read_json(path)
    if not isinstance(data, dict):
        raise ConfigError("Backend config must be a JSON object")
    default_backend = data.get("default_backend")
    if not isinstance(default_backend, str) or not default_backend.strip():
        raise ConfigError("Backend config field 'default_backend' must be a non-empty string")
    unknown_keys = sorted(set(data) - {"default_backend"})
    if unknown_keys:
        raise ConfigError("Unsupported backend config fields: " + ", ".join(unknown_keys))
    return default_backend.strip()


def default_preprocessor_config() -> PreprocessorConfig:
    """Return the built-in preprocessor dictionary defaults."""

    return PreprocessorConfig(
        preprocessor_files=_DEFAULT_PREPROCESSOR_FILES,
        preprocessor_globs=_DEFAULT_PREPROCESSOR_GLOBS,
        skip_review_files=_DEFAULT_SKIP_REVIEW_FILES,
        skip_review_globs=_DEFAULT_SKIP_REVIEW_GLOBS,
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


def _parse_domain_knowledge_rule(data: Any) -> DomainKnowledgeRule:
    if not isinstance(data, dict):
        raise ConfigError("Each domain knowledge rule must be a JSON object")

    try:
        rule_id = _require_str(data, "id")
        action = _require_str(data, "action")
        symbol_regex = _require_str(data, "symbol_regex")
    except KeyError as exc:
        raise ConfigError(f"Missing required domain knowledge field: {exc.args[0]}") from exc

    if action != "skip_candidate":
        raise ConfigError("Domain knowledge field 'action' must be 'skip_candidate'")
    try:
        re.compile(symbol_regex)
    except re.error as exc:
        raise ConfigError(f"Invalid domain knowledge regex for {rule_id}: {exc}") from exc

    applies_to_sinks = data.get("applies_to_sinks", [])
    if (
        not isinstance(applies_to_sinks, list)
        or any(not isinstance(item, str) or not item for item in applies_to_sinks)
    ):
        raise ConfigError("Domain knowledge field 'applies_to_sinks' must be a string array")

    assumed_non_nil = data.get("assumed_non_nil", True)
    if not isinstance(assumed_non_nil, bool):
        raise ConfigError("Domain knowledge field 'assumed_non_nil' must be a boolean")

    assumed_kind = data.get("assumed_kind")
    if assumed_kind is not None and (not isinstance(assumed_kind, str) or not assumed_kind):
        raise ConfigError("Domain knowledge field 'assumed_kind' must be a non-empty string")

    return DomainKnowledgeRule(
        id=rule_id,
        action=action,
        symbol_regex=symbol_regex,
        applies_to_sinks=tuple(dict.fromkeys(applies_to_sinks)),
        assumed_non_nil=assumed_non_nil,
        assumed_kind=assumed_kind,
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
    returns_non_nil_from_args_by_return_slot = _optional_positive_int_index_map(
        data,
        "returns_non_nil_from_args_by_return_slot",
    )
    requires_guarded_args_by_return_slot = _optional_positive_int_index_map(
        data,
        "requires_guarded_args_by_return_slot",
    )
    applies_in_modules = _optional_str_list(data, "applies_in_modules")
    applies_in_function_scopes = _optional_str_list(data, "applies_in_function_scopes")
    applies_to_top_level_phases = _optional_str_list(data, "applies_to_top_level_phases")
    applies_to_scope_kinds = _optional_str_list(data, "applies_to_scope_kinds")
    applies_to_sinks = _optional_str_list(data, "applies_to_sinks")
    applies_to_call_roles = _optional_str_list(data, "applies_to_call_roles")
    applies_to_usage_modes = _optional_str_list(data, "applies_to_usage_modes")
    applies_to_return_slots = _optional_positive_int_list(data, "applies_to_return_slots")
    applies_with_arg_count = _optional_positive_int(data, "applies_with_arg_count")
    required_literal_args = _optional_choice_arg_map(
        data,
        "required_literal_args",
        value_label="literal strings",
    )
    required_arg_shapes = _optional_choice_arg_map(
        data,
        "required_arg_shapes",
        value_label="argument shape names",
    )
    required_arg_roots = _optional_choice_arg_map(
        data,
        "required_arg_roots",
        value_label="argument root names",
    )
    required_arg_prefixes = _optional_choice_arg_map(
        data,
        "required_arg_prefixes",
        value_label="argument path prefixes",
    )
    required_arg_access_paths = _optional_choice_arg_map(
        data,
        "required_arg_access_paths",
        value_label="exact argument access paths",
    )
    if any(role not in _SUPPORTED_CALL_ROLES for role in applies_to_call_roles):
        raise ConfigError(
            "Function contract field 'applies_to_call_roles' must contain only "
            "assignment_origin, sink_expression, or guard_call"
        )
    if any(mode not in _SUPPORTED_USAGE_MODES for mode in applies_to_usage_modes):
        raise ConfigError(
            "Function contract field 'applies_to_usage_modes' must contain only "
            "single_assignment, multi_assignment, or direct_sink"
        )
    if any(kind not in _SUPPORTED_SCOPE_KINDS for kind in applies_to_scope_kinds):
        raise ConfigError(
            "Function contract field 'applies_to_scope_kinds' must contain only "
            "top_level or function_body"
        )
    if any(phase not in _SUPPORTED_TOP_LEVEL_PHASES for phase in applies_to_top_level_phases):
        raise ConfigError(
            "Function contract field 'applies_to_top_level_phases' must contain only "
            "init or post_definitions"
        )
    if any(
        shape not in _SUPPORTED_ARG_SHAPES
        for _, allowed_shapes in required_arg_shapes
        for shape in allowed_shapes
    ):
        raise ConfigError(
            "Function contract field 'required_arg_shapes' must contain only "
            "identifier, member_access, indexed_access, literal, call, or expression"
        )

    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise ConfigError("Function contract field 'notes' must be a string when provided")

    if (
        not returns_non_nil
        and not ensures_non_nil_args
        and not returns_non_nil_from_args
        and not returns_non_nil_from_args_by_return_slot
    ):
        raise ConfigError(
            f"Function contract for {qualified_name} must enable at least one supported contract flag"
        )

    return FunctionContract(
        qualified_name=qualified_name,
        returns_non_nil=returns_non_nil,
        ensures_non_nil_args=tuple(ensures_non_nil_args),
        returns_non_nil_from_args=tuple(returns_non_nil_from_args),
        returns_non_nil_from_args_by_return_slot=returns_non_nil_from_args_by_return_slot,
        requires_guarded_args_by_return_slot=requires_guarded_args_by_return_slot,
        applies_in_modules=tuple(applies_in_modules),
        applies_in_function_scopes=tuple(dict.fromkeys(applies_in_function_scopes)),
        applies_to_top_level_phases=tuple(dict.fromkeys(applies_to_top_level_phases)),
        applies_to_scope_kinds=tuple(dict.fromkeys(applies_to_scope_kinds)),
        applies_to_sinks=tuple(applies_to_sinks),
        applies_to_call_roles=tuple(dict.fromkeys(applies_to_call_roles)),
        applies_to_usage_modes=tuple(dict.fromkeys(applies_to_usage_modes)),
        applies_to_return_slots=tuple(dict.fromkeys(applies_to_return_slots)),
        applies_with_arg_count=applies_with_arg_count,
        required_literal_args=required_literal_args,
        required_arg_shapes=required_arg_shapes,
        required_arg_roots=required_arg_roots,
        required_arg_prefixes=required_arg_prefixes,
        required_arg_access_paths=required_arg_access_paths,
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


def _optional_choice_arg_map(
    data: dict[str, Any],
    key: str,
    *,
    value_label: str,
) -> tuple[tuple[int, tuple[str, ...]], ...]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(
            f"Function contract field '{key}' must be an object mapping argument indexes to {value_label}"
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


def _optional_positive_int_index_map(
    data: dict[str, Any],
    key: str,
) -> tuple[tuple[int, tuple[int, ...]], ...]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(
            f"Function contract field '{key}' must be an object mapping positive integer slots to positive integer argument indexes"
        )

    pairs: list[tuple[int, tuple[int, ...]]] = []
    for raw_index, raw_positions in value.items():
        if not isinstance(raw_index, str) or not raw_index.isdigit() or int(raw_index) < 1:
            raise ConfigError(
                f"Function contract field '{key}' must use positive integer string keys"
            )
        slot = int(raw_index)
        if isinstance(raw_positions, int) and raw_positions >= 1:
            positions = (raw_positions,)
        elif (
            isinstance(raw_positions, list)
            and raw_positions
            and all(isinstance(item, int) and item >= 1 for item in raw_positions)
        ):
            positions = tuple(dict.fromkeys(raw_positions))
        else:
            raise ConfigError(
                f"Function contract field '{key}' values must be a positive integer or positive integer array"
            )
        pairs.append((slot, positions))

    pairs.sort(key=lambda item: item[0])
    return tuple(pairs)


def _optional_str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ConfigError(f"Function contract field '{key}' must be a non-empty string array")
    return value


def _default_config_template_root() -> Path:
    return Path(__file__).resolve().parents[2] / "config"
