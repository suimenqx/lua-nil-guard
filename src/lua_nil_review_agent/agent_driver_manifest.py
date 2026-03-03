from __future__ import annotations

import json
from pathlib import Path

from .agent_driver_models import AgentCapabilities, AgentProviderSpec


BUILTIN_AGENT_PROVIDER_MANIFESTS: dict[str, dict[str, object]] = {
    "codex": {
        "name": "codex",
        "protocol": "schema_file_cli",
        "default_executable": "codex",
        "default_timeout_seconds": 45.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": True,
            "supports_backend_cache": True,
            "supports_output_schema": True,
            "supports_output_file": True,
            "supports_stdout_json": False,
            "supports_tool_free_prompting": True,
        },
    },
    "claude": {
        "name": "claude",
        "protocol": "stdout_structured_cli",
        "default_executable": "claude",
        "default_timeout_seconds": 75.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": False,
            "supports_backend_cache": True,
            "supports_output_schema": True,
            "supports_output_file": False,
            "supports_stdout_json": True,
            "supports_tool_free_prompting": True,
        },
    },
    "gemini": {
        "name": "gemini",
        "protocol": "stdout_envelope_cli",
        "default_executable": "gemini",
        "default_timeout_seconds": 45.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": False,
            "supports_backend_cache": True,
            "supports_output_schema": False,
            "supports_output_file": False,
            "supports_stdout_json": True,
            "supports_tool_free_prompting": True,
        },
    },
    "codeagent": {
        "name": "codeagent",
        "protocol": "stdout_envelope_cli",
        "default_executable": "gemini",
        "default_timeout_seconds": 45.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": False,
            "supports_backend_cache": True,
            "supports_output_schema": False,
            "supports_output_file": False,
            "supports_stdout_json": True,
            "supports_tool_free_prompting": True,
        },
    },
}


def load_agent_provider_spec_manifest(payload: dict[str, object]) -> AgentProviderSpec:
    """Validate a manifest payload and convert it into a provider spec."""

    capabilities_payload = payload.get("capabilities", {})
    if not isinstance(capabilities_payload, dict):
        raise ValueError("Provider manifest field 'capabilities' must be an object")
    capabilities = AgentCapabilities(
        supports_model_override=_optional_manifest_bool(
            capabilities_payload,
            "supports_model_override",
            default=False,
        ),
        supports_config_overrides=_optional_manifest_bool(
            capabilities_payload,
            "supports_config_overrides",
            default=False,
        ),
        supports_backend_cache=_optional_manifest_bool(
            capabilities_payload,
            "supports_backend_cache",
            default=True,
        ),
        supports_output_schema=_optional_manifest_bool(
            capabilities_payload,
            "supports_output_schema",
            default=False,
        ),
        supports_output_file=_optional_manifest_bool(
            capabilities_payload,
            "supports_output_file",
            default=False,
        ),
        supports_stdout_json=_optional_manifest_bool(
            capabilities_payload,
            "supports_stdout_json",
            default=False,
        ),
        supports_tool_free_prompting=_optional_manifest_bool(
            capabilities_payload,
            "supports_tool_free_prompting",
            default=True,
        ),
    )
    timeout = payload.get("default_timeout_seconds")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))):
        raise ValueError("Provider manifest field 'default_timeout_seconds' must be numeric or null")
    max_attempts = payload.get("default_max_attempts")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("Provider manifest field 'default_max_attempts' must be a positive integer")

    return AgentProviderSpec(
        name=_require_manifest_string(payload, "name"),
        protocol=_require_manifest_string(payload, "protocol"),
        default_executable=_require_manifest_string(payload, "default_executable"),
        default_timeout_seconds=float(timeout) if timeout is not None else None,
        default_max_attempts=max_attempts,
        default_fallback_to_uncertain_on_error=_require_manifest_bool(
            payload,
            "default_fallback_to_uncertain_on_error",
        ),
        capabilities=capabilities,
    )


def load_agent_provider_spec_manifest_file(path: str | Path) -> AgentProviderSpec:
    """Load and validate a provider spec from a JSON manifest file."""

    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid provider manifest JSON: {manifest_path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Provider manifest must contain an object: {manifest_path}")
    return load_agent_provider_spec_manifest(payload)


def get_builtin_agent_provider_manifest(name: str) -> dict[str, object]:
    """Return the built-in manifest payload for a provider name."""

    normalized = name.strip().lower()
    if normalized not in BUILTIN_AGENT_PROVIDER_MANIFESTS:
        raise ValueError(f"Unknown built-in provider manifest: {name}")
    return BUILTIN_AGENT_PROVIDER_MANIFESTS[normalized]


def get_builtin_agent_provider_spec(name: str) -> AgentProviderSpec:
    """Return the built-in provider spec loaded from its manifest payload."""

    return load_agent_provider_spec_manifest(get_builtin_agent_provider_manifest(name))


def _require_manifest_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Provider manifest field {key!r} must be a non-empty string")
    return value


def _require_manifest_bool(payload: dict[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Provider manifest field {key!r} must be a boolean")
    return value


def _optional_manifest_bool(payload: dict[str, object], key: str, *, default: bool) -> bool:
    value = payload.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"Provider manifest field {key!r} must be a boolean when present")
    return value


CODEX_PROVIDER_SPEC = get_builtin_agent_provider_spec("codex")
CLAUDE_PROVIDER_SPEC = get_builtin_agent_provider_spec("claude")
GEMINI_PROVIDER_SPEC = get_builtin_agent_provider_spec("gemini")
CODEAGENT_PROVIDER_SPEC = get_builtin_agent_provider_spec("codeagent")


BUILTIN_AGENT_PROVIDER_SPECS: dict[str, AgentProviderSpec] = {
    CODEX_PROVIDER_SPEC.name: CODEX_PROVIDER_SPEC,
    CLAUDE_PROVIDER_SPEC.name: CLAUDE_PROVIDER_SPEC,
    GEMINI_PROVIDER_SPEC.name: GEMINI_PROVIDER_SPEC,
    CODEAGENT_PROVIDER_SPEC.name: CODEAGENT_PROVIDER_SPEC,
}
