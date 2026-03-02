from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentCapabilities:
    """Declared capabilities for a provider driver."""

    supports_model_override: bool = False
    supports_config_overrides: bool = False
    supports_backend_cache: bool = True
    supports_output_schema: bool = False
    supports_output_file: bool = False
    supports_stdout_json: bool = False
    supports_tool_free_prompting: bool = True


@dataclass(frozen=True)
class AgentProviderSpec:
    """Declarative defaults and protocol metadata for a provider."""

    name: str
    protocol: str
    default_executable: str
    default_timeout_seconds: float | None
    default_max_attempts: int
    default_fallback_to_uncertain_on_error: bool
    capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)


CODEX_PROVIDER_SPEC = AgentProviderSpec(
    name="codex",
    protocol="schema_file_cli",
    default_executable="codex",
    default_timeout_seconds=45.0,
    default_max_attempts=2,
    default_fallback_to_uncertain_on_error=True,
    capabilities=AgentCapabilities(
        supports_model_override=True,
        supports_config_overrides=True,
        supports_backend_cache=True,
        supports_output_schema=True,
        supports_output_file=True,
        supports_stdout_json=False,
        supports_tool_free_prompting=True,
    ),
)


CODEAGENT_PROVIDER_SPEC = AgentProviderSpec(
    name="codeagent",
    protocol="stdout_envelope_cli",
    default_executable="codeagent",
    default_timeout_seconds=45.0,
    default_max_attempts=2,
    default_fallback_to_uncertain_on_error=True,
    capabilities=AgentCapabilities(
        supports_model_override=True,
        supports_config_overrides=True,
        supports_backend_cache=True,
        supports_output_schema=False,
        supports_output_file=False,
        supports_stdout_json=True,
        supports_tool_free_prompting=True,
    ),
)


BUILTIN_AGENT_PROVIDER_SPECS: dict[str, AgentProviderSpec] = {
    CODEX_PROVIDER_SPEC.name: CODEX_PROVIDER_SPEC,
    CODEAGENT_PROVIDER_SPEC.name: CODEAGENT_PROVIDER_SPEC,
}


def get_builtin_agent_provider_spec(name: str) -> AgentProviderSpec:
    """Return the built-in provider spec for a normalized backend name."""

    normalized = name.strip().lower()
    if normalized not in BUILTIN_AGENT_PROVIDER_SPECS:
        raise ValueError(f"Unknown built-in provider spec: {name}")
    return BUILTIN_AGENT_PROVIDER_SPECS[normalized]
