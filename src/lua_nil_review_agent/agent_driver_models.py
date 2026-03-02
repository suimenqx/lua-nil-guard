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
