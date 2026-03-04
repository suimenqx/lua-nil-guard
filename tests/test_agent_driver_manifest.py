from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_guard.agent_driver_manifest import (
    BUILTIN_AGENT_PROVIDER_MANIFESTS,
    CODEAGENT_PROVIDER_SPEC,
    CLAUDE_PROVIDER_SPEC,
    CODEX_PROVIDER_SPEC,
    GEMINI_PROVIDER_SPEC,
    build_agent_provider_manifest_template,
    get_builtin_agent_provider_manifest,
    get_builtin_agent_provider_spec,
    load_agent_provider_spec_manifest,
    load_agent_provider_spec_manifest_file,
)


def test_builtin_manifests_load_into_builtin_specs() -> None:
    assert get_builtin_agent_provider_manifest("codex") == BUILTIN_AGENT_PROVIDER_MANIFESTS["codex"]
    assert get_builtin_agent_provider_manifest("claude") == BUILTIN_AGENT_PROVIDER_MANIFESTS["claude"]
    assert get_builtin_agent_provider_manifest("gemini") == BUILTIN_AGENT_PROVIDER_MANIFESTS["gemini"]
    assert get_builtin_agent_provider_manifest("codeagent") == BUILTIN_AGENT_PROVIDER_MANIFESTS["codeagent"]
    assert BUILTIN_AGENT_PROVIDER_MANIFESTS["gemini"]["capabilities"] == {
        "supports_model_override": True,
        "supports_config_overrides": False,
        "supports_backend_cache": True,
        "supports_output_schema": False,
        "supports_output_file": False,
        "supports_stdout_json": True,
        "supports_tool_free_prompting": True,
    }
    assert BUILTIN_AGENT_PROVIDER_MANIFESTS["codeagent"]["capabilities"] == {
        "supports_model_override": True,
        "supports_config_overrides": False,
        "supports_backend_cache": True,
        "supports_output_schema": False,
        "supports_output_file": False,
        "supports_stdout_json": True,
        "supports_tool_free_prompting": True,
    }

    assert get_builtin_agent_provider_spec("codex") == CODEX_PROVIDER_SPEC
    assert get_builtin_agent_provider_spec("claude") == CLAUDE_PROVIDER_SPEC
    assert get_builtin_agent_provider_spec("gemini") == GEMINI_PROVIDER_SPEC
    assert get_builtin_agent_provider_spec("codeagent") == CODEAGENT_PROVIDER_SPEC
    assert CODEX_PROVIDER_SPEC.default_expanded_evidence_retry_mode == "auto"
    assert CLAUDE_PROVIDER_SPEC.default_expanded_evidence_retry_mode == "auto"
    assert GEMINI_PROVIDER_SPEC.default_expanded_evidence_retry_mode == "auto"
    assert CODEAGENT_PROVIDER_SPEC.default_expanded_evidence_retry_mode == "auto"
    assert GEMINI_PROVIDER_SPEC.default_executable == "gemini"
    assert CODEAGENT_PROVIDER_SPEC.default_executable == "gemini"


def test_load_agent_provider_spec_manifest_validates_required_fields() -> None:
    with pytest.raises(ValueError, match="default_max_attempts"):
        load_agent_provider_spec_manifest(
            {
                "name": "bad",
                "protocol": "stdout_envelope_cli",
                "default_executable": "bad-agent",
                "default_timeout_seconds": 10.0,
                "default_max_attempts": 0,
                "default_fallback_to_uncertain_on_error": True,
            }
        )

    with pytest.raises(ValueError, match="default_expanded_evidence_retry_mode"):
        load_agent_provider_spec_manifest(
            {
                "name": "bad",
                "protocol": "stdout_envelope_cli",
                "default_executable": "bad-agent",
                "default_timeout_seconds": 10.0,
                "default_max_attempts": 1,
                "default_fallback_to_uncertain_on_error": True,
                "default_expanded_evidence_retry_mode": "sometimes",
            }
        )


def test_load_agent_provider_spec_manifest_file_reads_json(tmp_path: Path) -> None:
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(BUILTIN_AGENT_PROVIDER_MANIFESTS["codex"]), encoding="utf-8")

    spec = load_agent_provider_spec_manifest_file(path)

    assert spec == CODEX_PROVIDER_SPEC


def test_load_agent_provider_spec_manifest_defaults_expanded_evidence_retry_mode_to_auto() -> None:
    spec = load_agent_provider_spec_manifest(
        {
            "name": "sample",
            "protocol": "stdout_envelope_cli",
            "default_executable": "sample-agent",
            "default_timeout_seconds": 10.0,
            "default_max_attempts": 1,
            "default_fallback_to_uncertain_on_error": True,
        }
    )

    assert spec.default_expanded_evidence_retry_mode == "auto"


def test_load_agent_provider_spec_manifest_file_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "provider.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid provider manifest JSON"):
        load_agent_provider_spec_manifest_file(path)


def test_build_agent_provider_manifest_template_sets_protocol_defaults() -> None:
    payload = build_agent_provider_manifest_template("sample-agent", "stdout_envelope_cli")

    assert payload["name"] == "sample-agent"
    assert payload["default_executable"] == "sample-agent"
    assert payload["default_expanded_evidence_retry_mode"] == "auto"
    assert payload["default_timeout_seconds"] == 45.0
    assert payload["default_max_attempts"] == 2
    assert payload["capabilities"]["supports_stdout_json"] is True
    assert payload["capabilities"]["supports_output_schema"] is False


def test_build_agent_provider_manifest_template_rejects_unknown_protocol() -> None:
    with pytest.raises(ValueError, match="Unknown provider manifest protocol"):
        build_agent_provider_manifest_template("sample-agent", "sdk_api")
