from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_review_agent.agent_driver_manifest import (
    BUILTIN_AGENT_PROVIDER_MANIFESTS,
    CODEAGENT_PROVIDER_SPEC,
    CLAUDE_PROVIDER_SPEC,
    CODEX_PROVIDER_SPEC,
    get_builtin_agent_provider_manifest,
    get_builtin_agent_provider_spec,
    load_agent_provider_spec_manifest,
    load_agent_provider_spec_manifest_file,
)


def test_builtin_manifests_load_into_builtin_specs() -> None:
    assert get_builtin_agent_provider_manifest("codex") == BUILTIN_AGENT_PROVIDER_MANIFESTS["codex"]
    assert get_builtin_agent_provider_manifest("claude") == BUILTIN_AGENT_PROVIDER_MANIFESTS["claude"]
    assert get_builtin_agent_provider_manifest("codeagent") == BUILTIN_AGENT_PROVIDER_MANIFESTS["codeagent"]

    assert get_builtin_agent_provider_spec("codex") == CODEX_PROVIDER_SPEC
    assert get_builtin_agent_provider_spec("claude") == CLAUDE_PROVIDER_SPEC
    assert get_builtin_agent_provider_spec("codeagent") == CODEAGENT_PROVIDER_SPEC


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


def test_load_agent_provider_spec_manifest_file_reads_json(tmp_path: Path) -> None:
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(BUILTIN_AGENT_PROVIDER_MANIFESTS["codex"]), encoding="utf-8")

    spec = load_agent_provider_spec_manifest_file(path)

    assert spec == CODEX_PROVIDER_SPEC


def test_load_agent_provider_spec_manifest_file_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "provider.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid provider manifest JSON"):
        load_agent_provider_spec_manifest_file(path)
