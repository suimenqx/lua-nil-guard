from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from lua_nil_review_agent.agent_driver_manifest import load_agent_provider_spec_manifest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "agent-backend-onboarding"
    / "scripts"
    / "generate_provider_manifest.py"
)


def test_generate_provider_manifest_script_emits_valid_manifest() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "sample-agent",
            "stdout_structured_cli",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    spec = load_agent_provider_spec_manifest(payload)

    assert spec.name == "sample-agent"
    assert spec.protocol == "stdout_structured_cli"
    assert spec.default_executable == "sample-agent"
    assert spec.default_timeout_seconds == 75.0
    assert spec.capabilities.supports_stdout_json is True
    assert spec.capabilities.supports_output_schema is True


def test_generate_provider_manifest_script_rejects_invalid_name() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "Bad Name",
            "stdout_envelope_cli",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "name must use lowercase letters, digits, and hyphens only" in completed.stderr
