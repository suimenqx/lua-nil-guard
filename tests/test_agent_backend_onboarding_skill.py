from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from lua_nil_review_agent.agent_driver_manifest import load_agent_provider_spec_manifest


MANIFEST_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "agent-backend-onboarding"
    / "scripts"
    / "generate_provider_manifest.py"
)
CLASSIFY_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "agent-backend-onboarding"
    / "scripts"
    / "classify_provider_fit.py"
)


def test_generate_provider_manifest_script_emits_valid_manifest() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT_PATH),
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
            str(MANIFEST_SCRIPT_PATH),
            "Bad Name",
            "stdout_envelope_cli",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "name must use lowercase letters, digits, and hyphens only" in completed.stderr


def test_classify_provider_fit_reports_direct_fit_for_supported_envelope_shape() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(CLASSIFY_SCRIPT_PATH),
            "sample-agent",
            "--prompt-mode",
            "flag_arg",
            "--output-mode",
            "stdout_envelope",
            "--envelope-field",
            "response",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)

    assert payload["status"] == "direct-fit"
    assert payload["can_directly_integrate"] is True
    assert payload["recommended_protocol"] == "stdout_envelope_cli"
    assert payload["integration_path"] == "manifest-only"


def test_classify_provider_fit_reports_runtime_changes_for_unknown_envelope_field() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(CLASSIFY_SCRIPT_PATH),
            "sample-agent",
            "--prompt-mode",
            "flag_arg",
            "--output-mode",
            "stdout_envelope",
            "--envelope-field",
            "payload",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)

    assert payload["status"] == "needs-runtime-changes"
    assert payload["can_directly_integrate"] is False
    assert payload["recommended_protocol"] is None


def test_classify_provider_fit_reports_insufficient_evidence() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(CLASSIFY_SCRIPT_PATH),
            "sample-agent",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)

    assert payload["status"] == "insufficient-evidence"
    assert payload["can_directly_integrate"] is False
    assert "prompt mode" in payload["missing_evidence"]
    assert "output mode" in payload["missing_evidence"]
