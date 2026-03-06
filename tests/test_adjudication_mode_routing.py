from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_guard.adjudication import route_adjudication
from lua_nil_guard.config_loader import ConfigError, load_adjudication_policy
from lua_nil_guard.models import (
    EvidencePacket,
    EvidenceTarget,
    SinkRule,
)


def _make_rule() -> SinkRule:
    return SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("if x then ... end",),
    )


def _make_packet(case_id: str = "case_001") -> EvidencePacket:
    return EvidencePacket(
        case_id=case_id,
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=8,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="local username = req.params.username\nreturn string.match(username, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
    )


def test_route_single_pass_uses_adjudicate_single_pass() -> None:
    verdict = route_adjudication(_make_packet(), _make_rule(), mode="single_pass")
    assert verdict.status in ("safe", "risky", "uncertain")


@pytest.mark.parametrize("mode", ["legacy_mode", "legacy_split"])
def test_route_rejects_legacy_modes(mode: str) -> None:
    with pytest.raises(ValueError, match="single_pass"):
        route_adjudication(_make_packet(), _make_rule(), mode=mode, ab_seed=42)


# --- Config loading tests ---


def test_load_adjudication_policy_reads_valid_json(tmp_path: Path) -> None:
    policy_path = tmp_path / "adjudication_policy.json"
    policy_path.write_text(
        json.dumps({
            "adjudication_mode": "single_pass",
            "calibration": {"cold_start_threshold": 50, "recalibrate_interval_runs": 10},
        }),
        encoding="utf-8",
    )

    policy = load_adjudication_policy(policy_path)

    assert policy.adjudication_mode == "single_pass"
    assert policy.calibration_cold_start_threshold == 50
    assert policy.calibration_recalibrate_interval_runs == 10


def test_load_adjudication_policy_missing_file_returns_default(tmp_path: Path) -> None:
    policy = load_adjudication_policy(tmp_path / "nonexistent.json")

    assert policy.adjudication_mode == "single_pass"


def test_load_adjudication_policy_invalid_json_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "adjudication_policy.json"
    policy_path.write_text("not json", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_adjudication_policy(policy_path)


def test_cli_help_includes_adjudication_mode() -> None:
    from lua_nil_guard.cli import run

    exit_code, output = run(["--help"])
    assert exit_code == 0
    assert "adjudication-mode" in output.lower() or "Adjudication mode" in output


def test_cli_parse_review_options_adjudication_mode() -> None:
    """_parse_review_options extracts --adjudication-mode correctly."""
    # Import the private parser for direct testing
    import lua_nil_guard.cli as cli_module

    result = cli_module._parse_review_options(
        ["--adjudication-mode", "single_pass", "/path/to/repo"]
    )
    # adjudication_mode is the last element
    assert result[-1] == "single_pass"
    # positional should have the repo path
    assert result[-2] == ["/path/to/repo"]


def test_cli_parse_review_options_adjudication_mode_invalid() -> None:
    import lua_nil_guard.cli as cli_module

    with pytest.raises(ValueError, match="adjudication-mode"):
        cli_module._parse_review_options(["--adjudication-mode", "bogus", "/path"])


def test_single_pass_heuristic_backend_returns_adjudication_record() -> None:
    from lua_nil_guard.agent_backend import SinglePassHeuristicBackend

    backend = SinglePassHeuristicBackend()
    result = backend.adjudicate(_make_packet(), _make_rule())

    # Must return AdjudicationRecord for protocol compatibility
    from lua_nil_guard.models import AdjudicationRecord

    assert isinstance(result, AdjudicationRecord)
    assert result.judge.status in ("safe", "risky", "uncertain")
    assert result.prosecutor.role in {"prosecutor", "single_pass"}
    assert result.defender.role in {"defender", "single_pass"}


def test_load_adjudication_policy_rejects_unknown_legacy_section(tmp_path: Path) -> None:
    policy_path = tmp_path / "adjudication_policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "adjudication_mode": "single_pass",
                "legacy_split": {"enabled": True},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Unsupported adjudication policy fields"):
        load_adjudication_policy(policy_path)


def test_load_adjudication_policy_invalid_mode_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "adjudication_policy.json"
    policy_path.write_text(
        json.dumps({"adjudication_mode": "invalid_mode"}),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Unsupported adjudication_mode"):
        load_adjudication_policy(policy_path)
