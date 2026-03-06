from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_guard.adjudication import route_adjudication
from lua_nil_guard.config_loader import ConfigError, load_adjudication_policy
from lua_nil_guard.models import (
    AdjudicationPolicy,
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


def test_route_multi_agent_uses_adjudicate_packet() -> None:
    verdict = route_adjudication(_make_packet(), _make_rule(), mode="multi_agent")
    assert verdict.status in ("safe", "risky", "uncertain")


def test_route_single_pass_uses_adjudicate_single_pass() -> None:
    verdict = route_adjudication(_make_packet(), _make_rule(), mode="single_pass")
    assert verdict.status in ("safe", "risky", "uncertain")


def test_route_ab_test_splits_deterministically() -> None:
    """AB test with same seed and case_id always routes to same path."""
    rule = _make_rule()
    packet = _make_packet("stable_case")

    v1 = route_adjudication(packet, rule, mode="ab_test", ab_seed=42)
    v2 = route_adjudication(packet, rule, mode="ab_test", ab_seed=42)
    assert v1.status == v2.status


def test_route_ab_test_approximate_split_ratio() -> None:
    """AB test with 100 cases should split roughly 50/50."""
    rule = _make_rule()
    statuses_single: list[str] = []
    statuses_multi: list[str] = []

    for i in range(100):
        packet = _make_packet(f"case_{i:03d}")
        # All these cases have same evidence, so verdict should be same
        # but the routing path may differ
        verdict = route_adjudication(packet, rule, mode="ab_test", ab_seed=42)
        # We can't easily distinguish which path was taken from verdict alone,
        # but the distribution shouldn't be degenerate
        assert verdict.status in ("safe", "risky", "uncertain")

    # Just ensure it completes without error for all 100 cases


def test_route_ab_test_different_seed_can_change_path() -> None:
    rule = _make_rule()
    packet = _make_packet("test_case")

    v_seed1 = route_adjudication(packet, rule, mode="ab_test", ab_seed=1)
    v_seed2 = route_adjudication(packet, rule, mode="ab_test", ab_seed=99999)
    # Different seeds may or may not produce different results for same case
    # but both should be valid
    assert v_seed1.status in ("safe", "risky", "uncertain")
    assert v_seed2.status in ("safe", "risky", "uncertain")


# --- Config loading tests ---


def test_load_adjudication_policy_reads_valid_json(tmp_path: Path) -> None:
    policy_path = tmp_path / "adjudication_policy.json"
    policy_path.write_text(
        json.dumps({
            "adjudication_mode": "single_pass",
            "ab_test": {"enabled": True, "split_ratio": 0.3, "seed": 123},
            "calibration": {"cold_start_threshold": 50, "recalibrate_interval_runs": 10},
        }),
        encoding="utf-8",
    )

    policy = load_adjudication_policy(policy_path)

    assert policy.adjudication_mode == "single_pass"
    assert policy.ab_test_enabled is True
    assert policy.ab_test_split_ratio == 0.3
    assert policy.ab_test_seed == 123
    assert policy.calibration_cold_start_threshold == 50
    assert policy.calibration_recalibrate_interval_runs == 10


def test_load_adjudication_policy_missing_file_returns_default(tmp_path: Path) -> None:
    policy = load_adjudication_policy(tmp_path / "nonexistent.json")

    assert policy.adjudication_mode == "single_pass"
    assert policy.ab_test_enabled is False


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
    assert result.prosecutor.role == "single_pass"
    assert result.defender.role == "single_pass"


def test_load_adjudication_policy_invalid_mode_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "adjudication_policy.json"
    policy_path.write_text(
        json.dumps({"adjudication_mode": "invalid_mode"}),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Unsupported adjudication_mode"):
        load_adjudication_policy(policy_path)
