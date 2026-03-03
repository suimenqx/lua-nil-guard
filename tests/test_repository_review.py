from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.service import bootstrap_repository, run_repository_review


def test_run_repository_review_produces_verified_risk_for_locally_proven_nil_sink(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky_verified"
    assert verdicts[0].confidence == "high"


def test_run_repository_review_uses_function_contracts_to_suppress_false_positive(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "notes": "normalizes nil usernames",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
                "",
                "local username = normalize_name(req.params.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "safe"
    assert any("returns non-nil" in fact for fact in verdicts[0].safety_evidence)


def test_run_repository_review_uses_guard_contract_to_suppress_member_access_false_positive(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "member_access.receiver",
                    "kind": "receiver",
                    "qualified_name": "member_access",
                    "arg_index": 0,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["assert(x)", "if x then ... end"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_profile",
                    "returns_non_nil": False,
                    "ensures_non_nil_args": [1],
                    "notes": "raises if profile is nil",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local profile = req.profile",
                "assert_profile(profile)",
                "return profile.name",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    profile_verdicts = [verdict for verdict in verdicts if verdict.case_id.endswith(":member_access.receiver")]
    assert any(verdict.status.startswith("safe") for verdict in profile_verdicts)


def test_run_repository_review_uses_return_normalizer_contract_to_suppress_false_positive(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args": [1],
                    "notes": "returns a defaulted non-nil username",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = normalize_name(req.params.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("safe")
    assert "normalize_name(...) returns non-nil" in verdicts[0].safety_evidence


def test_run_repository_review_limits_contracts_to_configured_modules(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_in_modules": ["user.profile"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "user.lua").write_text(
        "\n".join(
            [
                "module(\"user.profile\", package.seeall)",
                "function parse_user(req)",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "admin.lua").write_text(
        "\n".join(
            [
                "module(\"admin.profile\", package.seeall)",
                "function parse_admin(req)",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "helpers.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)
    verdict_by_file = {
        Path(verdict.case_id.split(":", 1)[0]).name: verdict
        for verdict in verdicts
    }

    assert verdict_by_file["user.lua"].status.startswith("safe")
    assert verdict_by_file["admin.lua"].status == "uncertain"
