from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_guard.agent_backend import HeuristicAdjudicationBackend
from lua_nil_guard.models import AdjudicationRecord, RoleOpinion, Verdict
from lua_nil_guard.service import (
    bootstrap_repository,
    clear_trace_artifacts,
    repository_review_case_replay,
    repository_review_run_verdicts,
    repository_review_run_trace,
    repository_review_run_status,
    run_repository_review_job,
)


class CountingBackend:
    def __init__(self) -> None:
        self.calls = 0

    def adjudicate(self, packet, sink_rule):  # noqa: ANN001
        self.calls += 1
        risk_path = (f"potential nil reaches {sink_rule.qualified_name}",)
        return AdjudicationRecord(
            prosecutor=RoleOpinion(
                role="prosecutor",
                status="risky",
                confidence="medium",
                risk_path=risk_path,
                safety_evidence=(),
                missing_evidence=(),
                recommended_next_action="report",
                suggested_fix=None,
            ),
            defender=RoleOpinion(
                role="defender",
                status="uncertain",
                confidence="low",
                risk_path=(),
                safety_evidence=(),
                missing_evidence=("no explicit guard",),
                recommended_next_action="expand_context",
                suggested_fix=None,
            ),
            judge=Verdict(
                case_id=packet.case_id,
                status="risky",
                confidence="medium",
                risk_path=risk_path,
                safety_evidence=(),
                counterarguments_considered=("no explicit guard",),
                suggested_fix=None,
                needs_human=False,
            ),
        )


def _write_review_config(root: Path) -> None:
    (root / "config").mkdir()
    (root / "src").mkdir()
    (root / "config" / "sink_rules.json").write_text(
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
    (root / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )


def _write_trace_policy(root: Path, *, default_trace_level: str) -> None:
    (root / "config" / "trace_policy.json").write_text(
        json.dumps(
            {
                "default_trace_level": default_trace_level,
                "max_inline_payload_bytes": 65536,
                "redact_patterns": [],
            }
        ),
        encoding="utf-8",
    )


def test_run_repository_review_job_routes_only_unknown_cases_to_backend(tmp_path: Path) -> None:
    _write_review_config(tmp_path)
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "if username then",
                "  local safe = string.match(username, '^a')",
                "end",
                "local raw = req.params.raw",
                "local maybe = string.match(raw, '^b')",
            ]
        ),
        encoding="utf-8",
    )
    snapshot = bootstrap_repository(tmp_path)
    run_db = tmp_path / "runs.sqlite3"

    backend = CountingBackend()
    status, verdicts = run_repository_review_job(
        snapshot,
        backend=backend,
        run_db_path=run_db,
    )

    assert status.status == "completed"
    assert status.total_cases == 2
    assert status.completed_cases == 2
    assert status.ast_exact_cases == 2
    assert status.lexical_fallback_cases == 0
    assert status.ast_lite_cases == 2
    assert status.static_unknown_cases == 2
    assert status.llm_enqueued_cases == 2
    assert status.llm_processed_cases == 2
    assert status.llm_second_hop_cases == 0
    assert status.safe_verified_cases == 0
    assert status.risky_verified_cases == 0
    assert status.unknown_reason_distribution == ()
    assert backend.calls == 2
    assert len(verdicts) == 2

    loaded = repository_review_run_status(
        tmp_path,
        run_db_path=run_db,
        run_id=status.run_id,
    )
    assert loaded.run_id == status.run_id
    assert loaded.completed_cases == 2
    assert loaded.unknown_reason_distribution == ()
    assert loaded.analysis_mode_distribution
    assert loaded.origin_analysis_mode_distribution

    backend_resume = CountingBackend()
    resumed_status, resumed_verdicts = run_repository_review_job(
        snapshot,
        backend=backend_resume,
        run_db_path=run_db,
        run_id=status.run_id,
    )

    assert resumed_status.run_id == status.run_id
    assert resumed_status.status == "completed"
    assert backend_resume.calls == 0
    assert len(resumed_verdicts) == 2

    loaded_status, loaded_verdicts = repository_review_run_verdicts(
        tmp_path,
        run_db_path=run_db,
        run_id=status.run_id,
    )
    assert loaded_status.run_id == status.run_id
    assert tuple(verdict.case_id for verdict in loaded_verdicts) == tuple(
        verdict.case_id for verdict in verdicts
    )


def test_repository_review_run_status_defaults_to_latest_run(tmp_path: Path) -> None:
    _write_review_config(tmp_path)
    (tmp_path / "src" / "demo.lua").write_text(
        "local raw = req.params.raw\nlocal maybe = string.match(raw, '^b')\n",
        encoding="utf-8",
    )
    snapshot = bootstrap_repository(tmp_path)
    run_db = tmp_path / "runs.sqlite3"

    first_status, _ = run_repository_review_job(snapshot, backend=HeuristicAdjudicationBackend(), run_db_path=run_db)
    second_status, _ = run_repository_review_job(snapshot, backend=HeuristicAdjudicationBackend(), run_db_path=run_db)

    latest = repository_review_run_status(tmp_path, run_db_path=run_db)
    assert latest.run_id == second_status.run_id
    assert latest.run_id > first_status.run_id


def test_repository_review_trace_and_case_replay_api(tmp_path: Path) -> None:
    _write_review_config(tmp_path)
    (tmp_path / "src" / "demo.lua").write_text(
        "local raw = req.params.raw\nlocal maybe = string.match(raw, '^b')\n",
        encoding="utf-8",
    )
    snapshot = bootstrap_repository(tmp_path)
    run_db = tmp_path / "runs.sqlite3"

    status, verdicts = run_repository_review_job(snapshot, backend=CountingBackend(), run_db_path=run_db)
    assert len(verdicts) == 1

    loaded_status, events = repository_review_run_trace(
        tmp_path,
        run_db_path=run_db,
        run_id=status.run_id,
    )
    assert loaded_status.run_id == status.run_id
    assert events == ()

    replay_status, replay_payload = repository_review_case_replay(
        tmp_path,
        run_db_path=run_db,
        run_id=status.run_id,
        case_id=verdicts[0].case_id,
    )
    assert replay_status.run_id == status.run_id
    assert replay_payload["case_id"] == verdicts[0].case_id
    assert replay_payload["events"] == []
    assert replay_payload["final_verdict"]["case_id"] == verdicts[0].case_id
    assert replay_payload["evidence_packet"]["case_id"] == verdicts[0].case_id
    assert replay_payload["decision_trace"]["verdict"] == replay_payload["final_verdict"]["status"]
    assert replay_payload["decision_trace"]["confidence"] == replay_payload["final_verdict"]["confidence"]
    assert isinstance(replay_payload["decision_trace"]["evidence_refs"], list)
    assert replay_payload["decision_trace"]["evidence_refs"]

    removed = clear_trace_artifacts(tmp_path, run_id=status.run_id)
    assert removed == 0


def test_run_repository_review_job_rejects_forensic_trace_policy_default(tmp_path: Path) -> None:
    _write_review_config(tmp_path)
    _write_trace_policy(tmp_path, default_trace_level="forensic")
    (tmp_path / "src" / "demo.lua").write_text(
        "local raw = req.params.raw\nlocal maybe = string.match(raw, '^b')\n",
        encoding="utf-8",
    )
    snapshot = bootstrap_repository(tmp_path)
    run_db = tmp_path / "runs.sqlite3"

    with pytest.raises(ValueError, match="default_trace_level cannot be 'forensic'"):
        run_repository_review_job(snapshot, backend=CountingBackend(), run_db_path=run_db)

    status, _ = run_repository_review_job(
        snapshot,
        backend=CountingBackend(),
        run_db_path=run_db,
        trace_level="forensic",
    )
    assert status.trace_level == "forensic"
