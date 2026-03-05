from __future__ import annotations

import json
from pathlib import Path

from lua_nil_guard.models import AdjudicationRecord, RoleOpinion, Verdict
from lua_nil_guard.service import (
    bootstrap_repository,
    repository_review_run_verdicts,
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
    assert status.static_unknown_cases == 1
    assert status.llm_enqueued_cases == 1
    assert status.llm_processed_cases == 1
    assert backend.calls == 1
    assert len(verdicts) == 2

    loaded = repository_review_run_status(
        tmp_path,
        run_db_path=run_db,
        run_id=status.run_id,
    )
    assert loaded.run_id == status.run_id
    assert loaded.completed_cases == 2

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

    first_status, _ = run_repository_review_job(snapshot, run_db_path=run_db)
    second_status, _ = run_repository_review_job(snapshot, run_db_path=run_db)

    latest = repository_review_run_status(tmp_path, run_db_path=run_db)
    assert latest.run_id == second_status.run_id
    assert latest.run_id > first_status.run_id
