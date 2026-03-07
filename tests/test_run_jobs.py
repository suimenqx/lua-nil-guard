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
    assert status.ast_exact_cases == 0
    assert status.lexical_fallback_cases == 2
    assert status.static_unknown_cases == 1
    assert status.llm_enqueued_cases == 1
    assert status.llm_processed_cases == 1
    assert status.llm_second_hop_cases == 0
    assert status.safe_verified_cases == 1
    assert status.risky_verified_cases == 1
    assert status.unknown_reason_distribution == (("no_bounded_ast_proof", 1),)
    assert backend.calls == 1
    assert len(verdicts) == 2

    loaded = repository_review_run_status(
        tmp_path,
        run_db_path=run_db,
        run_id=status.run_id,
    )
    assert loaded.run_id == status.run_id
    assert loaded.completed_cases == 2
    assert loaded.unknown_reason_distribution == (("no_bounded_ast_proof", 1),)

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


def test_run_repository_review_job_tracks_second_hop_metrics(tmp_path: Path) -> None:
    _write_review_config(tmp_path)
    (tmp_path / "lib").mkdir()
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local function parse_user()",
                "  local username = normalize_name(req.params.username)",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "normalizer.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return coerce_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "coerce.lua").write_text(
        "\n".join(
            [
                "function coerce_name(value)",
                "  return ensure_name(value)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "ensure.lua").write_text(
        "\n".join(
            [
                "function ensure_name(value)",
                "  value = value or ''",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    snapshot = bootstrap_repository(tmp_path)
    run_db = tmp_path / "runs.sqlite3"

    class ExpansionAwareBackend:
        supports_expanded_evidence_retry = True

        def __init__(self) -> None:
            self.calls = 0

        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            self.calls += 1
            if any("ensure_name @ " in context for context in packet.related_function_contexts):
                return AdjudicationRecord(
                    prosecutor=RoleOpinion(
                        role="prosecutor",
                        status="uncertain",
                        confidence="low",
                        risk_path=(),
                        safety_evidence=(),
                        missing_evidence=("second hop context resolved sanitizer",),
                        recommended_next_action="suppress",
                        suggested_fix=None,
                    ),
                    defender=RoleOpinion(
                        role="defender",
                        status="safe",
                        confidence="medium",
                        risk_path=(),
                        safety_evidence=("ensure_name returns fallback",),
                        missing_evidence=(),
                        recommended_next_action="suppress",
                        suggested_fix=None,
                    ),
                    judge=Verdict(
                        case_id=packet.case_id,
                        status="safe",
                        confidence="medium",
                        risk_path=(),
                        safety_evidence=("ensure_name returns fallback",),
                        counterarguments_considered=(),
                        suggested_fix=None,
                        needs_human=False,
                    ),
                )
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("need deeper helper context",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("first hop inconclusive",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="uncertain",
                    confidence="medium",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=("first hop inconclusive",),
                    suggested_fix=None,
                    needs_human=True,
                ),
            )

    backend = ExpansionAwareBackend()
    status, _verdicts = run_repository_review_job(
        snapshot,
        backend=backend,
        run_db_path=run_db,
    )

    assert backend.calls == 2
    assert status.llm_enqueued_cases == 1
    assert status.llm_processed_cases == 1
    assert status.llm_second_hop_cases == 1

    loaded = repository_review_run_status(tmp_path, run_db_path=run_db, run_id=status.run_id)
    assert loaded.llm_second_hop_cases == 1
