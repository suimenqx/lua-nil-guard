from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.models import AdjudicationRecord, RoleOpinion, SinkRule, Verdict
from lua_nil_review_agent.service import bootstrap_repository, run_repository_review


class StubBackend:
    def adjudicate(self, packet, sink_rule):  # noqa: ANN001
        return AdjudicationRecord(
            prosecutor=RoleOpinion(
                role="prosecutor",
                status="risky",
                confidence="high",
                risk_path=("stub path",),
                safety_evidence=(),
                missing_evidence=(),
                recommended_next_action="report",
                suggested_fix="local safe = value or ''",
            ),
            defender=RoleOpinion(
                role="defender",
                status="uncertain",
                confidence="low",
                risk_path=(),
                safety_evidence=(),
                missing_evidence=("stubbed",),
                recommended_next_action="expand_context",
                suggested_fix=None,
            ),
            judge=Verdict(
                case_id=packet.case_id,
                status="risky",
                confidence="high",
                risk_path=("stub path",),
                safety_evidence=(),
                counterarguments_considered=("stubbed",),
                suggested_fix="local safe = value or ''",
                needs_human=False,
            ),
        )


def test_run_repository_review_accepts_custom_backend(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot, backend=StubBackend())

    assert len(verdicts) == 1
    assert verdicts[0].risk_path == ("stub path",)
    assert verdicts[0].confidence == "high"
