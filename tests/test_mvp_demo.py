from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.reporting import render_json_report
from lua_nil_review_agent.service import (
    bootstrap_repository,
    refresh_knowledge_base,
    run_repository_review,
)


def test_demo_project_mvp_reports_only_the_real_risk_after_knowledge_refresh() -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "demo_project"
    snapshot = bootstrap_repository(project_root)

    facts = refresh_knowledge_base(snapshot)
    verdicts = run_repository_review(snapshot)
    payload = json.loads(render_json_report(verdicts, snapshot.confidence_policy))

    assert len(facts) == 1
    assert facts[0].subject == "normalize_name"
    assert len(payload) == 1
    assert "risky_match.lua" in payload[0]["case_id"]
