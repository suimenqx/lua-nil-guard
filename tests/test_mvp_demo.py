from __future__ import annotations

import json
from pathlib import Path
import shutil

from lua_nil_guard.reporting import render_json_report
from lua_nil_guard.service import (
    bootstrap_repository,
    refresh_knowledge_base,
    run_repository_review,
)


def test_demo_project_mvp_reports_only_the_real_risk_after_knowledge_refresh(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "demo_project"
    runtime_root = tmp_path / "demo_project"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    facts = refresh_knowledge_base(snapshot)
    verdicts = run_repository_review(snapshot)
    payload = json.loads(render_json_report(verdicts, snapshot.confidence_policy))

    assert len(facts) == 1
    assert facts[0].subject == "normalize_name"
    assert len(payload) == 1
    assert payload[0]["status"] == "risky_verified"
    assert "risky_match.lua" in payload[0]["case_id"]
