from __future__ import annotations

import json
from pathlib import Path
import shutil

from lua_nil_guard.reporting import render_json_report
from lua_nil_guard.service import (
    bootstrap_repository,
    refresh_knowledge_base,
    review_repository,
    run_repository_review,
)


def test_semantic_suite_static_scan_covers_multiple_patterns(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "semantic_suite"
    runtime_root = tmp_path / "semantic_suite"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    assessments = review_repository(snapshot)
    by_state = {
        "safe_static": 0,
        "unknown_static": 0,
        "risky_static": 0,
    }
    sink_ids = set()
    for assessment in assessments:
        by_state[assessment.candidate.static_state] += 1
        sink_ids.add(assessment.candidate.sink_rule_id)

    assert len(assessments) == 7
    assert by_state["safe_static"] == 0
    assert by_state["unknown_static"] == 7
    assert by_state["risky_static"] == 0
    assert sink_ids == {"string.match.arg1", "string.find.arg1"}


def test_semantic_suite_reports_only_provable_risks_after_knowledge_refresh(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "semantic_suite"
    runtime_root = tmp_path / "semantic_suite"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    facts = refresh_knowledge_base(snapshot)
    verdicts = run_repository_review(snapshot)
    payload = json.loads(render_json_report(verdicts, snapshot.confidence_policy))
    case_ids = {item["case_id"] for item in payload}

    assert len(facts) == 1
    assert facts[0].subject == "normalize_name"
    assert len(payload) == 7
    assert all(item["status"] == "risky" for item in payload)
    assert any("risky_direct_match.lua" in case_id for case_id in case_ids)
    assert any("risky_find.lua" in case_id for case_id in case_ids)
    assert any("risky_nil_literal.lua" in case_id for case_id in case_ids)
    assert any("safe_if_guard.lua" in case_id for case_id in case_ids)
    assert any("safe_assert_find.lua" in case_id for case_id in case_ids)
    assert any("safe_default_match.lua" in case_id for case_id in case_ids)
    assert any("safe_normalized_match.lua" in case_id for case_id in case_ids)
