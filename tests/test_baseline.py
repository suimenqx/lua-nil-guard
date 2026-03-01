from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.baseline import BaselineStore, build_baseline, filter_new_findings
from lua_nil_review_agent.models import ConfidencePolicy, Verdict


def test_build_baseline_keeps_only_reportable_findings() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )
    verdicts = (
        Verdict(
            case_id="keep_me",
            status="risky_verified",
            confidence="high",
            risk_path=("x",),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        ),
        Verdict(
            case_id="drop_me",
            status="uncertain",
            confidence="high",
            risk_path=(),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        ),
    )

    baseline = build_baseline(verdicts, policy)

    assert baseline == ("keep_me",)


def test_filter_new_findings_excludes_known_baseline_keys(tmp_path: Path) -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )
    store = BaselineStore(tmp_path / "baseline.json")
    store.save(("known_case",))
    verdicts = (
        Verdict(
            case_id="known_case",
            status="risky_verified",
            confidence="high",
            risk_path=("x",),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        ),
        Verdict(
            case_id="new_case",
            status="risky_verified",
            confidence="high",
            risk_path=("y",),
            safety_evidence=(),
            counterarguments_considered=(),
            suggested_fix=None,
            needs_human=False,
        ),
    )

    filtered = filter_new_findings(verdicts, store.load(), policy)

    assert tuple(item.case_id for item in filtered) == ("new_case",)
