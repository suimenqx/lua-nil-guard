from __future__ import annotations

from lua_nil_review_agent.models import ConfidencePolicy, Verdict
from lua_nil_review_agent.reporting import render_markdown_report


def test_render_markdown_report_outputs_only_reportable_findings() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )
    risky = Verdict(
        case_id="case_101",
        status="risky",
        confidence="high",
        risk_path=("username <- req.params.username",),
        safety_evidence=(),
        counterarguments_considered=("No normalizer found",),
        suggested_fix="local safe_name = username or ''",
        needs_human=False,
    )
    uncertain = Verdict(
        case_id="case_102",
        status="uncertain",
        confidence="high",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
    )

    report = render_markdown_report((risky, uncertain), policy)

    assert "case_101" in report
    assert "local safe_name = username or ''" in report
    assert "case_102" not in report
