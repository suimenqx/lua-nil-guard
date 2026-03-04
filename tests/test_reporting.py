from __future__ import annotations

import json

from lua_nil_review_agent.models import (
    AutofixPatch,
    ConfidencePolicy,
    FunctionContract,
    ImprovementAnalytics,
    ImprovementProposal,
    VerificationSummary,
    Verdict,
)
from lua_nil_review_agent.reporting import (
    render_improvement_analytics_json,
    render_improvement_analytics_markdown,
    render_improvement_proposals_json,
    render_improvement_proposals_markdown,
    render_json_report,
    render_markdown_report,
)


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


def test_render_json_report_outputs_machine_readable_findings() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )
    risky = Verdict(
        case_id="case_201",
        status="risky_verified",
        confidence="high",
        risk_path=("username <- req.params.username",),
        safety_evidence=(),
        counterarguments_considered=("No normalizer found",),
        suggested_fix="local safe_name = username or ''",
        needs_human=False,
        autofix_patch=AutofixPatch(
            case_id="case_201",
            file="demo.lua",
            action="insert_before",
            start_line=8,
            end_line=8,
            replacement="username = username or ''",
        ),
        verification_summary=VerificationSummary(
            mode="risk_no_guard",
            evidence=("username <- req.params.username",),
        ),
    )

    payload = json.loads(render_json_report((risky,), policy))

    assert payload[0]["case_id"] == "case_201"
    assert payload[0]["status"] == "risky_verified"
    assert payload[0]["autofix_patch"]["action"] == "insert_before"
    assert payload[0]["autofix_patch"]["start_line"] == 8
    assert payload[0]["verification_summary"]["mode"] == "risk_no_guard"


def test_render_markdown_report_lists_verified_suppressions() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )
    safe = Verdict(
        case_id="case_250",
        status="safe_verified",
        confidence="high",
        risk_path=(),
        safety_evidence=("if username then",),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
        verification_summary=VerificationSummary(
            mode="structured_static_proof",
            strongest_proof_kind="direct_guard",
            strongest_proof_depth=0,
            strongest_proof_summary="if username then",
            verification_score=100,
            evidence=("if username then",),
        ),
    )

    report = render_markdown_report((safe,), policy)

    assert "No reportable findings." in report
    assert "## Verified Suppressions" in report
    assert "case_250: safe_verified (high)" in report
    assert "direct_guard depth=0" in report
    assert "score=100" in report


def test_render_markdown_report_formats_multiline_fix_as_code_block() -> None:
    policy = ConfidencePolicy(
        levels=("low", "medium", "high"),
        default_report_min_confidence="high",
        default_include_medium_in_audit=True,
    )
    risky = Verdict(
        case_id="case_301",
        status="risky_verified",
        confidence="high",
        risk_path=("items <- req.items",),
        safety_evidence=(),
        counterarguments_considered=("No guard found",),
        suggested_fix="local items = req.items or {}\nfor _, item in pairs(items) do",
        needs_human=False,
    )

    report = render_markdown_report((risky,), policy)

    assert "```lua" in report
    assert "local items = req.items or {}" in report
    assert "for _, item in pairs(items) do" in report


def test_render_improvement_proposals_outputs_machine_and_markdown_views() -> None:
    proposals = (
        ImprovementProposal(
            kind="function_contract",
            case_id="case_900",
            file="src/demo.lua",
            status="uncertain",
            confidence="medium",
            reason="normalize_name participates in unresolved call chain",
            suggested_contract=FunctionContract(
                qualified_name="normalize_name",
                returns_non_nil=True,
            ),
            evidence=("normalize_name(req.params.username)",),
        ),
    )

    markdown = render_improvement_proposals_markdown(proposals)
    payload = json.loads(render_improvement_proposals_json(proposals))

    assert "# Lua Nil Review Improvement Proposals" in markdown
    assert "case_900 [function_contract]" in markdown
    assert "suggested_contract: normalize_name" in markdown
    assert payload[0]["suggested_contract"] == "normalize_name"


def test_render_improvement_analytics_outputs_machine_and_markdown_views() -> None:
    analytics = ImprovementAnalytics(
        total_proposals=3,
        unique_cases=2,
        by_kind=(("ast_pattern", 2), ("function_contract", 1)),
        by_reason=(("no_bounded_ast_proof", 2), ("normalize_name", 1)),
        by_pattern=(("no_bounded_ast_proof", 2),),
        by_contract=(("normalize_name", 1),),
    )

    markdown = render_improvement_analytics_markdown(analytics)
    payload = json.loads(render_improvement_analytics_json(analytics))

    assert "# Lua Nil Review Improvement Analytics" in markdown
    assert "ast_pattern: 2" in markdown
    assert payload["total_proposals"] == 3
    assert payload["by_contract"][0]["key"] == "normalize_name"
