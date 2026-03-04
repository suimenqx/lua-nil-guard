from __future__ import annotations

import json

from .models import (
    AutofixPatch,
    ConfidencePolicy,
    ImprovementAnalytics,
    ImprovementProposal,
    VerificationSummary,
    Verdict,
)
from .pipeline import should_report


def render_markdown_report(
    verdicts: tuple[Verdict, ...],
    policy: ConfidencePolicy,
    *,
    audit_mode: bool = False,
) -> str:
    """Render a sparse markdown report from reportable verdicts only."""

    lines = ["# Lua Nil Risk Report", ""]
    reportable = [v for v in verdicts if should_report(v, policy, audit_mode=audit_mode)]
    verified_suppressions = [
        verdict
        for verdict in verdicts
        if verdict.status in {"safe", "safe_verified"}
        and verdict.verification_summary is not None
        and not _is_macro_only_verified_suppression(verdict)
        and not should_report(verdict, policy, audit_mode=audit_mode)
    ]

    if not reportable and not verified_suppressions:
        lines.append("No reportable findings.")
        return "\n".join(lines)

    if reportable:
        for verdict in reportable:
            lines.extend(
                [
                    f"## {verdict.case_id}",
                    f"- status: {verdict.status}",
                    f"- confidence: {verdict.confidence}",
                    f"- risk_path: {'; '.join(verdict.risk_path) if verdict.risk_path else '(none)'}",
                    f"- counterarguments_considered: {'; '.join(verdict.counterarguments_considered) if verdict.counterarguments_considered else '(none)'}",
                ]
            )
            _append_verification_summary(lines, verdict.verification_summary)
            _append_suggested_fix(lines, verdict.suggested_fix)
            lines.append("")
    else:
        lines.extend(["No reportable findings.", ""])

    if verified_suppressions:
        lines.extend(
            [
                "## Verified Suppressions",
            ]
        )
        for verdict in verified_suppressions:
            lines.append(
                f"- {verdict.case_id}: {verdict.status} ({verdict.confidence}) via {_format_verification_summary(verdict.verification_summary)}"
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def render_json_report(
    verdicts: tuple[Verdict, ...],
    policy: ConfidencePolicy,
    *,
    audit_mode: bool = False,
) -> str:
    """Render reportable findings as a JSON array."""

    payload = [
        {
            "case_id": verdict.case_id,
            "status": verdict.status,
            "confidence": verdict.confidence,
            "risk_path": list(verdict.risk_path),
            "safety_evidence": list(verdict.safety_evidence),
            "counterarguments_considered": list(verdict.counterarguments_considered),
            "suggested_fix": verdict.suggested_fix,
            "needs_human": verdict.needs_human,
            "autofix_patch": _serialize_autofix_patch(verdict.autofix_patch),
            "verification_summary": _serialize_verification_summary(verdict.verification_summary),
        }
        for verdict in verdicts
        if should_report(verdict, policy, audit_mode=audit_mode)
    ]
    return json.dumps(payload, indent=2, sort_keys=True)


def render_improvement_proposals_markdown(
    proposals: tuple[ImprovementProposal, ...],
) -> str:
    """Render draft-only improvement proposals as markdown."""

    lines = ["# Lua Nil Review Improvement Proposals", ""]
    if not proposals:
        lines.append("No draft improvement proposals.")
        return "\n".join(lines)

    for proposal in proposals:
        lines.extend(
            [
                f"## {proposal.case_id} [{proposal.kind}]",
                f"- file: {proposal.file}",
                f"- status: {proposal.status}",
                f"- confidence: {proposal.confidence}",
                f"- reason: {proposal.reason}",
                f"- evidence: {'; '.join(proposal.evidence) if proposal.evidence else '(none)'}",
            ]
        )
        if proposal.suggested_pattern:
            lines.append(f"- suggested_pattern: {proposal.suggested_pattern}")
        if proposal.suggested_contract is not None:
            lines.append(f"- suggested_contract: {proposal.suggested_contract.qualified_name}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_improvement_proposals_json(
    proposals: tuple[ImprovementProposal, ...],
) -> str:
    """Render draft-only improvement proposals as a JSON array."""

    payload = [
        {
            "kind": proposal.kind,
            "case_id": proposal.case_id,
            "file": proposal.file,
            "status": proposal.status,
            "confidence": proposal.confidence,
            "reason": proposal.reason,
            "suggested_pattern": proposal.suggested_pattern,
            "suggested_contract": (
                proposal.suggested_contract.qualified_name
                if proposal.suggested_contract is not None
                else None
            ),
            "evidence": list(proposal.evidence),
        }
        for proposal in proposals
    ]
    return json.dumps(payload, indent=2, sort_keys=True)


def render_improvement_analytics_markdown(
    analytics: ImprovementAnalytics,
) -> str:
    """Render aggregate improvement analytics as markdown."""

    lines = [
        "# Lua Nil Review Improvement Analytics",
        "",
        f"- total_proposals: {analytics.total_proposals}",
        f"- unique_cases: {analytics.unique_cases}",
        f"- unresolved_proposals: {analytics.unresolved_proposals}",
        f"- medium_reportable_proposals: {analytics.medium_reportable_proposals}",
        "",
        "## By Kind",
    ]
    lines.extend(_render_counter_lines(analytics.by_kind))
    lines.extend(["", "## Unresolved By Kind"])
    lines.extend(_render_counter_lines(analytics.unresolved_by_kind))
    lines.extend(["", "## Medium Reportable By Kind"])
    lines.extend(_render_counter_lines(analytics.medium_reportable_by_kind))
    lines.extend(["", "## Top Reasons"])
    lines.extend(_render_counter_lines(analytics.by_reason))
    lines.extend(["", "## Top Patterns"])
    lines.extend(_render_counter_lines(analytics.by_pattern))
    lines.extend(["", "## Top Contracts"])
    lines.extend(_render_counter_lines(analytics.by_contract))
    return "\n".join(lines).rstrip()


def render_improvement_analytics_json(
    analytics: ImprovementAnalytics,
) -> str:
    """Render aggregate improvement analytics as JSON."""

    payload = {
        "total_proposals": analytics.total_proposals,
        "unique_cases": analytics.unique_cases,
        "unresolved_proposals": analytics.unresolved_proposals,
        "medium_reportable_proposals": analytics.medium_reportable_proposals,
        "by_kind": [{"key": key, "count": count} for key, count in analytics.by_kind],
        "unresolved_by_kind": [
            {"key": key, "count": count} for key, count in analytics.unresolved_by_kind
        ],
        "medium_reportable_by_kind": [
            {"key": key, "count": count} for key, count in analytics.medium_reportable_by_kind
        ],
        "by_reason": [{"key": key, "count": count} for key, count in analytics.by_reason],
        "by_pattern": [{"key": key, "count": count} for key, count in analytics.by_pattern],
        "by_contract": [{"key": key, "count": count} for key, count in analytics.by_contract],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _serialize_autofix_patch(patch: AutofixPatch | None) -> dict[str, object] | None:
    if patch is None:
        return None
    return {
        "case_id": patch.case_id,
        "file": patch.file,
        "action": patch.action,
        "start_line": patch.start_line,
        "end_line": patch.end_line,
        "replacement": patch.replacement,
        "expected_original": patch.expected_original,
    }


def _serialize_verification_summary(
    summary: VerificationSummary | None,
) -> dict[str, object] | None:
    if summary is None:
        return None
    return {
        "mode": summary.mode,
        "strongest_proof_kind": summary.strongest_proof_kind,
        "strongest_proof_depth": summary.strongest_proof_depth,
        "strongest_proof_summary": summary.strongest_proof_summary,
        "verification_score": summary.verification_score,
        "evidence": list(summary.evidence),
    }


def _append_suggested_fix(lines: list[str], suggested_fix: str | None) -> None:
    if not suggested_fix:
        lines.append("- suggested_fix: (none)")
        return
    if "\n" not in suggested_fix:
        lines.append(f"- suggested_fix: {suggested_fix}")
        return

    lines.extend(
        [
            "- suggested_fix:",
            "```lua",
            suggested_fix,
            "```",
        ]
    )


def _append_verification_summary(
    lines: list[str],
    summary: VerificationSummary | None,
) -> None:
    if summary is None:
        return
    lines.append(f"- verification: {_format_verification_summary(summary)}")


def _format_verification_summary(summary: VerificationSummary | None) -> str:
    if summary is None:
        return "(none)"

    details: list[str] = [summary.mode]
    if summary.strongest_proof_kind is not None:
        proof_detail = summary.strongest_proof_kind
        if summary.strongest_proof_depth is not None:
            proof_detail = f"{proof_detail} depth={summary.strongest_proof_depth}"
        details.append(proof_detail)
    if summary.verification_score is not None:
        details.append(f"score={summary.verification_score}")
    if summary.strongest_proof_summary:
        details.append(summary.strongest_proof_summary)
    return " | ".join(details)


def _render_counter_lines(entries: tuple[tuple[str, int], ...]) -> list[str]:
    if not entries:
        return ["- (none)"]
    return [f"- {key}: {count}" for key, count in entries]


def _is_macro_only_verified_suppression(verdict: Verdict) -> bool:
    summary = verdict.verification_summary
    if summary is None:
        return False
    return summary.strongest_proof_kind == "macro_fact_guard"
