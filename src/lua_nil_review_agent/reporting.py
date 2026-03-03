from __future__ import annotations

import json

from .models import AutofixPatch, ConfidencePolicy, VerificationSummary, Verdict
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
