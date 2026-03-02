from __future__ import annotations

import json

from .models import AutofixPatch, ConfidencePolicy, Verdict
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

    if not reportable:
        lines.append("No reportable findings.")
        return "\n".join(lines)

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
        _append_suggested_fix(lines, verdict.suggested_fix)
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
