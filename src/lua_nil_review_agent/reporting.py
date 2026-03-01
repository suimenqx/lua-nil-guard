from __future__ import annotations

import json

from .models import ConfidencePolicy, Verdict
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
                f"- suggested_fix: {verdict.suggested_fix or '(none)'}",
                "",
            ]
        )

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
        }
        for verdict in verdicts
        if should_report(verdict, policy, audit_mode=audit_mode)
    ]
    return json.dumps(payload, indent=2, sort_keys=True)
