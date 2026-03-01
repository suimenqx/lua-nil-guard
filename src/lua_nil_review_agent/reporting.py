from __future__ import annotations

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
