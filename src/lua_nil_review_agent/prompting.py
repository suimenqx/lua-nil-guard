from __future__ import annotations

from pathlib import Path

from .models import EvidencePacket, SinkRule
from .skill_runtime import compile_adjudicator_skill_header


def build_adjudication_prompt(
    *,
    packet: EvidencePacket,
    sink_rule: SinkRule,
    skill_path: str | Path | None = None,
    strict_skill: bool = True,
) -> str:
    """Render a deterministic prompt for strict nil-risk adjudication."""

    return "\n".join(
        [
            compile_adjudicator_skill_header(skill_path, strict=strict_skill),
            "",
            "Target case:",
            f"- case_id: {packet.case_id}",
            f"- file: {packet.target.file}",
            f"- line: {packet.target.line}",
            f"- column: {packet.target.column}",
            f"- sink: {packet.target.sink}",
            f"- arg_index: {packet.target.arg_index}",
            f"- expression: {packet.target.expression}",
            "",
            "Sink rule:",
            f"- id: {sink_rule.id}",
            f"- qualified_name: {sink_rule.qualified_name}",
            f"- nil_sensitive: {sink_rule.nil_sensitive}",
            f"- failure_mode: {sink_rule.failure_mode}",
            f"- safe_patterns: {', '.join(sink_rule.safe_patterns) if sink_rule.safe_patterns else '(none)'}",
            "",
            "Static reasoning:",
            f"- state: {packet.static_reasoning['state']}",
            f"- origin_candidates: {', '.join(packet.static_reasoning['origin_candidates']) or '(none)'}",
            f"- observed_guards: {', '.join(packet.static_reasoning['observed_guards']) or '(none)'}",
            "",
            "Local context:",
            packet.local_context or "(none)",
            "",
            "Related functions:",
            ", ".join(packet.related_functions) if packet.related_functions else "(none)",
            "",
            "Function summaries:",
            "\n".join(packet.function_summaries) if packet.function_summaries else "(none)",
            "",
            "Knowledge facts:",
            "\n".join(packet.knowledge_facts) if packet.knowledge_facts else "(none)",
        ]
    )
