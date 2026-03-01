from __future__ import annotations

from .models import EvidencePacket, SinkRule


def build_adjudication_prompt(*, packet: EvidencePacket, sink_rule: SinkRule) -> str:
    """Render a deterministic prompt for strict nil-risk adjudication."""

    return "\n".join(
        [
            "You are a strict Lua nil-risk adjudicator.",
            "Judge only whether nil can reach the declared nil-sensitive sink.",
            "Unknown is not risk.",
            "Absence of proof is not proof of bug.",
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
            "",
            "Required output:",
            "- status: safe | risky | uncertain",
            "- confidence: low | medium | high",
            "- risk_path: explicit path steps only",
            "- safety_evidence: explicit guard or contract evidence only",
            "- missing_evidence: what else is needed if uncertain",
            "- recommended_next_action: suppress | expand_context | verify_runtime | report | autofix",
            "- suggested_fix: only when confidence is sufficient",
        ]
    )
