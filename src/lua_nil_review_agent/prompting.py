from __future__ import annotations

from pathlib import Path

from .models import EvidencePacket, SinkRule, StaticProof
from .skill_runtime import compile_adjudicator_skill_header


_PROOF_KIND_CALIBRATIONS = {
    "direct_guard": (
        "Example (direct_guard): `if username then sink(username)` is usually sufficient local safety proof unless a reassignment or alternate reachable branch bypasses the guard."
    ),
    "loop_exit_guard": (
        "Example (loop_exit_guard): `repeat ... until username` only proves safety after the loop when no earlier reachable break can bypass the exit condition."
    ),
    "early_exit_guard": (
        "Example (early_exit_guard): `if not username then return end; sink(username)` is normally sufficient because the nil branch cannot reach the sink."
    ),
    "assert_guard": (
        "Example (assert_guard): `assert(username); sink(username)` is usually sufficient because the failing branch aborts before the sink."
    ),
    "contract_guard": (
        "Example (contract_guard): if a configured or inlined helper guarantees argument non-nil, treat it as a strong proof only for the exact matched call shape."
    ),
    "guarded_field_origin": (
        "Example (guarded_field_origin): if `local name = req.params.name` happens under an active guard on the same field path, the local inherits that proof."
    ),
    "return_contract": (
        "Example (return_contract): when a call matches a constrained return contract, treat the proved return slot as safe, but do not generalize to other slots or call shapes."
    ),
    "chained_return_contract": (
        "Example (chained_return_contract): accept bounded chained proofs, but inspect each hop; one weak or mismatched hop breaks the whole chain."
    ),
    "wrapper_passthrough": (
        "Example (wrapper_passthrough): a tiny wrapper that only returns one argument preserves upstream proof, but only if its body is transparent and side-effect-light."
    ),
    "wrapper_defaulting": (
        "Example (wrapper_defaulting): a tiny wrapper that defaults to a non-nil literal is strong evidence for that return slot, but not for unrelated outputs."
    ),
    "local_defaulting": (
        "Example (local_defaulting): `value = value or ''` is strong local proof for that symbol, but it does not prove sibling values or earlier aliases."
    ),
}

_UNKNOWN_REASON_CALIBRATIONS = {
    "unsupported_control_flow": (
        "Example (unsupported_control_flow): when loops or richer reachability are not fully modeled, keep the verdict conservative unless independent strong proof exists."
    ),
    "dynamic_metatable": (
        "Example (dynamic_metatable): metatable-driven lookup can invalidate simple field assumptions; prefer `uncertain` unless another explicit proof dominates."
    ),
    "dynamic_index_expression": (
        "Example (dynamic_index_expression): dynamic table keys are not stable field paths; do not upgrade them to safe from prefix-only similarity."
    ),
    "unresolved_ast_node": (
        "Example (unresolved_ast_node): if the target node cannot be resolved precisely, distrust AST-specific proof claims and stay conservative."
    ),
    "upvalue_capture": (
        "Example (upvalue_capture): captured mutable upvalues can break local assumptions; do not treat them as simple local proofs."
    ),
}


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
            f"- origin_usage_modes: {', '.join(packet.static_reasoning.get('origin_usage_modes', ())) or '(none)'}",
            f"- origin_return_slots: {', '.join(packet.static_reasoning.get('origin_return_slots', ())) or '(none)'}",
            f"- analysis_mode: {packet.static_reasoning.get('analysis_mode', 'legacy_only') or 'legacy_only'}",
            f"- unknown_reason: {packet.static_reasoning.get('unknown_reason', '') or '(none)'}",
            f"- observed_guards: {', '.join(packet.static_reasoning['observed_guards']) or '(none)'}",
            f"- proof_kinds: {', '.join(packet.static_reasoning.get('proof_kinds', ())) or '(none)'}",
            "",
            "Structured static proofs:",
            _render_static_proofs(packet.static_proofs),
            "",
            "Calibration examples:",
            _render_calibration_examples(packet),
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
            "Related function contexts:",
            "\n\n".join(packet.related_function_contexts) if packet.related_function_contexts else "(none)",
            "",
            "Knowledge facts:",
            "\n".join(packet.knowledge_facts) if packet.knowledge_facts else "(none)",
        ]
    )


def _render_static_proofs(proofs: tuple[StaticProof, ...]) -> str:
    if not proofs:
        return "(none)"

    chunks: list[str] = []
    for proof in proofs:
        lines = [
            f"- [{proof.kind}] {proof.summary}",
            f"  subject: {proof.subject}",
        ]
        if proof.source_function:
            lines.append(f"  source_function: {proof.source_function}")
        if proof.source_call:
            lines.append(f"  source_call: {proof.source_call}")
        if proof.source_symbol:
            lines.append(f"  source_symbol: {proof.source_symbol}")
        if proof.supporting_summaries:
            lines.append(f"  supporting: {', '.join(proof.supporting_summaries)}")
        if proof.provenance:
            lines.append(f"  provenance: {' | '.join(proof.provenance)}")
        lines.append(f"  depth: {proof.depth}")
        chunks.append("\n".join(lines))
    return "\n\n".join(chunks)


def _render_calibration_examples(packet: EvidencePacket) -> str:
    examples: list[str] = []
    seen: set[str] = set()

    for proof in packet.static_proofs:
        calibration = _PROOF_KIND_CALIBRATIONS.get(proof.kind)
        if calibration is None or calibration in seen:
            continue
        examples.append(calibration)
        seen.add(calibration)
        if len(examples) >= 2:
            break

    unknown_reason = packet.static_reasoning.get("unknown_reason", "")
    if isinstance(unknown_reason, str):
        calibration = _UNKNOWN_REASON_CALIBRATIONS.get(unknown_reason)
        if calibration is not None and calibration not in seen:
            examples.append(calibration)
            seen.add(calibration)

    if not examples:
        return "(none)"
    return "\n".join(f"- {example}" for example in examples)
