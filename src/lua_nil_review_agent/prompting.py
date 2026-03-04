from __future__ import annotations

from pathlib import Path

from .models import EvidencePacket, SinkRule, StaticProof
from .skill_runtime import compile_adjudicator_skill_header
from .verification import preview_static_verification


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
    "no_bounded_ast_proof": (
        "Example (no_bounded_ast_proof): when AST sees the shape but cannot prove a bounded guard, do not promote weak similarity into safety."
    ),
    "no_bounded_ast_origin": (
        "Example (no_bounded_ast_origin): if the local source cannot be bounded to a clear assignment, treat origin evidence as incomplete."
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
            f"- origin_analysis_mode: {packet.static_reasoning.get('origin_analysis_mode', 'legacy_origin_only') or 'legacy_origin_only'}",
            f"- origin_unknown_reason: {packet.static_reasoning.get('origin_unknown_reason', '') or '(none)'}",
            f"- observed_guards: {', '.join(packet.static_reasoning['observed_guards']) or '(none)'}",
            f"- proof_kinds: {', '.join(packet.static_reasoning.get('proof_kinds', ())) or '(none)'}",
            "",
            "Structured static proofs:",
            _render_static_proofs(packet.static_proofs),
            "",
            "Static verification preview:",
            _render_verification_preview(packet),
            "",
            "Calibration examples:",
            _render_calibration_examples(packet),
            "",
            "Role calibration:",
            _render_role_calibration(),
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
    preview = preview_static_verification(packet.static_proofs)
    has_deep_proof = any(proof.depth >= 2 for proof in packet.static_proofs)

    for proof in packet.static_proofs:
        calibration = _PROOF_KIND_CALIBRATIONS.get(proof.kind)
        if calibration is None or calibration in seen:
            continue
        examples.append(calibration)
        seen.add(calibration)
        if len(examples) >= 2:
            break

    if has_deep_proof:
        depth_calibration = (
            "Example (proof_depth): deeper proof chains should be treated as bounded evidence only; verify that every hop is explicit before accepting safety."
        )
        if depth_calibration not in seen:
            examples.append(depth_calibration)
            seen.add(depth_calibration)

    unknown_reason = packet.static_reasoning.get("unknown_reason", "")
    if isinstance(unknown_reason, str):
        calibration = _UNKNOWN_REASON_CALIBRATIONS.get(unknown_reason)
        if calibration is not None and calibration not in seen:
            examples.append(calibration)
            seen.add(calibration)

    origin_unknown_reason = packet.static_reasoning.get("origin_unknown_reason", "")
    if isinstance(origin_unknown_reason, str):
        calibration = _UNKNOWN_REASON_CALIBRATIONS.get(origin_unknown_reason)
        if calibration is not None and calibration not in seen:
            examples.append(calibration)
            seen.add(calibration)

    if preview is not None:
        verification_calibration = _verification_calibration(preview)
        if verification_calibration is not None and verification_calibration not in seen:
            examples.append(verification_calibration)
            seen.add(verification_calibration)

    if not examples:
        return "(none)"
    return "\n".join(f"- {example}" for example in examples)


def _render_verification_preview(packet: EvidencePacket) -> str:
    preview = preview_static_verification(packet.static_proofs)
    if preview is None:
        return "(none)"
    evidence = ", ".join(preview.evidence) if preview.evidence else "(none)"
    return "\n".join(
        [
            f"- mode: {preview.mode}",
            f"- strongest_proof_kind: {preview.strongest_proof_kind or '(none)'}",
            f"- strongest_proof_depth: {preview.strongest_proof_depth if preview.strongest_proof_depth is not None else '(none)'}",
            f"- verification_score: {preview.verification_score if preview.verification_score is not None else '(none)'}",
            f"- evidence: {evidence}",
        ]
    )


def _render_role_calibration() -> str:
    return "\n".join(
        [
            "- Prosecutor: try to break the current proof chain, not speculate about unseen code.",
            "- Defender: argue only from structured static proofs, matched contracts, wrapper evidence, and knowledge facts already in the packet.",
            "- Judge: decide whether the present proof is sufficient; unresolved gaps should remain `uncertain`, not auto-upgrade to `risky`.",
        ]
    )


def _verification_calibration(preview) -> str | None:
    score = preview.verification_score
    depth = preview.strongest_proof_depth
    if score is None:
        return None
    if score >= 80 and (depth is None or depth <= 1):
        return (
            "Example (verification_summary): a high-score shallow proof usually deserves deference unless a concrete reachable counterexample appears in the packet."
        )
    if depth is not None and depth >= 2:
        return (
            "Example (verification_summary): a deeper proof chain is useful but still bounded; keep the verdict conservative if any hop depends on weak inference."
        )
    return (
        "Example (verification_summary): medium-strength static proof should shape the review, but it does not by itself resolve missing control-flow evidence."
    )
