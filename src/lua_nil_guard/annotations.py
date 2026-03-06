"""Annotation parser and consistency verifier for Lua nil-guard annotations.

Parses ``--- @nil_guard`` comments in Lua source and optionally verifies
them against function body evidence.
"""

from __future__ import annotations

import re

from .models import AnnotationFact, AnnotationVerification, StaticProof


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_ANNOTATION_PREFIX_RE = re.compile(r"^---\s*@nil_guard\b(.*)$")

_RETURNS_NON_NIL_RE = re.compile(r"^\s*:?\s*returns_non_nil\b(.*)$")
_ENSURES_ARG_RE = re.compile(r"^\s*:\s*ensures_non_nil_arg\s+(\d+)\s*$")
_PARAM_RE = re.compile(r"^\s+param\s+(\w+)\s*:\s*(non_nil|may_nil)\s*$")
_RETURN_RE = re.compile(r"^\s+return\s+(\d+)\s*:\s*(non_nil|may_nil)\s*$")
_CONDITION_RE = re.compile(r"^(?:\s+)?when\s+(.+)$")

_FUNCTION_DEF_RE = re.compile(
    r"^(?:local\s+)?function\s+(?:[\w.:]+)\s*\(([^)]*)\)"
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_annotations(source: str, file_path: str) -> tuple[AnnotationFact, ...]:
    """Parse all ``@nil_guard`` annotations in *source* and associate them with functions."""

    lines = source.splitlines()
    pending: list[tuple[int, str, dict]] = []  # (line_number, raw_text, parsed_info)
    results: list[AnnotationFact] = []

    for i, line in enumerate(lines):
        m = _ANNOTATION_PREFIX_RE.match(line.strip())
        if m is not None:
            rest = m.group(1)
            parsed = _parse_annotation_body(rest)
            if parsed is not None:
                pending.append((i + 1, line.strip(), parsed))
            continue

        if not pending:
            continue

        func_match = _FUNCTION_DEF_RE.match(line.strip())
        if func_match is not None:
            param_names = [p.strip() for p in func_match.group(1).split(",") if p.strip()]
            func_line = i + 1
            func_name = _extract_function_name(line.strip())
            func_id = f"{file_path}::{func_name}:{func_line}"

            for ann_line, raw_text, parsed in pending:
                fact = _build_annotation_fact(
                    parsed=parsed,
                    function_id=func_id,
                    file=file_path,
                    line=ann_line,
                    raw_text=raw_text,
                    param_names=param_names,
                )
                if fact is not None:
                    results.append(fact)
            pending.clear()
            continue

        # Allow blank lines between annotations and function
        if line.strip() and not line.strip().startswith("---"):
            pending.clear()

    return tuple(results)


def _parse_annotation_body(rest: str) -> dict | None:
    m = _RETURNS_NON_NIL_RE.match(rest)
    if m is not None:
        condition_part = m.group(1).strip()
        condition_match = _CONDITION_RE.match(condition_part) if condition_part else None
        condition = condition_match.group(1).strip() if condition_match else None
        return {"type": "returns_non_nil", "condition": condition}

    m = _ENSURES_ARG_RE.match(rest)
    if m is not None:
        return {"type": "ensures_non_nil_arg", "param_index": int(m.group(1))}

    m = _PARAM_RE.match(rest)
    if m is not None:
        return {"type": "param_nullability", "param_name": m.group(1), "nullability": m.group(2)}

    m = _RETURN_RE.match(rest)
    if m is not None:
        return {"type": "return_nullability", "return_slot": int(m.group(1)), "nullability": m.group(2)}

    return None


def _extract_function_name(line: str) -> str:
    m = re.match(r"^(?:local\s+)?function\s+([\w.:]+)", line)
    if m:
        return m.group(1)
    return "anonymous"


def _build_annotation_fact(
    *,
    parsed: dict,
    function_id: str,
    file: str,
    line: int,
    raw_text: str,
    param_names: list[str],
) -> AnnotationFact | None:
    ann_type = parsed["type"]

    if ann_type == "returns_non_nil":
        return AnnotationFact(
            function_id=function_id,
            file=file,
            line=line,
            annotation_type="returns_non_nil",
            nullability="non_nil",
            condition=parsed.get("condition"),
            raw_text=raw_text,
        )

    if ann_type == "ensures_non_nil_arg":
        idx = parsed["param_index"]
        name = param_names[idx - 1] if 0 < idx <= len(param_names) else None
        return AnnotationFact(
            function_id=function_id,
            file=file,
            line=line,
            annotation_type="ensures_non_nil_arg",
            param_name=name,
            param_index=idx,
            raw_text=raw_text,
        )

    if ann_type == "param_nullability":
        name = parsed["param_name"]
        idx = (param_names.index(name) + 1) if name in param_names else None
        return AnnotationFact(
            function_id=function_id,
            file=file,
            line=line,
            annotation_type="param_nullability",
            param_name=name,
            param_index=idx,
            nullability=parsed["nullability"],
            raw_text=raw_text,
        )

    if ann_type == "return_nullability":
        return AnnotationFact(
            function_id=function_id,
            file=file,
            line=line,
            annotation_type="return_nullability",
            return_slot=parsed["return_slot"],
            nullability=parsed["nullability"],
            raw_text=raw_text,
        )

    return None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_annotation(
    annotation: AnnotationFact,
    function_body: str,
    static_proofs: tuple[StaticProof, ...] = (),
) -> AnnotationVerification:
    """Verify whether *annotation* is consistent with *function_body*."""

    if annotation.annotation_type == "returns_non_nil":
        return _verify_returns_non_nil(annotation, function_body, static_proofs)

    if annotation.annotation_type == "ensures_non_nil_arg":
        return _verify_ensures_non_nil_arg(annotation, function_body)

    if annotation.annotation_type == "param_nullability":
        return _verify_param_nullability(annotation, function_body)

    return AnnotationVerification(
        annotation=annotation,
        consistent=True,
        confidence="low",
    )


def _verify_returns_non_nil(
    annotation: AnnotationFact,
    body: str,
    proofs: tuple[StaticProof, ...],
) -> AnnotationVerification:
    lines = body.splitlines()
    stripped_lines = [ln.strip() for ln in lines if ln.strip()]
    has_explicit_return = any("return " in ln or ln.strip() == "return" for ln in lines)
    has_return_nil = any(
        ln.strip() == "return" or ln.strip() == "return nil" or ln.strip().startswith("return nil,")
        for ln in lines
    )

    # Check if there's an "or" defaulting in all return paths
    return_lines = [ln for ln in lines if ln.strip().startswith("return ") and ln.strip() != "return"]
    all_returns_defaulted = bool(return_lines) and all(" or " in ln for ln in return_lines)

    # If proofs contain evidence of non-nil returns, trust them
    has_proof = any(
        p.kind in ("local_defaulting", "wrapper_defaulting", "return_contract")
        for p in proofs
    )

    # Check if the last non-empty line is a return or end-of-block that guarantees return
    last_line = stripped_lines[-1] if stripped_lines else ""
    ends_with_return = last_line.startswith("return ") or last_line == "return" or last_line == "return nil"
    has_complete_if_else_returns = _has_complete_if_else_returns(lines)

    # Detect conditional-only returns (return inside if/for but nothing after)
    # Also handle single-line ifs like "if x then return x end"
    has_conditional_return = has_explicit_return and not ends_with_return and not has_complete_if_else_returns and (
        last_line == "end"
        or (last_line.startswith("if ") and last_line.endswith(" end"))
    )

    if has_return_nil and not all_returns_defaulted and not has_proof:
        return AnnotationVerification(
            annotation=annotation,
            consistent=False,
            conflicts=("implicit or explicit return nil path exists",),
            confidence="medium",
        )

    # Function may end without a return on some paths → implicit return nil
    if has_conditional_return and not has_proof:
        return AnnotationVerification(
            annotation=annotation,
            consistent=False,
            conflicts=("function may end without return on some branches (implicit nil)",),
            confidence="medium",
        )

    if not has_explicit_return:
        return AnnotationVerification(
            annotation=annotation,
            consistent=False,
            conflicts=("function may end without explicit return (implicit nil)",),
            confidence="medium",
        )

    if all_returns_defaulted or has_proof:
        return AnnotationVerification(
            annotation=annotation,
            consistent=True,
            evidence=("all return paths produce non-nil values",),
            confidence="high",
        )

    return AnnotationVerification(
        annotation=annotation,
        consistent=True,
        evidence=("explicit returns found, no nil return detected",),
        confidence="medium",
    )


def _has_complete_if_else_returns(lines: list[str]) -> bool:
    """Best-effort detection for top-level if/else blocks where both branches return."""

    stripped = [ln.strip() for ln in lines if ln.strip()]
    if not stripped:
        return False

    # Single-line: if cond then return a else return b end
    if len(stripped) == 1:
        line = stripped[0]
        if line.startswith("if ") and line.endswith(" end") and " then " in line and " else " in line:
            before_else, after_else = line.split(" else ", 1)
            return " return " in before_else and " return " in after_else
        return False

    if not (stripped[0].startswith("if ") and stripped[0].endswith("then") and stripped[-1] == "end"):
        return False
    if "else" not in stripped:
        return False

    else_index = stripped.index("else")
    then_block = stripped[1:else_index]
    else_block = stripped[else_index + 1 : -1]
    if not then_block or not else_block:
        return False

    then_has_return = any(ln.startswith("return ") or ln == "return" for ln in then_block)
    else_has_return = any(ln.startswith("return ") or ln == "return" for ln in else_block)
    return then_has_return and else_has_return


def _verify_ensures_non_nil_arg(
    annotation: AnnotationFact,
    body: str,
) -> AnnotationVerification:
    name = annotation.param_name or f"arg{annotation.param_index}"

    has_assert = f"assert({name}" in body or f"assert( {name}" in body
    has_error_guard = f"if not {name}" in body or f"if {name} == nil" in body

    if has_assert or has_error_guard:
        return AnnotationVerification(
            annotation=annotation,
            consistent=True,
            evidence=(f"guard or assert found for {name}",),
            confidence="high",
        )

    return AnnotationVerification(
        annotation=annotation,
        consistent=False,
        conflicts=(f"no assert/error/guard found for {name}",),
        confidence="medium",
    )


def _verify_param_nullability(
    annotation: AnnotationFact,
    body: str,
) -> AnnotationVerification:
    name = annotation.param_name or ""
    if annotation.nullability == "may_nil":
        # Check if body guards before use
        has_guard = f"if {name}" in body or f"if not {name}" in body or f"{name} or " in body
        if has_guard:
            return AnnotationVerification(
                annotation=annotation,
                consistent=True,
                evidence=(f"guard found before using {name}",),
                confidence="medium",
            )
        return AnnotationVerification(
            annotation=annotation,
            consistent=False,
            conflicts=(f"{name} declared may_nil but no guard found before use",),
            confidence="low",
        )

    return AnnotationVerification(
        annotation=annotation,
        consistent=True,
        confidence="low",
    )


# ---------------------------------------------------------------------------
# Annotation → StaticProof conversion
# ---------------------------------------------------------------------------

def annotation_to_proof(annotation: AnnotationFact) -> StaticProof:
    """Convert a verified annotation into a StaticProof for cross-function reasoning."""

    summary = f"@nil_guard {annotation.annotation_type}"
    if annotation.param_name:
        summary += f" {annotation.param_name}"

    return StaticProof(
        kind="annotation_proof",
        summary=summary,
        subject=annotation.param_name or annotation.function_id,
        source_function=annotation.function_id,
        provenance=(f"annotation at {annotation.file}:{annotation.line}",),
        depth=0,
    )
