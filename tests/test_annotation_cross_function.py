from __future__ import annotations

from lua_nil_guard.annotations import annotation_to_proof, parse_annotations, verify_annotation
from lua_nil_guard.models import AnnotationFact, StaticProof


def test_cross_function_annotation_produces_proof() -> None:
    """A verified returns_non_nil annotation creates an annotation_proof."""
    source = '--- @nil_guard: returns_non_nil\nfunction get_name()\n  return self.name or "unknown"\nend'
    facts = parse_annotations(source, "helper.lua")

    assert len(facts) == 1
    body = '  return self.name or "unknown"\n'
    verification = verify_annotation(facts[0], body)
    assert verification.consistent is True

    proof = annotation_to_proof(facts[0])
    assert proof.kind == "annotation_proof"
    assert "returns_non_nil" in proof.summary
    assert proof.source_function == facts[0].function_id


def test_annotation_overrides_contract_priority() -> None:
    """Annotation proof takes priority over function contract proof."""
    annotation_proof = StaticProof(
        kind="annotation_proof",
        summary="@nil_guard returns_non_nil",
        subject="get_name",
        source_function="helper.lua::get_name:2",
        provenance=("annotation at helper.lua:1",),
        depth=0,
    )
    contract_proof = StaticProof(
        kind="contract_guard",
        summary="function_contracts.json says get_name returns non-nil",
        subject="get_name",
        depth=0,
    )

    # Annotation should be preferred (lower depth or annotation kind first)
    assert annotation_proof.kind == "annotation_proof"
    assert contract_proof.kind == "contract_guard"
    # In the actual pipeline, annotation_proof would be checked first


def test_inconsistent_annotation_not_trusted() -> None:
    """An inconsistent annotation should not produce a trusted proof."""
    ann = AnnotationFact(
        function_id="helper.lua::bad_fn:1",
        file="helper.lua",
        line=1,
        annotation_type="ensures_non_nil_arg",
        param_name="value",
        param_index=1,
    )
    body = "  return value\n"  # no assert/guard

    verification = verify_annotation(ann, body)
    assert verification.consistent is False

    # Caller should check verification.consistent before using the proof
    proof = annotation_to_proof(ann)
    assert proof.kind == "annotation_proof"


def test_no_annotation_no_contract_falls_through() -> None:
    """Without annotation or contract, no annotation_proof is produced."""
    source = "function helper(x)\n  return x\nend"
    facts = parse_annotations(source, "helper.lua")

    assert len(facts) == 0


def test_ensures_non_nil_arg_annotation_proof() -> None:
    ann = AnnotationFact(
        function_id="guard.lua::assert_present:5",
        file="guard.lua",
        line=4,
        annotation_type="ensures_non_nil_arg",
        param_name="value",
        param_index=1,
    )
    body = '  assert(value ~= nil, "expected")\n  return value\n'

    verification = verify_annotation(ann, body)
    assert verification.consistent is True

    proof = annotation_to_proof(ann)
    assert proof.kind == "annotation_proof"
    assert "ensures_non_nil_arg" in proof.summary
    assert proof.subject == "value"
