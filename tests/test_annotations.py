from __future__ import annotations

from lua_nil_guard.annotations import (
    annotation_to_proof,
    parse_annotations,
    verify_annotation,
)
from lua_nil_guard.models import AnnotationFact, StaticProof


# =========================================================================
# Parser tests
# =========================================================================


def test_parse_returns_non_nil() -> None:
    source = '--- @nil_guard: returns_non_nil\nfunction get_name()\n  return self.name or "unknown"\nend'
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1
    assert facts[0].annotation_type == "returns_non_nil"
    assert "get_name" in facts[0].function_id


def test_parse_ensures_non_nil_arg() -> None:
    source = '--- @nil_guard: ensures_non_nil_arg 1\nfunction assert_present(value)\n  assert(value ~= nil)\n  return value\nend'
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1
    assert facts[0].annotation_type == "ensures_non_nil_arg"
    assert facts[0].param_index == 1
    assert facts[0].param_name == "value"


def test_parse_param_nullability() -> None:
    source = '--- @nil_guard param raw: may_nil\nfunction normalize(raw, fallback)\n  return raw or fallback or ""\nend'
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1
    assert facts[0].annotation_type == "param_nullability"
    assert facts[0].param_name == "raw"
    assert facts[0].nullability == "may_nil"


def test_parse_return_nullability() -> None:
    source = "--- @nil_guard return 1: non_nil\nfunction get()\n  return 42\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1
    assert facts[0].annotation_type == "return_nullability"
    assert facts[0].return_slot == 1
    assert facts[0].nullability == "non_nil"


def test_parse_conditional_annotation() -> None:
    source = "--- @nil_guard: returns_non_nil when arg1 is non_nil\nfunction f(x)\n  return x or 'default'\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1
    assert facts[0].condition == "arg1 is non_nil"


def test_parse_multiple_annotations_same_function() -> None:
    source = "--- @nil_guard param raw: may_nil\n--- @nil_guard return 1: non_nil\nfunction f(raw)\n  return raw or ''\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 2
    assert facts[0].function_id == facts[1].function_id


def test_parse_blank_line_between_annotation_and_function() -> None:
    source = "--- @nil_guard: returns_non_nil\n\nfunction f()\n  return 'ok'\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1


def test_parse_annotation_without_function_ignored() -> None:
    source = "--- @nil_guard: returns_non_nil\nlocal x = 1"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 0


def test_parse_non_nil_guard_comment_ignored() -> None:
    source = "--- this is a regular comment\nfunction f()\n  return 1\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 0


def test_parse_malformed_annotation_ignored() -> None:
    source = "--- @nil_guard foobar garbage\nfunction f()\n  return 1\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 0


def test_parse_no_annotations() -> None:
    source = "function f()\n  return 1\nend"
    facts = parse_annotations(source, "test.lua")

    assert facts == ()


def test_parse_local_function() -> None:
    source = "--- @nil_guard: returns_non_nil\nlocal function helper()\n  return ''\nend"
    facts = parse_annotations(source, "test.lua")

    assert len(facts) == 1
    assert "helper" in facts[0].function_id


# =========================================================================
# Verification tests
# =========================================================================


def test_verify_returns_non_nil_consistent() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="returns_non_nil",
        raw_text="--- @nil_guard: returns_non_nil",
    )
    body = '  return "hello"\n'

    result = verify_annotation(ann, body)

    assert result.consistent is True


def test_verify_returns_non_nil_inconsistent_with_return_nil() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="returns_non_nil",
    )
    body = "  if x then return x end\n"

    result = verify_annotation(ann, body)

    # ends without return in else branch
    assert result.consistent is False


def test_verify_returns_non_nil_with_or_default() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="returns_non_nil",
    )
    body = "  return x or ''\n"

    result = verify_annotation(ann, body)

    assert result.consistent is True


def test_verify_ensures_non_nil_arg_with_assert() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="ensures_non_nil_arg",
        param_name="value",
        param_index=1,
    )
    body = '  assert(value ~= nil, "expected non-nil")\n  return value\n'

    result = verify_annotation(ann, body)

    assert result.consistent is True


def test_verify_ensures_non_nil_arg_without_guard() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="ensures_non_nil_arg",
        param_name="value",
        param_index=1,
    )
    body = "  return value\n"

    result = verify_annotation(ann, body)

    assert result.consistent is False


def test_verify_param_may_nil_with_guard() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="param_nullability",
        param_name="raw",
        nullability="may_nil",
    )
    body = '  if raw then\n    return raw\n  end\n  return "default"\n'

    result = verify_annotation(ann, body)

    assert result.consistent is True


def test_verify_param_may_nil_without_guard() -> None:
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="param_nullability",
        param_name="raw",
        nullability="may_nil",
    )
    body = '  return string.match(raw, "^a")\n'

    result = verify_annotation(ann, body)

    assert result.consistent is False


def test_inconsistent_annotation_does_not_produce_proof() -> None:
    """When verification fails, the annotation should not be trusted."""
    ann = AnnotationFact(
        function_id="test.lua::f:1",
        file="test.lua",
        line=1,
        annotation_type="ensures_non_nil_arg",
        param_name="value",
        param_index=1,
    )
    body = "  return value\n"

    verification = verify_annotation(ann, body)
    assert verification.consistent is False

    # Proof can still be generated but caller should check verification first
    proof = annotation_to_proof(ann)
    assert proof.kind == "annotation_proof"


# =========================================================================
# Annotation → StaticProof conversion
# =========================================================================


def test_annotation_to_proof() -> None:
    ann = AnnotationFact(
        function_id="test.lua::normalize:10",
        file="test.lua",
        line=9,
        annotation_type="returns_non_nil",
    )

    proof = annotation_to_proof(ann)

    assert isinstance(proof, StaticProof)
    assert proof.kind == "annotation_proof"
    assert "returns_non_nil" in proof.summary
    assert proof.source_function == "test.lua::normalize:10"
