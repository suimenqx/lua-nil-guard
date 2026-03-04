from __future__ import annotations

from pathlib import Path

from lua_nil_guard.models import SinkRule
from lua_nil_guard.service import review_source


def test_review_source_combines_collection_and_static_analysis() -> None:
    sink_rules = (
        SinkRule(
            id="string.match.arg1",
            kind="function_arg",
            qualified_name="string.match",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  return string.match(username, '^a')",
            "end",
        ]
    )

    assessments = review_source(Path("foo.lua"), source, sink_rules)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.candidate.sink_name == "string.match"
    assert assessment.candidate.static_state == "safe_static"
    assert assessment.static_analysis.observed_guards == ("if username then",)
    assert assessment.static_analysis.origin_candidates == ("req.params.username",)


def test_review_source_handles_receiver_candidates() -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("if x then ... end",),
        ),
    )
    source = "\n".join(
        [
            "local profile = req.profile",
            "if profile then",
            "  return profile.name",
            "end",
        ]
    )

    assessments = review_source(Path("foo.lua"), source, sink_rules)

    assert len(assessments) == 2

    assessment_by_expression = {
        assessment.candidate.expression: assessment for assessment in assessments
    }

    req_assessment = assessment_by_expression["req"]
    assert req_assessment.candidate.sink_name == "member_access"
    assert req_assessment.candidate.static_state == "unknown_static"
    assert req_assessment.static_analysis.observed_guards == ()
    assert req_assessment.static_analysis.origin_candidates == ("req",)

    profile_assessment = assessment_by_expression["profile"]
    assert profile_assessment.candidate.sink_name == "member_access"
    assert profile_assessment.candidate.static_state == "safe_static"
    assert profile_assessment.static_analysis.observed_guards == ("if profile then",)
    assert profile_assessment.static_analysis.origin_candidates == ("req.profile",)


def test_review_source_suppresses_receiver_false_positive_for_global_require_module() -> None:
    sink_rules = (
        SinkRule(
            id="member_access.receiver",
            kind="receiver",
            qualified_name="member_access",
            arg_index=0,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("if x then ... end",),
        ),
    )
    source = "\n".join(
        [
            "require('bsbsocket')",
            "return bsbsocket.connect",
        ]
    )

    assessments = review_source(Path("foo.lua"), source, sink_rules)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.candidate.expression == "bsbsocket"
    assert assessment.candidate.static_state == "safe_static"
    assert any(proof.kind == "required_module_guard" for proof in assessment.static_analysis.proofs)


def test_review_source_handles_length_operator_candidates() -> None:
    sink_rules = (
        SinkRule(
            id="length.operand",
            kind="unary_operand",
            qualified_name="#",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or {}",),
        ),
    )
    source = "\n".join(
        [
            "local items = req.items or {}",
            "return #items",
        ]
    )

    assessments = review_source(Path("foo.lua"), source, sink_rules)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.candidate.sink_name == "#"
    assert assessment.candidate.expression == "items"
    assert assessment.candidate.static_state == "safe_static"
    assert assessment.static_analysis.observed_guards == ("items = items or ...",)
    assert assessment.static_analysis.origin_candidates == ("req.items or {}",)


def test_review_source_uses_local_ast_inlined_guard_helpers() -> None:
    sink_rules = (
        SinkRule(
            id="string.match.arg1",
            kind="function_arg",
            qualified_name="string.match",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("assert(x)",),
        ),
    )
    source = "\n".join(
        [
            "local function assert_present(value)",
            "  if not value then",
            "    error('missing')",
            "  end",
            "  return value",
            "end",
            "",
            "local username = req.params.username",
            "assert_present(username)",
            "return string.match(username, '^a')",
        ]
    )

    assessments = review_source(Path("foo.lua"), source, sink_rules)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.candidate.static_state == "safe_static"
    assert assessment.static_analysis.observed_guards == ("assert_present(username)",)
    assert any(proof.kind == "contract_guard" for proof in assessment.static_analysis.proofs)
