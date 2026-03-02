from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.models import SinkRule
from lua_nil_review_agent.service import review_source


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
