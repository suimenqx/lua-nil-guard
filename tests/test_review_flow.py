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
