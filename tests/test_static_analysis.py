from __future__ import annotations

from lua_nil_review_agent.models import CandidateCase
from lua_nil_review_agent.static_analysis import analyze_candidate


def test_analyze_candidate_marks_guarded_symbol_safe() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_1",
        file="demo.lua",
        line=3,
        column=10,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    assert result.observed_guards == ("if username then",)
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_marks_defaulted_symbol_safe() -> None:
    source = "\n".join(
        [
            "local username = req.params.username or ''",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_2",
        file="demo.lua",
        line=2,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    assert result.observed_guards == ("username = username or ...",)
    assert result.origin_candidates == ("req.params.username or ''",)


def test_analyze_candidate_leaves_unguarded_value_unknown() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_3",
        file="demo.lua",
        line=2,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("req.params.username",)
