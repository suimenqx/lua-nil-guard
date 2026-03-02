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


def test_analyze_candidate_does_not_treat_nil_branch_ternary_as_defaulted() -> None:
    source = "\n".join(
        [
            'local username = req.force_nil and nil or "admin"',
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_4",
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
    assert result.origin_candidates == ('req.force_nil and nil or "admin"',)


def test_analyze_candidate_tracks_single_call_origin_for_multi_assignment() -> None:
    source = "\n".join(
        [
            "local display_name, tag = normalize_pair(req.params.display_name)",
            "return string.match(display_name, '^g')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_5",
        file="demo.lua",
        line=2,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="display_name",
        symbol="display_name",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_pair(req.params.display_name)",)


def test_analyze_candidate_does_not_treat_closed_if_block_as_active_guard() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  log(username)",
            "end",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_6",
        file="demo.lua",
        line=5,
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


def test_analyze_candidate_treats_early_return_guard_as_safe() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if not username then",
            "  return nil",
            "end",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7",
        file="demo.lua",
        line=5,
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
    assert result.observed_guards == ("if not username then return",)
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_invalidates_positive_guard_after_reassignment() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  username = req.params.fallback_name",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_8",
        file="demo.lua",
        line=4,
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

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("req.params.fallback_name",)


def test_analyze_candidate_allows_re_guard_after_reassignment() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  username = req.params.fallback_name",
            "  if username then",
            "    return string.match(username, '^a')",
            "  end",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_9",
        file="demo.lua",
        line=5,
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
    assert result.origin_candidates == ("req.params.fallback_name",)
