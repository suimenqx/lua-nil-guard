from __future__ import annotations

from lua_nil_review_agent.models import CandidateCase, FunctionContract
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


def test_analyze_candidate_keeps_early_return_guard_active_across_non_assignments() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if not username then",
            "  return nil",
            "end",
            "log('ready')",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7b",
        file="demo.lua",
        line=6,
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


def test_analyze_candidate_treats_contract_guard_call_as_safe() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_contract_guard",
        file="demo.lua",
        line=3,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(
        source,
        candidate,
        function_contracts=(
            FunctionContract(
                qualified_name="assert_present",
                returns_non_nil=False,
                ensures_non_nil_args=(1,),
                notes="raises when username is nil",
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("assert_present(username)",)
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_treats_normalizer_return_contract_as_safe() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_return_contract",
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

    result = analyze_candidate(
        source,
        candidate,
        function_contracts=(
            FunctionContract(
                qualified_name="normalize_name",
                returns_non_nil=False,
                returns_non_nil_from_args=(1,),
                notes="normalizes nil usernames",
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username)",)


def test_analyze_candidate_keeps_assert_active_across_non_assignments() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert(username)",
            "log('ready')",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7assert_a",
        file="demo.lua",
        line=4,
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
    assert result.observed_guards == ("assert(username)",)
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_invalidates_assert_after_reassignment() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert(username)",
            "username = req.params.fallback_name",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7assert_b",
        file="demo.lua",
        line=4,
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
    assert result.origin_candidates == ("req.params.fallback_name",)


def test_analyze_candidate_does_not_leak_assert_to_else_branch() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if ready then",
            "  assert(username)",
            "else",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7assert_c",
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

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_invalidates_early_return_guard_after_reassignment() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if not username then",
            "  return nil",
            "end",
            "username = req.params.fallback_name",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7c",
        file="demo.lua",
        line=6,
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
    assert result.origin_candidates == ("req.params.fallback_name",)


def test_analyze_candidate_does_not_leak_early_return_guard_to_else_branch() -> None:
    source = "\n".join(
        [
            "if ready then",
            "  if not username then",
            "    return nil",
            "  end",
            "else",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_7d",
        file="demo.lua",
        line=6,
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
    assert result.origin_candidates == ("username",)


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


def test_analyze_candidate_keeps_positive_guard_on_sibling_branch_after_reassignment() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  if ready then",
            "    username = req.params.fallback_name",
            "  else",
            "    return string.match(username, '^a')",
            "  end",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_8b",
        file="demo.lua",
        line=6,
        column=12,
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


def test_analyze_candidate_ignores_branch_local_origin_after_merge() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if ready then",
            "  username = req.params.fallback_name",
            "end",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_8c",
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
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_ignores_then_branch_origin_in_else_branch() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if ready then",
            "  username = req.params.primary_name",
            "else",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_8d",
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

    assert result.state == "unknown_static"
    assert result.origin_candidates == ("req.params.username",)


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
