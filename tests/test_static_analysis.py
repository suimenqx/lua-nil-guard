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


def test_analyze_candidate_limits_guard_contracts_to_configured_sinks() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username)",
            "return string.find(username, 'a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_sink_guard_contract",
        file="demo.lua",
        line=3,
        column=8,
        sink_rule_id="string.find.arg1",
        sink_name="string.find",
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
                applies_to_sinks=("string.match.arg1",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_respects_guard_contract_arg_count() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username, 'username')",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_call_shape_guard_contract",
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
                applies_with_arg_count=2,
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("assert_present(username)",)
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_respects_guard_contract_literal_args() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username, false)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_literal_guard_contract",
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
                required_literal_args=((2, ("false",)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("assert_present(username)",)
    assert result.origin_candidates == ("req.params.username",)


def test_analyze_candidate_limits_guard_contracts_to_configured_call_roles() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_role_guard_contract",
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
                applies_to_call_roles=("assignment_origin",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
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


def test_analyze_candidate_respects_return_contract_literal_args() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username, '')",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_literal_return_contract",
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
                required_literal_args=((2, ("''",)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username, '')",)


def test_analyze_candidate_respects_return_contract_arg_shapes() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_shape_return_contract",
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
                required_arg_shapes=((1, ("member_access",)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username)",)


def test_analyze_candidate_limits_return_contracts_to_configured_literal_args() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username, fallback_name)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_literal_return_contract",
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
                required_literal_args=((2, ("''",)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username, fallback_name)",)


def test_analyze_candidate_limits_return_contracts_to_configured_arg_shapes() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_shape_return_contract",
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
                required_arg_shapes=((1, ("member_access",)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(username)",)


def test_analyze_candidate_respects_return_contract_arg_roots() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_root_return_contract",
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
                required_arg_roots=((1, ("req",)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username)",)


def test_analyze_candidate_limits_return_contracts_to_configured_arg_roots() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(fallbacks.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_root_return_contract",
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
                required_arg_roots=((1, ("req",)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(fallbacks.username)",)


def test_analyze_candidate_respects_return_contract_arg_prefixes() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_prefix_return_contract",
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
                required_arg_prefixes=((1, ("req.params",)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username)",)


def test_analyze_candidate_limits_return_contracts_to_configured_arg_prefixes() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.headers.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_prefix_return_contract",
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
                required_arg_prefixes=((1, ("req.params",)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.headers.username)",)


def test_analyze_candidate_respects_return_contract_arg_access_paths() -> None:
    source = "\n".join(
        [
            'local username = normalize_name(req.params["user"])',
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_access_path_return_contract",
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
                required_arg_access_paths=((1, ("req.params.user",)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ('normalize_name(req.params["user"])',)


def test_analyze_candidate_limits_return_contracts_to_configured_arg_access_paths() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params[token])",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_access_path_return_contract",
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
                required_arg_access_paths=((1, ("req.params.user",)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params[token])",)


def test_analyze_candidate_limits_return_contracts_to_configured_call_roles() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_role_return_contract",
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
                applies_to_call_roles=("sink_expression",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username)",)


def test_analyze_candidate_respects_return_contract_single_assignment_usage() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_single_assignment_usage",
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
                applies_to_usage_modes=("single_assignment",),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username)",)
    assert result.origin_usage_modes == ("single_assignment",)


def test_analyze_candidate_limits_return_contracts_to_configured_function_scopes() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_function_scope_return_contract",
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
                applies_in_function_scopes=("parse_user",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username)",)
    assert result.origin_usage_modes == ("single_assignment",)


def test_analyze_candidate_limits_return_contracts_to_scope_kinds() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scope_kind_return_contract",
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
                applies_to_scope_kinds=("function_body",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username)",)
    assert result.origin_usage_modes == ("single_assignment",)


def test_analyze_candidate_limits_return_contracts_to_top_level_phases() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_top_level_phase_return_contract",
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
                applies_to_top_level_phases=("post_definitions",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username)",)
    assert result.origin_usage_modes == ("single_assignment",)


def test_analyze_candidate_limits_return_contracts_to_single_assignment_usage() -> None:
    source = "\n".join(
        [
            "local username, tag = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_multi_assignment_usage",
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
                applies_to_usage_modes=("single_assignment",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username)",)
    assert result.origin_usage_modes == ("multi_assignment",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_respects_return_contract_first_slot_in_multi_assignment() -> None:
    source = "\n".join(
        [
            "local username, tag = normalize_pair(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_return_slot_first",
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
                qualified_name="normalize_pair",
                returns_non_nil=False,
                returns_non_nil_from_args=(1,),
                applies_to_return_slots=(1,),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_pair(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_pair(req.params.username)",)
    assert result.origin_usage_modes == ("multi_assignment",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_limits_return_contract_to_first_slot_in_multi_assignment() -> None:
    source = "\n".join(
        [
            "local username, tag = normalize_pair(req.params.username)",
            "return string.match(tag, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_return_slot_second",
        file="demo.lua",
        line=2,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="tag",
        symbol="tag",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(
        source,
        candidate,
        function_contracts=(
            FunctionContract(
                qualified_name="normalize_pair",
                returns_non_nil=False,
                returns_non_nil_from_args=(1,),
                applies_to_return_slots=(1,),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_pair(req.params.username)",)
    assert result.origin_usage_modes == ("multi_assignment",)
    assert result.origin_return_slots == (2,)


def test_analyze_candidate_uses_return_slot_specific_arg_requirements() -> None:
    source = "\n".join(
        [
            "local username, tag = normalize_pair(req.params.username, '')",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_return_slot_specific_args_first",
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
                qualified_name="normalize_pair",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((1, (2,)), (2, (1,))),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_pair(...) returns non-nil",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_limits_return_slot_specific_arg_requirements() -> None:
    source = "\n".join(
        [
            "local username, tag = normalize_pair(req.params.username, '')",
            "return string.match(tag, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_return_slot_specific_args_second",
        file="demo.lua",
        line=2,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="tag",
        symbol="tag",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(
        source,
        candidate,
        function_contracts=(
            FunctionContract(
                qualified_name="normalize_pair",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((1, (2,)), (2, (3,))),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_return_slots == (2,)


def test_analyze_candidate_combines_guard_contract_with_return_normalizer() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username)",
            "local raw, normalized = normalize_pair(username, '')",
            "return string.match(normalized, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_guarded_return_combo",
        file="demo.lua",
        line=4,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="normalized",
        symbol="normalized",
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
            ),
            FunctionContract(
                qualified_name="normalize_pair",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((2, (2,)),),
                requires_guarded_args_by_return_slot=((2, (1,)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_pair(...) returns non-nil",)
    assert result.origin_return_slots == (2,)


def test_analyze_candidate_requires_guard_before_return_normalizer_combo() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "local raw, normalized = normalize_pair(username, '')",
            "return string.match(normalized, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_guardless_return_combo",
        file="demo.lua",
        line=3,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="normalized",
        symbol="normalized",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(
        source,
        candidate,
        function_contracts=(
            FunctionContract(
                qualified_name="normalize_pair",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((2, (2,)),),
                requires_guarded_args_by_return_slot=((2, (1,)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_return_slots == (2,)


def test_analyze_candidate_respects_return_contract_arg_count() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username, '')",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_call_shape_return_contract",
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
                applies_with_arg_count=2,
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_name(...) returns non-nil",)
    assert result.origin_candidates == ("normalize_name(req.params.username, '')",)


def test_analyze_candidate_limits_normalizer_contracts_to_configured_sinks() -> None:
    source = "\n".join(
        [
            "local username = normalize_name(req.params.username)",
            "return string.find(username, 'a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_sink_return_contract",
        file="demo.lua",
        line=2,
        column=8,
        sink_rule_id="string.find.arg1",
        sink_name="string.find",
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
                applies_to_sinks=("string.match.arg1",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("normalize_name(req.params.username)",)


def test_analyze_candidate_ignores_scoped_normalizer_contract_outside_module() -> None:
    source = "\n".join(
        [
            "module(\"admin.profile\", package.seeall)",
            "local username = normalize_name(req.params.username)",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_scoped_return_contract",
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
                qualified_name="normalize_name",
                returns_non_nil=False,
                returns_non_nil_from_args=(1,),
                applies_in_modules=("user.profile",),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()


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
