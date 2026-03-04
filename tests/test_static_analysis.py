from __future__ import annotations

from lua_nil_guard.models import CandidateCase, FunctionContract, MacroFact, MacroIndex
from lua_nil_guard.parser_backend import get_parser_backend_info
from lua_nil_guard.static_analysis import analyze_candidate


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
    assert len(result.proofs) == 1
    assert result.proofs[0].kind == "direct_guard"
    assert result.proofs[0].subject == "username"
    assert result.proofs[0].provenance == ("an active positive branch requires `username` to be truthy",)
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


def test_analyze_candidate_uses_macro_fact_to_suppress_member_access_nil_receiver() -> None:
    source = "return _fid_a.name"
    candidate = CandidateCase(
        case_id="case_macro_receiver",
        file="demo.lua",
        line=1,
        column=8,
        sink_rule_id="member_access.receiver",
        sink_name="member_access",
        arg_index=0,
        expression="_fid_a",
        symbol="_fid_a",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(
        source,
        candidate,
        macro_index=MacroIndex(
            facts=(
                MacroFact(
                    key="_fid_a",
                    kind="empty_table",
                    value="{}",
                    provably_non_nil=True,
                    file="src/id.lua",
                    line=1,
                ),
            )
        ),
    )

    assert result.state == "safe_static"
    assert result.proofs
    assert result.proofs[0].kind == "macro_fact_guard"
    assert "_fid_a" in result.proofs[0].summary


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


def test_analyze_candidate_combines_field_guard_contract_with_return_normalizer() -> None:
    source = "\n".join(
        [
            "assert_present(req.params.username)",
            "local raw, normalized = normalize_pair(req.params.username, '')",
            "return string.match(normalized, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_field_guarded_return_combo",
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


def test_analyze_candidate_proves_two_hop_return_normalizer_chain() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username)",
            "local normalized = normalize_name(username, '')",
            "local wrapped = wrap_name(normalized)",
            "local final = finalize_name(wrapped)",
            "return string.match(final, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_two_hop_return_chain",
        file="demo.lua",
        line=6,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="final",
        symbol="final",
        function_scope="main",
        static_state="unknown_static",
    )

    common_normalizer = dict(
        returns_non_nil=False,
        returns_non_nil_from_args_by_return_slot=((1, (1,)),),
        requires_guarded_args_by_return_slot=((1, (1,)),),
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
                qualified_name="normalize_name",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((1, (2,)),),
                requires_guarded_args_by_return_slot=((1, (1,)),),
            ),
            FunctionContract(qualified_name="wrap_name", **common_normalizer),
            FunctionContract(qualified_name="finalize_name", **common_normalizer),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("finalize_name(...) returns non-nil",)
    assert len(result.proofs) == 1
    assert result.proofs[0].kind == "chained_return_contract"
    assert result.proofs[0].source_function == "finalize_name"
    assert result.proofs[0].supporting_summaries == ("wrap_name(...) returns non-nil",)
    assert result.proofs[0].depth >= 2
    assert result.proofs[0].provenance
    assert result.origin_candidates == ("finalize_name(wrapped)",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_limits_return_normalizer_chain_depth() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "assert_present(username)",
            "local normalized = normalize_name(username, '')",
            "local wrapped = wrap_name(normalized)",
            "local final = finalize_name(wrapped)",
            "local sealed = seal_name(final)",
            "return string.match(sealed, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_three_hop_return_chain",
        file="demo.lua",
        line=7,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="sealed",
        symbol="sealed",
        function_scope="main",
        static_state="unknown_static",
    )

    common_normalizer = dict(
        returns_non_nil=False,
        returns_non_nil_from_args_by_return_slot=((1, (1,)),),
        requires_guarded_args_by_return_slot=((1, (1,)),),
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
                qualified_name="normalize_name",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((1, (2,)),),
                requires_guarded_args_by_return_slot=((1, (1,)),),
            ),
            FunctionContract(qualified_name="wrap_name", **common_normalizer),
            FunctionContract(qualified_name="finalize_name", **common_normalizer),
            FunctionContract(qualified_name="seal_name", **common_normalizer),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("seal_name(final)",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_proves_transparent_wrapper_chain() -> None:
    source = "\n".join(
        [
            "function assert_present(value)",
            "  if not value then error('missing') end",
            "end",
            "",
            "function normalize_name(value, fallback)",
            "  return value or fallback",
            "end",
            "",
            "function wrap_name(value)",
            "  return value",
            "end",
            "",
            "function finalize_name(value)",
            "  return value",
            "end",
            "",
            "local username = req.params.username",
            "assert_present(username)",
            "local normalized = normalize_name(username, '')",
            "local wrapped = wrap_name(normalized)",
            "local final = finalize_name(wrapped)",
            "return string.match(final, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_transparent_wrapper_chain",
        file="demo.lua",
        line=22,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="final",
        symbol="final",
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
                qualified_name="normalize_name",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((1, (2,)),),
                requires_guarded_args_by_return_slot=((1, (1,)),),
            ),
        ),
    )

    assert result.state == "safe_static"
    assert result.observed_guards == ("finalize_name(...) preserves or defaults to non-nil",)
    assert len(result.proofs) == 1
    assert result.proofs[0].kind == "wrapper_passthrough"
    assert result.proofs[0].source_function == "finalize_name"
    assert result.proofs[0].supporting_summaries == ("wrap_name(...) preserves or defaults to non-nil",)
    assert result.proofs[0].provenance
    assert result.origin_candidates == ("finalize_name(wrapped)",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_proves_defaulting_wrapper_without_contract() -> None:
    source = "\n".join(
        [
            "function wrap_name(value)",
            "  local normalized = value or ''",
            "  return normalized",
            "end",
            "",
            "local final = wrap_name(req.params.username)",
            "return string.match(final, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_defaulting_wrapper_without_contract",
        file="demo.lua",
        line=7,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="final",
        symbol="final",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    assert result.observed_guards == ("wrap_name(...) preserves or defaults to non-nil",)
    assert result.origin_candidates == ("wrap_name(req.params.username)",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_proves_reassigned_defaulting_multi_return_wrapper_without_contract() -> None:
    source = "\n".join(
        [
            "function normalize_pair(value)",
            "  value = value or 'guest'",
            "  return value, 'fallback'",
            "end",
            "",
            "local final, tag = normalize_pair(req.params.username)",
            "return string.match(final, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_reassigned_defaulting_multi_return_wrapper",
        file="demo.lua",
        line=7,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="final",
        symbol="final",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    assert result.observed_guards == ("normalize_pair(...) preserves or defaults to non-nil",)
    assert result.origin_candidates == ("normalize_pair(req.params.username)",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_proves_fallback_arg_defaulting_wrapper_without_contract() -> None:
    source = "\n".join(
        [
            "function wrap_name(value, fallback)",
            "  local normalized = value or fallback",
            "  return normalized",
            "end",
            "",
            "local final = wrap_name(req.params.username, '')",
            "return string.match(final, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_fallback_arg_defaulting_wrapper_without_contract",
        file="demo.lua",
        line=7,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="final",
        symbol="final",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    assert result.observed_guards == ("wrap_name(...) preserves or defaults to non-nil",)
    assert result.origin_candidates == ("wrap_name(req.params.username, '')",)
    assert result.origin_return_slots == (1,)


def test_analyze_candidate_limits_transparent_wrapper_chain_depth() -> None:
    source = "\n".join(
        [
            "function assert_present(value)",
            "  if not value then error('missing') end",
            "end",
            "",
            "function normalize_name(value, fallback)",
            "  return value or fallback",
            "end",
            "",
            "function wrap_name(value)",
            "  return value",
            "end",
            "",
            "function finalize_name(value)",
            "  return value",
            "end",
            "",
            "function seal_name(value)",
            "  return value",
            "end",
            "",
            "local username = req.params.username",
            "assert_present(username)",
            "local normalized = normalize_name(username, '')",
            "local wrapped = wrap_name(normalized)",
            "local final = finalize_name(wrapped)",
            "local sealed = seal_name(final)",
            "return string.match(sealed, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_transparent_wrapper_chain_depth",
        file="demo.lua",
        line=27,
        column=8,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="sealed",
        symbol="sealed",
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
                qualified_name="normalize_name",
                returns_non_nil=False,
                returns_non_nil_from_args_by_return_slot=((1, (2,)),),
                requires_guarded_args_by_return_slot=((1, (1,)),),
            ),
        ),
    )

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.origin_candidates == ("seal_name(final)",)
    assert result.origin_return_slots == (1,)


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


def test_analyze_candidate_ast_preserves_guard_across_shadowed_do_block() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  do",
            "    local username = nil",
            "    log(username)",
            "  end",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_shadow",
        file="demo.lua",
        line=7,
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

    if get_parser_backend_info().tree_sitter_available:
        assert result.state == "safe_static"
        assert result.analysis_mode == "ast_primary"
        assert result.observed_guards == ("if username then",)
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_marks_loop_control_as_structured_unknown_when_ast_runs() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "for i = 1, 3 do",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_unknown",
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

    assert result.state == "unknown_static"
    if get_parser_backend_info().tree_sitter_available:
        assert result.analysis_mode == "ast_fallback_to_legacy"
        assert result.unknown_reason == "unsupported_control_flow"
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_marks_loop_break_guard_safe_when_ast_runs() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "while true do",
            "  if not username then",
            "    break",
            "  end",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_loop_break_guard",
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

    if get_parser_backend_info().tree_sitter_available:
        assert result.state == "safe_static"
        assert result.analysis_mode == "ast_primary"
        assert result.unknown_reason is None
        assert "if not username then break" in result.observed_guards
        assert any(proof.kind == "loop_break_guard" for proof in result.proofs)
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_allows_bounded_pairs_header_origin_proof() -> None:
    source = "\n".join(
        [
            "local items = req.items or {}",
            "for _, item in pairs(items) do",
            "  return item",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_pairs_header_origin",
        file="demo.lua",
        line=2,
        column=22,
        sink_rule_id="pairs.arg1",
        sink_name="pairs",
        arg_index=1,
        expression="items",
        symbol="items",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    if get_parser_backend_info().tree_sitter_available:
        assert result.state == "safe_static"
        assert result.unknown_reason is None
        assert result.origin_candidates == ("req.items or {}",)
        assert "items = items or ..." in result.observed_guards
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_marks_unproved_ast_case_with_structured_no_bounded_reason() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if ready then",
            "  log('ready')",
            "end",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_no_bounded_proof",
        file="demo.lua",
        line=5,
        column=21,
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
    if get_parser_backend_info().tree_sitter_available:
        assert result.analysis_mode == "ast_fallback_to_legacy"
        assert result.unknown_reason == "no_bounded_ast_proof"
        assert result.origin_analysis_mode == "ast_origin_primary"
        assert result.origin_unknown_reason is None
        assert result.origin_candidates == ("req.params.username",)
    else:
        assert result.analysis_mode == "legacy_only"
        assert result.origin_analysis_mode == "legacy_origin_only"


def test_analyze_candidate_marks_negative_guard_else_branch_safe_when_ast_runs() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if not username then",
            "  return",
            "else",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_negative_else_guard",
        file="demo.lua",
        line=5,
        column=23,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    if get_parser_backend_info().tree_sitter_available:
        assert result.state == "safe_static"
        assert result.analysis_mode == "ast_primary"
        assert result.unknown_reason is None
        assert "if not username then return" in result.observed_guards
        assert any(proof.kind == "early_exit_guard" for proof in result.proofs)
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_marks_nested_upvalue_capture_as_structured_unknown() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "local function render()",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_upvalue",
        file="demo.lua",
        line=3,
        column=23,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="render",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "unknown_static"
    if get_parser_backend_info().tree_sitter_available:
        assert result.analysis_mode == "ast_fallback_to_legacy"
        assert result.unknown_reason == "upvalue_capture"
        assert result.origin_analysis_mode == "ast_origin_fallback_to_legacy"
        assert result.origin_unknown_reason == "upvalue_capture"
    else:
        assert result.analysis_mode == "legacy_only"
        assert result.origin_analysis_mode == "legacy_origin_only"


def test_analyze_candidate_marks_elseif_guard_safe_when_ast_runs() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "if ready then",
            "  log('ready')",
            "elseif username then",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_elseif",
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

    if get_parser_backend_info().tree_sitter_available:
        assert result.state == "safe_static"
        assert result.analysis_mode == "ast_primary"
        assert result.observed_guards == ("if username then",)
        assert any(proof.kind == "direct_guard" for proof in result.proofs)
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_marks_repeat_until_guard_safe_when_ast_runs() -> None:
    source = "\n".join(
        [
            "local username = nil",
            "repeat",
            "  username = req.params.username",
            "until username",
            "return string.match(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_ast_repeat",
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

    if get_parser_backend_info().tree_sitter_available:
        assert result.state == "safe_static"
        assert result.analysis_mode == "ast_primary"
        assert result.observed_guards == ("repeat ... until username",)
        assert any(proof.kind == "loop_exit_guard" for proof in result.proofs)
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_tracks_direct_field_path_guard() -> None:
    source = "\n".join(
        [
            "if req.params.username then",
            "  return string.match(req.params.username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_field_guard",
        file="demo.lua",
        line=2,
        column=23,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="req.params.username",
        symbol="req.params.username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    assert result.observed_guards == ("if req.params.username then",)
    if get_parser_backend_info().tree_sitter_available:
        assert result.analysis_mode == "ast_primary"
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_normalizes_bracket_field_paths_for_guards() -> None:
    source = "\n".join(
        [
            "if req.headers['x-token'] then",
            "  return string.match(req.headers[\"x-token\"], '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_field_bracket_guard",
        file="demo.lua",
        line=2,
        column=23,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression='req.headers["x-token"]',
        symbol='req.headers["x-token"]',
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "safe_static"
    if get_parser_backend_info().tree_sitter_available:
        assert result.analysis_mode == "ast_primary"
    else:
        assert result.analysis_mode == "legacy_only"


def test_analyze_candidate_emits_direct_field_path_risk_signal() -> None:
    source = "return string.match(req.params.username, '^a')"
    candidate = CandidateCase(
        case_id="case_direct_field_path_risk",
        file="demo.lua",
        line=1,
        column=21,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="req.params.username",
        symbol="req.params.username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.risk_signals
    assert result.risk_signals[0].kind == "direct_sink_field_path"
    assert result.risk_signals[0].summary == "req.params.username reaches string.match directly"


def test_analyze_candidate_proves_local_from_guarded_field_origin_safe() -> None:
    source = "\n".join(
        [
            "if req.params.username then",
            "  local username = req.params.username",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    candidate = CandidateCase(
        case_id="case_guarded_field_origin",
        file="demo.lua",
        line=3,
        column=23,
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
    assert result.observed_guards == ("username inherits non-nil from req.params.username",)
    assert any(proof.kind == "guarded_field_origin" for proof in result.proofs)


def test_analyze_candidate_emits_unguarded_field_origin_risk_signal() -> None:
    source = "\n".join(
        [
            "local username = req.params.username",
            "return string.find(username, '^a')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_unguarded_field_origin_risk",
        file="demo.lua",
        line=2,
        column=20,
        sink_rule_id="string.find.arg1",
        sink_name="string.find",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="main",
        static_state="unknown_static",
    )

    result = analyze_candidate(source, candidate)

    assert result.state == "unknown_static"
    assert result.observed_guards == ()
    assert result.risk_signals
    assert result.risk_signals[0].kind == "unguarded_field_origin"
    assert result.risk_signals[0].summary == "username may inherit nil from req.params.username"


def test_analyze_candidate_emits_wrapper_field_path_risk_signal() -> None:
    source = "\n".join(
        [
            "local function passthrough_name(value)",
            "  return value",
            "end",
            "",
            "local display_name = passthrough_name(req.params.display_name)",
            "return string.match(display_name, '^guest')",
        ]
    )
    candidate = CandidateCase(
        case_id="case_wrapper_field_path_risk",
        file="demo.lua",
        line=6,
        column=21,
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
    assert result.risk_signals
    assert result.risk_signals[0].kind == "wrapper_field_path_risk"
    assert result.risk_signals[0].summary == "display_name may inherit nil via passthrough_name(...)"
