from __future__ import annotations

import json
from pathlib import Path

from lua_nil_guard.service import bootstrap_repository, run_repository_review


def _write_review_config(tmp_path: Path, sink_rules: list[dict[str, object]]) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(sink_rules),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )


def test_run_repository_review_produces_verified_risk_for_locally_proven_nil_sink(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky"
    assert verdicts[0].confidence == "high"
    assert verdicts[0].verification_summary is not None
    assert verdicts[0].verification_summary.mode == "risk_no_guard"


def test_run_repository_review_uses_preprocessor_macro_facts_without_scanning_macro_file(
    tmp_path: Path,
) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "string.find.arg1",
                "kind": "function_arg",
                "qualified_name": "string.find",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "concat.right",
                "kind": "binary_operand",
                "qualified_name": "concat",
                "arg_index": 2,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "pairs.arg1",
                "kind": "function_arg",
                "qualified_name": "pairs",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or {}"],
            },
            {
                "id": "length.operand",
                "kind": "unary_operand",
                "qualified_name": "length",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or {}"],
            },
            {
                "id": "compare.gte.left",
                "kind": "binary_operand",
                "qualified_name": "compare.gte",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x ~= nil"],
            },
            {
                "id": "arithmetic.add.left",
                "kind": "binary_operand",
                "qualified_name": "arithmetic.add",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x ~= nil"],
            },
        ],
    )
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/macros.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "macros.lua").write_text(
        "\n".join(
            [
                "USER_NAME = \"guest\"",
                "SUFFIX = \"!\"",
                "DEFAULT_TABLE = {}",
                "MAX_LEVEL = 0",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "consumer.lua").write_text(
        "\n".join(
            [
                "local prefix = 'hi'",
                "local limit = req.limit",
                "local bonus = req.bonus",
                "local _ = string.find(USER_NAME, '^g')",
                "local __ = prefix .. SUFFIX",
                "for _, item in pairs(DEFAULT_TABLE) do",
                "  local noop = item",
                "end",
                "local size = #DEFAULT_TABLE",
                "local allowed = MAX_LEVEL >= limit",
                "local score = MAX_LEVEL + bonus",
                "return _, __, size, allowed, score",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert snapshot.preprocessor_files == (tmp_path / "src" / "macros.lua",)
    assert snapshot.lua_files == (tmp_path / "src" / "consumer.lua",)
    assert all("macros.lua" not in verdict.case_id for verdict in verdicts)
    assert len(verdicts) == 6
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_uses_explicit_id_preprocessor_macro_facts_to_suppress_member_access_noise(
    tmp_path: Path,
) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "member_access.receiver",
                "kind": "receiver",
                "qualified_name": "member_access",
                "arg_index": 0,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["assert(x)", "if x then ... end"],
            }
        ],
    )
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/id.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "id.lua").write_text(
        "\n".join(
            [
                "AAA = 1",
                "_fid_a = {}",
                "_fid_a.name = 1",
                "_fid_a.id = 2",
                "_fid_alias = _fid_a",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "consumer.lua").write_text(
        "\n".join(
            [
                "function show()",
                "  print(_fid_a.name)",
                "  print(_fid_alias.id)",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert snapshot.preprocessor_files == (tmp_path / "src" / "id.lua",)
    assert snapshot.lua_files == (tmp_path / "src" / "consumer.lua",)
    assert len(verdicts) == 2
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_infers_parent_table_from_dot_assignments_in_id_file(
    tmp_path: Path,
) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "member_access.receiver",
                "kind": "receiver",
                "qualified_name": "member_access",
                "arg_index": 0,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["assert(x)", "if x then ... end"],
            },
            {
                "id": "compare.gte.left",
                "kind": "binary_operand",
                "qualified_name": "binary.gte",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x ~= nil"],
            },
        ],
    )
    (tmp_path / "config" / "function_contracts.json").write_text("[]\n", encoding="utf-8")
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/id.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )

    (tmp_path / "src" / "id.lua").write_text(
        "\n".join(
            [
                "AAA = 0x100",
                "a.b = 1",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "consumer.lua").write_text(
        "\n".join(
            [
                "function show()",
                "  print(a.b)",
                "  if AAA >= 1 then",
                "    return true",
                "  end",
                "  return false",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert snapshot.preprocessor_files == (tmp_path / "src" / "id.lua",)
    assert snapshot.lua_files == (tmp_path / "src" / "consumer.lua",)
    assert verdicts
    assert all(verdict.status.startswith("risky") for verdict in verdicts)

def test_run_repository_review_marks_transitive_cross_file_nil_return_chain_as_risky(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.find.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.find",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "consumer.lua").write_text(
        "\n".join(
            [
                "require(\"user.facade\")",
                "local nickname = user.facade.pick_name(req)",
                "return string.find(nickname, '^vip')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "facade.lua").write_text(
        "\n".join(
            [
                "module(\"user.facade\", package.seeall)",
                "",
                "function pick_name(req)",
                "  return user.lookup.resolve_name(req)",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "lookup.lua").write_text(
        "\n".join(
            [
                "module(\"user.lookup\", package.seeall)",
                "",
                "function resolve_name(req)",
                "  if req.force_nil then",
                "    return nil",
                "  end",
                "  if req.profile then",
                "    return req.profile.display_name",
                "  end",
                "  return req.cached_name",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")
    assert any("no guard before" in part for part in verdicts[0].risk_path)


def test_run_repository_review_uses_guard_contract_to_suppress_member_access_false_positive(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "member_access.receiver",
                    "kind": "receiver",
                    "qualified_name": "member_access",
                    "arg_index": 0,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["assert(x)", "if x then ... end"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_profile",
                    "returns_non_nil": False,
                    "ensures_non_nil_args": [1],
                    "notes": "raises if profile is nil",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local profile = req.profile",
                "assert_profile(profile)",
                "return profile.name",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    profile_verdicts = [verdict for verdict in verdicts if verdict.case_id.endswith(":member_access.receiver")]
    assert any(verdict.status.startswith("risky") for verdict in profile_verdicts)


def test_run_repository_review_uses_return_normalizer_contract_to_suppress_false_positive(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args": [1],
                    "notes": "returns a defaulted non-nil username",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = normalize_name(req.params.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")
    assert any("no guard before" in part for part in verdicts[0].risk_path)
def test_run_repository_review_skips_call_shaped_return_contracts_without_matching_call(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_with_arg_count": 2,
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value, fallback)",
                "  return value or fallback",
                "end",
                "",
                "local username = normalize_name(req.params.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky"


def test_run_repository_review_uses_literal_scoped_return_contract_when_call_matches(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_literal_args": {"2": ["''", "false"]},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value, fallback)",
                "  return value or fallback",
                "end",
                "",
                "local username = normalize_name(req.params.username, '')",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")
    assert any("no guard before" in part for part in verdicts[0].risk_path)


def test_run_repository_review_skips_literal_scoped_return_contract_when_call_differs(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_literal_args": {"2": "''"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value, fallback)",
                "  return value or fallback",
                "end",
                "",
                "local username = normalize_name(req.params.username, fallback_name)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")

def test_run_repository_review_uses_guarded_field_origin_to_suppress_false_positive(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "if req.params.username then",
                "  local username = req.params.username",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")
    assert any("no guard before" in part for part in verdicts[0].risk_path)


def test_run_repository_review_skips_shape_scoped_return_contract_when_call_differs(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_shapes": {"1": "member_access"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
                "",
                "local username = normalize_name(username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")

def test_run_repository_review_skips_root_scoped_return_contract_when_call_differs(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_roots": {"1": "req"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
                "",
                "local username = normalize_name(fallbacks.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")

def test_run_repository_review_skips_prefix_scoped_return_contract_when_call_differs(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_prefixes": {"1": "req.params"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
                "",
                "local username = normalize_name(req.headers.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")

def test_run_repository_review_skips_access_path_scoped_return_contract_when_call_differs(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "required_arg_access_paths": {"1": "req.params.user"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
                "",
                "local username = normalize_name(req.params[token])",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky"

def test_run_repository_review_skips_second_return_slot_when_only_first_is_safe(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil": True,
                    "applies_to_return_slots": [1],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_pair(value)",
                "  return value, nil",
                "end",
                "",
                "local username, tag = normalize_pair(req.params.username)",
                "return string.match(tag, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky"


def test_run_repository_review_uses_return_slot_specific_arg_requirements(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                        "2": [1],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_pair(value, fallback)",
                "  return value or fallback, value",
                "end",
                "",
                "local username, tag = normalize_pair(req.params.username, '')",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_skips_return_slot_when_slot_specific_args_do_not_match(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                        "2": [3],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_pair(value, fallback)",
                "  return value or fallback, value",
                "end",
                "",
                "local username, tag = normalize_pair(req.params.username, '')",
                "return string.match(tag, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_combines_guard_contract_with_return_normalizer(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil_from_args_by_return_slot": {
                        "2": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "2": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function assert_present(value)",
                "  if not value then error('missing') end",
                "end",
                "",
                "function normalize_pair(value, fallback)",
                "  return value, value or fallback",
                "end",
                "",
                "local username = req.params.username",
                "assert_present(username)",
                "local raw, normalized = normalize_pair(username, '')",
                "return string.match(normalized, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_requires_guard_for_return_normalizer_combo(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_pair",
                    "returns_non_nil_from_args_by_return_slot": {
                        "2": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "2": [1],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_pair(value, fallback)",
                "  return value, value or fallback",
                "end",
                "",
                "local username = req.params.username",
                "local raw, normalized = normalize_pair(username, '')",
                "return string.match(normalized, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_proves_two_hop_return_normalizer_chain(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
                {
                    "qualified_name": "wrap_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [1],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
                {
                    "qualified_name": "finalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [1],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
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
                "  local result = value",
                "  return result",
                "end",
                "",
                "function finalize_name(value)",
                "  local result = value",
                "  return result",
                "end",
                "",
                "local username = req.params.username",
                "assert_present(username)",
                "local normalized = normalize_name(username, '')",
                "local wrapped = wrap_name(normalized)",
                "local final = finalize_name(wrapped)",
                "return string.match(final, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_limits_return_normalizer_chain_depth(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
                {
                    "qualified_name": "wrap_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [1],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
                {
                    "qualified_name": "finalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [1],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
                {
                    "qualified_name": "seal_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [1],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
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
                "  local result = value",
                "  result = result",
                "  return result",
                "end",
                "",
                "function finalize_name(value)",
                "  local result = value",
                "  result = result",
                "  return result",
                "end",
                "",
                "function seal_name(value)",
                "  local result = value",
                "  result = result",
                "  return result",
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
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky"


def test_run_repository_review_proves_transparent_wrapper_chain(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
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
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_uses_cross_file_transparent_wrappers(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "assert_present(username)",
                "local normalized = normalize_name(username, '')",
                "local wrapped = wrap_name(normalized)",
                "local final = finalize_name(wrapped)",
                "return string.match(final, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "wrappers.lua").write_text(
        "\n".join(
            [
                "function wrap_name(value)",
                "  return value",
                "end",
                "",
                "function finalize_name(value)",
                "  return value",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_uses_cross_file_defaulting_wrappers_without_contracts(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local final = wrap_name(req.params.username)",
                "return string.match(final, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "wrappers.lua").write_text(
        "\n".join(
            [
                "function wrap_name(value)",
                "  local normalized = value or ''",
                "  return normalized",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_uses_cross_file_fallback_arg_defaulting_wrappers(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local final = wrap_name(req.params.username, '')",
                "return string.match(final, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "wrappers.lua").write_text(
        "\n".join(
            [
                "function wrap_name(value, fallback)",
                "  local normalized = value or fallback",
                "  return normalized",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_limits_transparent_wrapper_chain_depth(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "assert_present",
                    "ensures_non_nil_args": [1],
                },
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil_from_args_by_return_slot": {
                        "1": [2],
                    },
                    "requires_guarded_args_by_return_slot": {
                        "1": [1],
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
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
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")

def test_run_repository_review_skips_sink_expression_contracts_when_role_differs(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_call_roles": ["assignment_origin"],
                    "required_literal_args": {"2": "''"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value, fallback)",
                "  return value or fallback",
                "end",
                "",
                "return string.match(normalize_name(req.params.username, ''), '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status == "risky"

def test_run_repository_review_skips_single_assignment_contracts_for_multi_assignment(
    tmp_path: Path,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text(
        json.dumps(
            [
                {
                    "id": "string.match.arg1",
                    "kind": "function_arg",
                    "qualified_name": "string.match",
                    "arg_index": 1,
                    "nil_sensitive": True,
                    "failure_mode": "runtime_error",
                    "default_severity": "high",
                    "safe_patterns": ["x or ''"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "confidence_policy.json").write_text(
        json.dumps(
            {
                "levels": ["low", "medium", "high"],
                "default_report_min_confidence": "high",
                "default_include_medium_in_audit": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "function_contracts.json").write_text(
        json.dumps(
            [
                {
                    "qualified_name": "normalize_name",
                    "returns_non_nil": True,
                    "applies_to_usage_modes": ["single_assignment"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "function normalize_name(value)",
                "  return value",
                "end",
                "",
                "local username, tag = normalize_name(req.params.username)",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_marks_binary_operand_hazards_as_risky(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "concat.left",
                "kind": "binary_operand",
                "qualified_name": "..",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "compare.gte.left",
                "kind": "binary_operand",
                "qualified_name": ">=",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "arithmetic.add.left",
                "kind": "binary_operand",
                "qualified_name": "+",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local prefix = nil",
                "local threshold = nil",
                "local bonus = nil",
                "local label = prefix .. suffix",
                "local ok = threshold >= limit",
                "local total = bonus + base",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 3
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_suppresses_defaulted_binary_operands(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "concat.left",
                "kind": "binary_operand",
                "qualified_name": "..",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "arithmetic.add.left",
                "kind": "binary_operand",
                "qualified_name": "+",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local safe_name = req.params.name or ''",
                "local safe_bonus = bonus or 0",
                "local label = safe_name .. suffix",
                "local total = safe_bonus + base",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 2
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_supports_extended_string_api_sinks(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "string.lower.arg1",
                "kind": "function_arg",
                "qualified_name": "string.lower",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "string.len.arg1",
                "kind": "function_arg",
                "qualified_name": "string.len",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local raw = nil",
                "local lowered = string.lower(raw)",
                "local count = string.len(raw)",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 2
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_marks_module_style_cross_file_binary_and_direct_call_risks(
    tmp_path: Path,
) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "concat.left",
                "kind": "binary_operand",
                "qualified_name": "..",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "string.find.arg1",
                "kind": "function_arg",
                "qualified_name": "string.find",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
        ],
    )
    (tmp_path / "lib").mkdir()
    (tmp_path / "src" / "consumer.lua").write_text(
        "\n".join(
            [
                "require(\"user.lookup\")",
                "local nickname = user.lookup.resolve_name(req)",
                "local tag = nickname .. '!'",
                "return string.find(user.lookup.resolve_name(req), '^vip')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "lookup.lua").write_text(
        "\n".join(
            [
                "module(\"user.lookup\", package.seeall)",
                "",
                "function resolve_name(req)",
                "  if req.force_nil then",
                "    return nil",
                "  end",
                "  if req.cached_name then",
                "    return req.cached_name",
                "  end",
                "  return req.profile.display_name",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 2
    assert all(verdict.status.startswith("risky") for verdict in verdicts)
    assert any("no guard before" in " ".join(verdict.risk_path) for verdict in verdicts)


def test_run_repository_review_marks_module_style_numeric_binary_risks(
    tmp_path: Path,
) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "arithmetic.add.left",
                "kind": "binary_operand",
                "qualified_name": "+",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "compare.gte.left",
                "kind": "binary_operand",
                "qualified_name": ">=",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
        ],
    )
    (tmp_path / "lib").mkdir()
    (tmp_path / "src" / "consumer.lua").write_text(
        "\n".join(
            [
                "require(\"metrics.score\")",
                "local total = metrics.score.resolve(req) + bonus",
                "if metrics.score.resolve(req) >= limit then",
                "  return total",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "lib" / "score.lua").write_text(
        "\n".join(
            [
                "module(\"metrics.score\", package.seeall)",
                "",
                "function resolve(req)",
                "  if req.missing then",
                "    return nil",
                "  end",
                "  return req.current_score",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 2
    assert all(verdict.status.startswith("risky") for verdict in verdicts)
    assert all(any("no guard before" in part for part in verdict.risk_path) for verdict in verdicts)


def test_run_repository_review_marks_concat_right_hazard_as_risky(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "concat.right",
                "kind": "binary_operand",
                "qualified_name": "..",
                "arg_index": 2,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local suffix = nil",
                "local label = 'x' .. suffix",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 1
    assert verdicts[0].status.startswith("risky")


def test_run_repository_review_marks_remaining_ordered_comparisons_as_risky(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "compare.lt.left",
                "kind": "binary_operand",
                "qualified_name": "<",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "compare.lte.left",
                "kind": "binary_operand",
                "qualified_name": "<=",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "compare.gt.left",
                "kind": "binary_operand",
                "qualified_name": ">",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local score_lt = nil",
                "local score_lte = nil",
                "local score_gt = nil",
                "local is_low = score_lt < limit",
                "local is_low_or_equal = score_lte <= limit",
                "local is_high = score_gt > limit",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 3
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_ignores_equality_comparisons(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "compare.lt.left",
                "kind": "binary_operand",
                "qualified_name": "<",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "compare.lte.left",
                "kind": "binary_operand",
                "qualified_name": "<=",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "compare.gt.left",
                "kind": "binary_operand",
                "qualified_name": ">",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "compare.gte.left",
                "kind": "binary_operand",
                "qualified_name": ">=",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local score = nil",
                "local same = score == limit",
                "local changed = score ~= limit",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert verdicts == ()


def test_run_repository_review_marks_remaining_arithmetic_hazards_as_risky(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "arithmetic.sub.left",
                "kind": "binary_operand",
                "qualified_name": "-",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "arithmetic.mul.left",
                "kind": "binary_operand",
                "qualified_name": "*",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "arithmetic.div.left",
                "kind": "binary_operand",
                "qualified_name": "/",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "arithmetic.mod.left",
                "kind": "binary_operand",
                "qualified_name": "%",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
            {
                "id": "arithmetic.pow.left",
                "kind": "binary_operand",
                "qualified_name": "^",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or 0"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local delta = nil",
                "local factor = nil",
                "local ratio = nil",
                "local remainder = nil",
                "local exponent = nil",
                "local diff = delta - base",
                "local scaled = factor * base",
                "local share = ratio / base",
                "local modded = remainder % base",
                "local power = exponent ^ base",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 5
    assert all(verdict.status.startswith("risky") for verdict in verdicts)


def test_run_repository_review_supports_remaining_extended_string_api_sinks(tmp_path: Path) -> None:
    _write_review_config(
        tmp_path,
        [
            {
                "id": "string.sub.arg1",
                "kind": "function_arg",
                "qualified_name": "string.sub",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "string.byte.arg1",
                "kind": "function_arg",
                "qualified_name": "string.byte",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
            {
                "id": "string.upper.arg1",
                "kind": "function_arg",
                "qualified_name": "string.upper",
                "arg_index": 1,
                "nil_sensitive": True,
                "failure_mode": "runtime_error",
                "default_severity": "high",
                "safe_patterns": ["x or ''"],
            },
        ],
    )
    (tmp_path / "src" / "demo.lua").write_text(
        "\n".join(
            [
                "local raw = nil",
                "local sliced = string.sub(raw, 1, 2)",
                "local code = string.byte(raw)",
                "local loud = string.upper(raw)",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    verdicts = run_repository_review(snapshot)

    assert len(verdicts) == 3
    assert all(verdict.status.startswith("risky") for verdict in verdicts)
