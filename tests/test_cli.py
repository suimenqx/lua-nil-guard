from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

import lua_nil_guard.cli as cli_module
from lua_nil_guard.agent_backend import BackendError
from lua_nil_guard.cli import run
from lua_nil_guard.models import (
    AdjudicationRecord,
    BenchmarkCacheComparison,
    BenchmarkSummary,
    ImprovementAnalytics,
    ImprovementProposal,
    RoleOpinion,
    Verdict,
)
from lua_nil_guard.parser_backend import ParserBackendInfo


def test_cli_help_lists_supported_backends() -> None:
    exit_code, output = run(["--help"])

    assert exit_code == 0
    assert "doctor" in output
    assert "Backend values: heuristic | codex | claude | gemini" in output
    assert "init-config" in output
    assert "macro-audit" in output
    assert "macro-audit-json" in output
    assert "macro-build-cache" in output
    assert "macro-build-cache-json" in output
    assert "macro-cache-status" in output
    assert "macro-cache-status-json" in output
    assert "generate-backend-manifest" in output
    assert "scan-file" in output
    assert "report-file" in output
    assert "report-file-json" in output
    assert "--allow-skill-fallback" in output
    assert "--backend-executable PATH" in output
    assert "--backend-manifest PATH" in output
    assert "--backend-timeout SECONDS" in output
    assert "--backend-attempts N" in output
    assert "--expanded-evidence-retry MODE" in output
    assert "--backend-cache PATH" in output
    assert "--backend-config KEY=VALUE" in output
    assert "--focus MODE" in output
    assert "Focus values: all | string" in output
    assert "encoding-audit" in output
    assert "normalize-encoding" in output
    assert "benchmark" in output
    assert "export-autofix" in output
    assert "apply-autofix" in output
    assert "export-unified-diff" in output
    assert "clear-backend-cache" in output
    assert "validate-backend-manifest" in output
    assert "validate-backend-manifest-json" in output
    assert "register-backend-manifest" in output
    assert "register-backend-manifest-json" in output
    assert "benchmark-cache-compare" in output
    assert "benchmark-json" in output
    assert "benchmark-cache-compare-json" in output
    assert "compare-benchmark-json" in output
    assert "proposal-export" in output
    assert "proposal-export-json" in output
    assert "proposal-analytics" in output
    assert "proposal-analytics-json" in output
    assert "run-start" in output
    assert "run-resume" in output
    assert "run-status" in output
    assert "run-report" in output
    assert "run-export-json" in output


def test_cli_scan_reports_static_summary(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "if username then",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["scan", str(tmp_path)])

    assert exit_code == 0
    assert "Lua Nil Review Static Summary" in output
    assert "Parser backend: tree_sitter_local" in output
    assert "Parser detail:" in output
    assert "Total candidates: 1" in output
    assert "safe_static: 1" in output


def test_cli_scan_supports_string_focus_filter(tmp_path: Path) -> None:
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
                },
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
                "local username = req.params.username",
                "local score = req.params.score",
                "return string.match(username, '^a'), score < 10",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["scan", str(tmp_path)])

    assert exit_code == 0
    assert "Focus mode: all" in output
    assert "Total candidates: 2" in output

    exit_code, output = run(["scan", "--focus", "string", str(tmp_path)])

    assert exit_code == 0
    assert "Focus mode: string" in output
    assert "Total candidates: 1" in output


def test_cli_run_start_status_and_resume(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "if username then",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    run_db = tmp_path / "run-store.sqlite3"

    exit_code, output = run(["run-start", "--run-db", str(run_db), str(tmp_path)])
    assert exit_code == 0
    assert "Run ID:" in output
    assert "Run Status: completed" in output

    run_id_line = next(line for line in output.splitlines() if line.startswith("Run ID: "))
    run_id = int(run_id_line.split(":", 1)[1].strip())

    exit_code, status_output = run(
        ["run-status", "--run-db", str(run_db), str(tmp_path), str(run_id)]
    )
    assert exit_code == 0
    assert f"Run ID: {run_id}" in status_output
    assert "Status: completed" in status_output
    assert "AST exact candidates:" in status_output
    assert "LLM processed cases:" in status_output
    assert "Stage metrics:" in status_output
    assert "Unknown reasons:" in status_output

    exit_code, resume_output = run(
        ["run-resume", "--run-db", str(run_db), str(tmp_path), str(run_id)]
    )
    assert exit_code == 0
    assert f"Run ID: {run_id}" in resume_output
    assert "Run Status: completed" in resume_output

    exit_code, run_report_output = run(
        ["run-report", "--run-db", str(run_db), str(tmp_path), str(run_id)]
    )
    assert exit_code == 0
    assert f"Run ID: {run_id}" in run_report_output
    assert "# Lua Nil Guard Run Status" in run_report_output
    assert "Stage metrics:" in run_report_output
    assert "# Lua Nil Risk Report" in run_report_output

    json_output = tmp_path / "run-report.json"
    exit_code, export_output = run(
        [
            "run-export-json",
            "--run-db",
            str(run_db),
            str(tmp_path),
            str(run_id),
            str(json_output),
        ]
    )
    assert exit_code == 0
    assert "Run JSON export complete." in export_output
    exported_payload = json.loads(json_output.read_text(encoding="utf-8"))
    assert isinstance(exported_payload, dict)
    assert "run" in exported_payload
    assert "findings" in exported_payload
    assert isinstance(exported_payload["findings"], list)
    run_payload = exported_payload["run"]
    assert run_payload["run_id"] == run_id
    assert "stage_metrics" in run_payload
    assert "unknown_reason_distribution" in run_payload


def test_cli_doctor_reports_parser_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_module,
        "get_parser_backend_info",
        lambda: ParserBackendInfo(
            name="unavailable",
            tree_sitter_available=False,
            reason="tree_sitter Python package not installed",
            selected_compiler="gcc (/usr/bin/gcc)",
            local_library_path=None,
            tree_sitter_python_available=False,
        ),
    )

    exit_code, output = run(["doctor"])

    assert exit_code == 0
    assert "Lua Nil Guard Doctor" in output
    assert "Parser backend: unavailable" in output
    assert "Status: tree_sitter Python package not installed" in output
    assert "Detected compiler: gcc (/usr/bin/gcc)" in output
    assert "macro-cache-status <repository>" in output


def test_cli_scan_requires_tree_sitter_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "get_parser_backend_info",
        lambda: ParserBackendInfo(
            name="unavailable",
            tree_sitter_available=False,
            reason="tree_sitter Python package not installed",
            selected_compiler="gcc (/usr/bin/gcc)",
            local_library_path=None,
            tree_sitter_python_available=False,
        ),
    )

    exit_code, output = run(["scan", str(tmp_path)])

    assert exit_code == 2
    assert "Tree-sitter is required for analysis commands." in output
    assert "Run `lua-nil-guard doctor`" in output


def test_cli_report_rejects_lua_file_path_with_single_file_hint(tmp_path: Path) -> None:
    file_path = tmp_path / "demo.lua"
    file_path.write_text("return string.match(name, '^a')\n", encoding="utf-8")

    exit_code, output = run(["report", str(file_path)])

    assert exit_code == 2
    assert "repository root directory" in output
    assert "report-file" in output


def test_cli_report_file_names_non_utf8_dependency_file(tmp_path: Path) -> None:
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
    target_file = tmp_path / "src" / "demo.lua"
    target_file.write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    bad_file = tmp_path / "src" / "legacy.lua"
    bad_file.write_bytes(b"local value = '\xbd'\n")

    exit_code, output = run(["report-file", str(target_file)])

    assert exit_code == 2
    assert str(bad_file) in output
    assert "not valid UTF-8" in output


def test_cli_scan_file_reports_static_summary(tmp_path: Path) -> None:
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
    file_path = tmp_path / "src" / "demo.lua"
    file_path.write_text(
        "\n".join(
            [
                "local username = req.params.username",
                "if username then",
                "  return string.match(username, '^a')",
                "end",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["scan-file", str(file_path)])

    assert exit_code == 0
    assert "Lua Nil Review Static Summary" in output
    assert f"Target file: {file_path}" in output
    assert "Total candidates: 1" in output
    assert "safe_static: 1" in output


def test_cli_init_config_writes_default_templates(tmp_path: Path) -> None:
    exit_code, output = run(["init-config", str(tmp_path)])

    sink_path = tmp_path / "config" / "sink_rules.json"
    policy_path = tmp_path / "config" / "confidence_policy.json"
    contracts_path = tmp_path / "config" / "function_contracts.json"
    preprocessor_path = tmp_path / "config" / "preprocessor_files.json"
    sink_payload = json.loads(sink_path.read_text(encoding="utf-8"))
    policy_payload = json.loads(policy_path.read_text(encoding="utf-8"))
    contracts_payload = json.loads(contracts_path.read_text(encoding="utf-8"))
    preprocessor_payload = json.loads(preprocessor_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "Repository config initialized." in output
    assert f"Sink rules: {sink_path}" in output
    assert f"Confidence policy: {policy_path}" in output
    assert f"Function contracts: {contracts_path}" in output
    assert f"Preprocessor config: {preprocessor_path}" in output
    assert any(rule["id"] == "string.match.arg1" for rule in sink_payload)
    assert policy_payload["default_report_min_confidence"] == "high"
    assert contracts_payload == []
    assert preprocessor_payload == {
        "preprocessor_files": [],
        "preprocessor_globs": ["id.lua", "*_id.lua"],
    }


def test_cli_init_config_preserves_existing_files_and_backfills_missing_templates(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    sink_path = config_dir / "sink_rules.json"
    policy_path = config_dir / "confidence_policy.json"
    contracts_path = config_dir / "function_contracts.json"
    preprocessor_path = config_dir / "preprocessor_files.json"
    sink_path.write_text("[]", encoding="utf-8")
    policy_path.write_text("{}", encoding="utf-8")
    contracts_path.write_text("[]", encoding="utf-8")

    exit_code, output = run(["init-config", str(tmp_path)])

    assert exit_code == 0
    assert "Repository config initialized." in output
    assert sink_path.read_text(encoding="utf-8") == "[]"
    assert policy_path.read_text(encoding="utf-8") == "{}"
    assert contracts_path.read_text(encoding="utf-8") == "[]"
    assert json.loads(preprocessor_path.read_text(encoding="utf-8")) == {
        "preprocessor_files": [],
        "preprocessor_globs": ["id.lua", "*_id.lua"],
    }


def test_cli_init_config_force_overwrites_existing_files(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    sink_path = config_dir / "sink_rules.json"
    policy_path = config_dir / "confidence_policy.json"
    contracts_path = config_dir / "function_contracts.json"
    preprocessor_path = config_dir / "preprocessor_files.json"
    sink_path.write_text("[]", encoding="utf-8")
    policy_path.write_text("{}", encoding="utf-8")
    contracts_path.write_text("{}", encoding="utf-8")
    preprocessor_path.write_text("{}", encoding="utf-8")

    exit_code, output = run(["init-config", "--force", str(tmp_path)])

    sink_payload = json.loads(sink_path.read_text(encoding="utf-8"))
    policy_payload = json.loads(policy_path.read_text(encoding="utf-8"))
    contracts_payload = json.loads(contracts_path.read_text(encoding="utf-8"))
    preprocessor_payload = json.loads(preprocessor_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "Force overwrite: yes" in output
    assert any(rule["id"] == "string.match.arg1" for rule in sink_payload)
    assert policy_payload["default_report_min_confidence"] == "high"
    assert contracts_payload == []
    assert preprocessor_payload == {
        "preprocessor_files": [],
        "preprocessor_globs": ["id.lua", "*_id.lua"],
    }


def test_cli_encoding_audit_reports_convertible_and_unsupported_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    utf8_file = tmp_path / "src" / "utf8.lua"
    gb_file = tmp_path / "src" / "legacy.lua"
    bad_file = tmp_path / "src" / "broken.lua"
    utf8_file.write_text("return 'ok'\n", encoding="utf-8")
    gb_file.write_bytes("return '中文'\n".encode("gb18030"))
    bad_file.write_bytes(b"return '\xbd'\n")

    exit_code, output = run(["encoding-audit", str(tmp_path)])

    assert exit_code == 0
    assert "Lua Source Encoding Audit" in output
    assert "UTF-8 compliant: 1" in output
    assert "Needs normalization: 1" in output
    assert "Unsupported encoding: 1" in output
    assert f"{gb_file} (gb18030)" in output
    assert str(bad_file) in output


def test_cli_macro_audit_reports_resolved_and_unresolved_macro_lines(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/macros.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "macros.lua").write_text(
        "\n".join(
            [
                "USER_NAME = \"guest\"",
                "BROKEN = some_call()",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.lua").write_text("return nil\n", encoding="utf-8")

    exit_code, output = run(["macro-audit", str(tmp_path)])

    assert exit_code == 0
    assert "Preprocessor Macro Audit" in output
    assert "Configured macro files: 1" in output
    assert "Resolved macro facts: 1" in output
    assert "Unresolved lines: 1" in output
    assert "USER_NAME" in output
    assert "unsupported_value_syntax" in output


def test_cli_macro_audit_json_renders_structured_payload(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/macros.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "macros.lua").write_text("MAX_LEVEL = 100\n", encoding="utf-8")
    (tmp_path / "src" / "demo.lua").write_text("return nil\n", encoding="utf-8")

    exit_code, output = run(["macro-audit-json", str(tmp_path)])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["total_files"] == 1
    assert payload["total_facts"] == 1
    assert payload["facts"][0]["key"] == "MAX_LEVEL"


def test_cli_macro_build_cache_and_status_report_compiled_cache(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/macros.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "macros.lua").write_text("MAX_LEVEL = 100\n", encoding="utf-8")
    (tmp_path / "src" / "demo.lua").write_text("return nil\n", encoding="utf-8")

    exit_code, output = run(["macro-build-cache", str(tmp_path)])

    assert exit_code == 0
    assert "Preprocessor Macro Cache Status" in output
    assert "State: rebuilt" in output
    assert "Resolved macro facts: 1" in output

    exit_code, output = run(["macro-cache-status", str(tmp_path)])

    assert exit_code == 0
    assert "State: fresh" in output
    assert "Configured macro files: 1" in output


def test_cli_macro_cache_status_json_reports_missing_cache(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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
    (tmp_path / "config" / "preprocessor_files.json").write_text(
        json.dumps({"preprocessor_files": ["src/macros.lua"], "preprocessor_globs": []}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "macros.lua").write_text("MAX_LEVEL = 100\n", encoding="utf-8")
    (tmp_path / "src" / "demo.lua").write_text("return nil\n", encoding="utf-8")

    exit_code, output = run(["macro-cache-status-json", str(tmp_path)])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["state"] == "missing"
    assert payload["file_count"] == 1


def test_cli_normalize_encoding_dry_run_and_write(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    gb_file = tmp_path / "src" / "legacy.lua"
    gb_file.write_bytes("return '中文'\n".encode("gb18030"))

    exit_code, output = run(["normalize-encoding", str(tmp_path)])

    assert exit_code == 0
    assert "Mode: dry-run" in output
    assert "Would convert: 1" in output
    assert f"{gb_file} (gb18030 -> utf-8)" in output
    assert gb_file.read_bytes() == "return '中文'\n".encode("gb18030")

    exit_code, output = run(["normalize-encoding", "--write", str(tmp_path)])

    assert exit_code == 0
    assert "Mode: write" in output
    assert "Converted: 1" in output
    assert gb_file.read_text(encoding="utf-8") == "return '中文'\n"


def test_cli_clear_backend_cache_removes_cache_file(tmp_path: Path) -> None:
    cache_path = tmp_path / "codex-cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "entry-1": {"judge": {"status": "safe"}},
                "entry-2": {"judge": {"status": "uncertain"}},
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["clear-backend-cache", str(cache_path)])

    assert exit_code == 0
    assert "Backend cache cleared." in output
    assert "Removed entries: 2" in output
    assert not cache_path.exists()


def test_cli_generate_backend_manifest_renders_template_json() -> None:
    exit_code, output = run(["generate-backend-manifest", "sample-agent", "stdout_envelope_cli"])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["name"] == "sample-agent"
    assert payload["protocol"] == "stdout_envelope_cli"
    assert payload["default_expanded_evidence_retry_mode"] == "auto"
    assert payload["capabilities"]["supports_stdout_json"] is True


def test_cli_generate_backend_manifest_writes_output_file(tmp_path: Path) -> None:
    output_path = tmp_path / "provider.json"

    exit_code, output = run(
        [
            "generate-backend-manifest",
            "sample-agent",
            "schema_file_cli",
            str(output_path),
        ]
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "Backend manifest template generated." in output
    assert payload["protocol"] == "schema_file_cli"
    assert payload["capabilities"]["supports_output_schema"] is True
    assert payload["default_expanded_evidence_retry_mode"] == "auto"


def test_cli_generate_backend_manifest_rejects_unknown_protocol() -> None:
    exit_code, output = run(["generate-backend-manifest", "sample-agent", "sdk_api"])

    assert exit_code == 2
    assert output.startswith("Unknown provider manifest protocol: sdk_api")


def test_cli_validate_backend_manifest_reports_summary(tmp_path: Path) -> None:
    manifest_path = tmp_path / "provider.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "claude-code",
                "protocol": "stdout_envelope_cli",
                "default_executable": "claude-code",
                "default_timeout_seconds": 30.0,
                "default_max_attempts": 2,
                "default_fallback_to_uncertain_on_error": True,
                "default_expanded_evidence_retry_mode": "off",
                "capabilities": {
                    "supports_model_override": True,
                    "supports_config_overrides": True,
                    "supports_stdout_json": True,
                },
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["validate-backend-manifest", str(manifest_path)])

    assert exit_code == 0
    assert "Backend manifest valid." in output
    assert f"Manifest: {manifest_path}" in output
    assert "Name: claude-code" in output
    assert "Protocol: stdout_envelope_cli" in output
    assert "Protocol backend: CodeAgentCliBackend" in output
    assert "Runtime compatibility: supported" in output
    assert "Default expanded evidence retry: off" in output


def test_cli_validate_backend_manifest_rejects_unsupported_protocol(tmp_path: Path) -> None:
    manifest_path = tmp_path / "provider.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "claude-sdk",
                "protocol": "sdk_api",
                "default_executable": "claude-sdk",
                "default_timeout_seconds": 30.0,
                "default_max_attempts": 2,
                "default_fallback_to_uncertain_on_error": True,
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["validate-backend-manifest", str(manifest_path)])

    assert exit_code == 2
    assert output == "Unknown CLI protocol backend: sdk_api"


def test_cli_validate_backend_manifest_json_returns_machine_readable_output(tmp_path: Path) -> None:
    manifest_path = tmp_path / "provider.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "claude-code",
                "protocol": "stdout_envelope_cli",
                "default_executable": "claude-code",
                "default_timeout_seconds": 30.0,
                "default_max_attempts": 2,
                "default_fallback_to_uncertain_on_error": True,
                "default_expanded_evidence_retry_mode": "off",
                "capabilities": {
                    "supports_model_override": True,
                    "supports_config_overrides": True,
                    "supports_stdout_json": True,
                },
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["validate-backend-manifest-json", str(manifest_path)])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["status"] == "valid"
    assert payload["manifest"] == str(manifest_path)
    assert payload["default_expanded_evidence_retry_mode"] == "off"
    assert payload["protocol_backend"] == "CodeAgentCliBackend"
    assert payload["runtime_compatibility"] == "supported"
    assert payload["registration_scope"] is None


def test_cli_register_backend_manifest_calls_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = tmp_path / "provider.json"
    manifest_path.write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    class StubCapabilities:
        supports_model_override = True
        supports_config_overrides = True
        supports_backend_cache = True
        supports_output_schema = False
        supports_output_file = False
        supports_stdout_json = True

    class StubSpec:
        name = "claude-code"
        protocol = "stdout_envelope_cli"
        default_executable = "claude-code"
        default_timeout_seconds = 30.0
        default_max_attempts = 2
        default_expanded_evidence_retry_mode = "auto"
        capabilities = StubCapabilities()

    def fake_register(path, *, replace=False):
        captured["path"] = Path(path)
        captured["replace"] = replace
        return StubSpec()

    monkeypatch.setattr(
        "lua_nil_guard.cli.register_manifest_backed_adjudication_backend",
        fake_register,
    )

    exit_code, output = run(["register-backend-manifest", "--replace", str(manifest_path)])

    assert exit_code == 0
    assert captured["path"] == manifest_path
    assert captured["replace"] is True
    assert "Backend manifest registered." in output
    assert "Protocol backend: CodeAgentCliBackend" in output
    assert "Registration scope: current process invocation" in output


def test_cli_register_backend_manifest_json_writes_output_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = tmp_path / "provider.json"
    manifest_path.write_text("{}", encoding="utf-8")
    output_path = tmp_path / "provider-result.json"

    class StubCapabilities:
        supports_model_override = True
        supports_config_overrides = True
        supports_backend_cache = True
        supports_output_schema = False
        supports_output_file = False
        supports_stdout_json = True
        supports_tool_free_prompting = True

    class StubSpec:
        name = "claude-code"
        protocol = "stdout_envelope_cli"
        default_executable = "claude-code"
        default_timeout_seconds = 30.0
        default_max_attempts = 2
        default_expanded_evidence_retry_mode = "auto"
        capabilities = StubCapabilities()

    monkeypatch.setattr(
        "lua_nil_guard.cli.register_manifest_backed_adjudication_backend",
        lambda path, *, replace=False: StubSpec(),
    )

    exit_code, output = run(
        ["register-backend-manifest-json", "--replace", str(manifest_path), str(output_path)]
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "Backend manifest registration JSON export complete." in output
    assert payload["status"] == "registered"
    assert payload["protocol_backend"] == "CodeAgentCliBackend"
    assert payload["registration_scope"] == "current_process_invocation"


def test_cli_benchmark_reports_labeled_accuracy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)

    class FileLabelBackend:
        def adjudicate(self, packet, sink_rule):  # noqa: ANN001
            file_name = Path(packet.target.file).name
            if file_name.startswith("provable_risky_"):
                status = "risky"
            elif file_name.startswith("provable_safe_"):
                status = "safe"
            else:
                status = "uncertain"
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status=status,
                    confidence="high",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=(),
                    recommended_next_action="report",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status=status,
                    confidence="high",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=(),
                    recommended_next_action="report",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status=status,
                    confidence="high",
                    risk_path=(),
                    safety_evidence=(),
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

    monkeypatch.setattr(
        cli_module,
        "create_adjudication_backend",
        lambda *args, **kwargs: FileLabelBackend(),
    )

    exit_code, output = run(["benchmark", str(runtime_root)])

    assert exit_code == 0
    assert "# Lua Nil Review Benchmark" in output
    assert "Total labeled cases: 18" in output
    assert "Backend: FileLabelBackend" in output
    assert "Exact matches: 18" in output
    assert "Accuracy: 100.0%" in output
    assert "Missed risks: 0" in output
    assert "False positive risks: 0" in output
    assert "Backend fallbacks: 0" in output
    assert "Backend timeouts: 0" in output
    assert "Backend cache hits: 0" in output
    assert "Backend cache misses: 0" in output
    assert "Backend calls: 0" in output
    assert "Backend warm-up calls: 0" in output
    assert "Backend review calls: 0" in output
    assert "Backend total latency: 0.000s" in output
    assert "Backend warm-up latency: 0.000s" in output
    assert "Backend review latency: 0.000s" in output
    assert "Backend average latency: 0.000s" in output
    assert "Backend review average latency: 0.000s" in output
    assert "AST primary cases:" in output
    assert "AST fallback cases:" in output
    assert "Legacy-only cases:" in output


def test_cli_benchmark_json_outputs_machine_readable_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    monkeypatch.setattr(
        cli_module,
        "benchmark_repository_review",
        lambda snapshot, backend: BenchmarkSummary(
            total_cases=2,
            exact_matches=1,
            expected_risky=1,
            expected_safe=1,
            expected_uncertain=0,
            actual_risky=1,
            actual_safe=0,
            actual_uncertain=1,
            false_positive_risks=0,
            missed_risks=0,
            unresolved_cases=1,
            backend_fallbacks=0,
            backend_timeouts=0,
            backend_cache_hits=1,
            backend_cache_misses=1,
            backend_calls=1,
            backend_total_seconds=0.75,
            backend_average_seconds=0.75,
            backend_name="codeagent",
            backend_model="codeagent-main",
            backend_executable="/tmp/codeagent",
            cases=(),
            ast_primary_cases=1,
            ast_fallback_to_legacy_cases=1,
            legacy_only_cases=0,
        ),
    )

    exit_code, output = run(["benchmark-json", str(tmp_path)])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["repository"] == str(tmp_path)
    assert payload["backend_name"] == "codeagent"
    assert payload["total_cases"] == 2
    assert payload["exact_matches"] == 1
    assert payload["backend_calls"] == 1
    assert payload["backend_warmup_calls"] == 0
    assert payload["backend_review_calls"] == 1
    assert payload["backend_total_seconds"] == 0.75
    assert payload["backend_warmup_total_seconds"] == 0.0
    assert payload["backend_review_total_seconds"] == 0.75
    assert payload["ast_primary_cases"] == 1
    assert payload["ast_fallback_to_legacy_cases"] == 1
    assert payload["legacy_only_cases"] == 0


def test_cli_benchmark_json_writes_output_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    monkeypatch.setattr(
        cli_module,
        "benchmark_repository_review",
        lambda snapshot, backend: BenchmarkSummary(
            total_cases=1,
            exact_matches=1,
            expected_risky=0,
            expected_safe=1,
            expected_uncertain=0,
            actual_risky=0,
            actual_safe=1,
            actual_uncertain=0,
            false_positive_risks=0,
            missed_risks=0,
            unresolved_cases=0,
            backend_fallbacks=0,
            backend_timeouts=0,
            backend_cache_hits=0,
            backend_cache_misses=0,
            backend_calls=0,
            backend_total_seconds=0.0,
            backend_average_seconds=0.0,
            backend_name="codeagent",
            backend_model=None,
            backend_executable=None,
            cases=(),
        ),
    )
    output_path = tmp_path / "benchmark.json"

    exit_code, output = run(["benchmark-json", str(tmp_path), str(output_path)])

    assert exit_code == 0
    assert "Benchmark JSON export complete." in output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["total_cases"] == 1


def test_cli_proposal_export_json_outputs_machine_readable_proposals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    monkeypatch.setattr(
        cli_module,
        "draft_review_improvements",
        lambda snapshot, backend: (
            ImprovementProposal(
                kind="ast_pattern",
                case_id="case_1",
                file="src/demo.lua",
                status="uncertain",
                confidence="medium",
                reason="structured fallback blocked proof",
                suggested_pattern="no_bounded_ast_proof",
                evidence=("username",),
            ),
        ),
    )

    exit_code, output = run(["proposal-export-json", str(tmp_path)])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload[0]["kind"] == "ast_pattern"
    assert payload[0]["suggested_pattern"] == "no_bounded_ast_proof"


def test_cli_proposal_analytics_renders_aggregate_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    monkeypatch.setattr(
        cli_module,
        "analyze_review_improvements",
        lambda snapshot, backend: ImprovementAnalytics(
            total_proposals=3,
            unique_cases=2,
            unresolved_proposals=2,
            medium_reportable_proposals=1,
            by_kind=(("ast_pattern", 2), ("function_contract", 1)),
            by_reason=(("no_bounded_ast_proof", 2), ("normalize_name", 1)),
            by_pattern=(("no_bounded_ast_proof", 2),),
            by_contract=(("normalize_name", 1),),
            unresolved_by_kind=(("ast_pattern", 2),),
            medium_reportable_by_kind=(("function_contract", 1),),
        ),
    )

    exit_code, output = run(["proposal-analytics", str(tmp_path)])

    assert exit_code == 0
    assert "# Lua Nil Review Improvement Analytics" in output
    assert "total_proposals: 3" in output
    assert "unresolved_proposals: 2" in output
    assert "medium_reportable_proposals: 1" in output
    assert "ast_pattern: 2" in output
    assert "normalize_name: 1" in output


def test_cli_benchmark_cache_compare_reports_cold_and_warm_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    fake_summary = BenchmarkSummary(
        total_cases=18,
        exact_matches=18,
        expected_risky=5,
        expected_safe=8,
        expected_uncertain=5,
        actual_risky=5,
        actual_safe=8,
        actual_uncertain=5,
        false_positive_risks=0,
        missed_risks=0,
        unresolved_cases=0,
        backend_fallbacks=0,
        backend_timeouts=0,
        backend_cache_hits=0,
        backend_cache_misses=18,
        backend_calls=18,
        backend_total_seconds=9.0,
        backend_average_seconds=0.5,
        backend_name="codeagent",
        backend_model="codeagent-a",
        backend_executable="/tmp/codeagent-a",
        cases=(),
    )
    warm_summary = BenchmarkSummary(
        total_cases=18,
        exact_matches=18,
        expected_risky=5,
        expected_safe=8,
        expected_uncertain=5,
        actual_risky=5,
        actual_safe=8,
        actual_uncertain=5,
        false_positive_risks=0,
        missed_risks=0,
        unresolved_cases=0,
        backend_fallbacks=0,
        backend_timeouts=0,
        backend_cache_hits=18,
        backend_cache_misses=0,
        backend_calls=0,
        backend_total_seconds=0.0,
        backend_average_seconds=0.0,
        backend_name="codeagent",
        backend_model="codeagent-b",
        backend_executable="/tmp/codeagent-b",
        cases=(),
    )

    monkeypatch.setattr(
        cli_module,
        "benchmark_cache_compare",
        lambda snapshot, cache_path, backend_factory: BenchmarkCacheComparison(
            cache_path=str(cache_path),
            cache_cleared_entries=2,
            cold=fake_summary,
            warm=warm_summary,
        ),
    )

    exit_code, output = run(
        [
            "benchmark-cache-compare",
            "--backend-cache",
            str(tmp_path / "codex-cache.json"),
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert "# Lua Nil Review Cache Comparison" in output
    assert "Cleared entries before cold run: 2" in output
    assert "Cold run:" in output
    assert "Warm run:" in output
    assert "Delta (warm - cold):" in output
    assert "Cache hits: +18" in output
    assert "Backend calls: -18" in output
    assert "Backend warm-up calls: +0" in output
    assert "Backend review calls: -18" in output


def test_cli_benchmark_cache_compare_json_outputs_machine_readable_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    cold = BenchmarkSummary(
        total_cases=18,
        exact_matches=18,
        expected_risky=5,
        expected_safe=8,
        expected_uncertain=5,
        actual_risky=5,
        actual_safe=8,
        actual_uncertain=5,
        false_positive_risks=0,
        missed_risks=0,
        unresolved_cases=0,
        backend_fallbacks=0,
        backend_timeouts=0,
        backend_cache_hits=0,
        backend_cache_misses=18,
        backend_calls=18,
        backend_total_seconds=9.0,
        backend_average_seconds=0.5,
        backend_name="codeagent",
        backend_model="codeagent-a",
        backend_executable="/tmp/codeagent-a",
        cases=(),
    )
    warm = BenchmarkSummary(
        total_cases=18,
        exact_matches=18,
        expected_risky=5,
        expected_safe=8,
        expected_uncertain=5,
        actual_risky=5,
        actual_safe=8,
        actual_uncertain=5,
        false_positive_risks=0,
        missed_risks=0,
        unresolved_cases=0,
        backend_fallbacks=0,
        backend_timeouts=0,
        backend_cache_hits=18,
        backend_cache_misses=0,
        backend_calls=0,
        backend_total_seconds=0.0,
        backend_average_seconds=0.0,
        backend_name="codeagent",
        backend_model="codeagent-b",
        backend_executable="/tmp/codeagent-b",
        cases=(),
    )
    monkeypatch.setattr(
        cli_module,
        "benchmark_cache_compare",
        lambda snapshot, cache_path, backend_factory: BenchmarkCacheComparison(
            cache_path=str(cache_path),
            cache_cleared_entries=3,
            cold=cold,
            warm=warm,
        ),
    )

    exit_code, output = run(
        [
            "benchmark-cache-compare-json",
            "--backend-cache",
            str(tmp_path / "codex-cache.json"),
            str(tmp_path),
        ]
    )

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["repository"] == str(tmp_path)
    assert payload["cache_cleared_entries"] == 3
    assert payload["cold"]["backend_calls"] == 18
    assert payload["cold"]["backend_warmup_calls"] == 0
    assert payload["cold"]["backend_review_calls"] == 18
    assert payload["warm"]["backend_calls"] == 0
    assert payload["warm"]["backend_warmup_calls"] == 0
    assert payload["warm"]["backend_review_calls"] == 0
    assert payload["delta"]["backend_calls"] == -18
    assert payload["delta"]["backend_warmup_calls"] == 0
    assert payload["delta"]["backend_review_calls"] == -18


def test_cli_benchmark_cache_compare_json_writes_output_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    base_summary = BenchmarkSummary(
        total_cases=1,
        exact_matches=1,
        expected_risky=0,
        expected_safe=1,
        expected_uncertain=0,
        actual_risky=0,
        actual_safe=1,
        actual_uncertain=0,
        false_positive_risks=0,
        missed_risks=0,
        unresolved_cases=0,
        backend_fallbacks=0,
        backend_timeouts=0,
        backend_cache_hits=0,
        backend_cache_misses=1,
        backend_calls=1,
        backend_total_seconds=0.5,
        backend_average_seconds=0.5,
        backend_name="codeagent",
        backend_model="codeagent-main",
        backend_executable="/tmp/codeagent",
        cases=(),
    )
    monkeypatch.setattr(
        cli_module,
        "benchmark_cache_compare",
        lambda snapshot, cache_path, backend_factory: BenchmarkCacheComparison(
            cache_path=str(cache_path),
            cache_cleared_entries=0,
            cold=base_summary,
            warm=base_summary,
        ),
    )
    output_path = tmp_path / "compare.json"

    exit_code, output = run(
        [
            "benchmark-cache-compare-json",
            "--backend-cache",
            str(tmp_path / "codex-cache.json"),
            str(tmp_path),
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert "Benchmark cache comparison JSON export complete." in output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["cache_cleared_entries"] == 0


def test_cli_compare_benchmark_json_reports_key_deltas(tmp_path: Path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(
        json.dumps(
            {
                "repository": "/tmp/repo",
                "backend_name": "codeagent",
                "backend_model": "gemini-2.5-pro",
                "backend_executable": "/usr/bin/codeagent",
                "total_cases": 18,
                "exact_matches": 14,
                "accuracy": 77.8,
                "missed_risks": 2,
                "false_positive_risks": 2,
                "unresolved_cases": 2,
                "backend_fallbacks": 1,
                "backend_timeouts": 1,
                "backend_cache_hits": 0,
                "backend_cache_misses": 18,
                "backend_calls": 18,
                "backend_total_seconds": 9.0,
                "backend_average_seconds": 0.5,
            }
        ),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(
            {
                "repository": "/tmp/repo",
                "backend_name": "codeagent",
                "backend_model": "gemini-2.5-pro-fast",
                "backend_executable": "/opt/bin/codeagent",
                "total_cases": 18,
                "exact_matches": 17,
                "accuracy": 94.4,
                "missed_risks": 1,
                "false_positive_risks": 0,
                "unresolved_cases": 1,
                "backend_fallbacks": 0,
                "backend_timeouts": 0,
                "backend_cache_hits": 12,
                "backend_cache_misses": 6,
                "backend_calls": 6,
                "backend_total_seconds": 2.4,
                "backend_average_seconds": 0.4,
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["compare-benchmark-json", str(before_path), str(after_path)])

    assert exit_code == 0
    assert "# Lua Nil Review Benchmark Comparison" in output
    assert "Backend before: codeagent" in output
    assert "Backend model before: gemini-2.5-pro" in output
    assert "Backend model after: gemini-2.5-pro-fast" in output
    assert "Backend executable before: /usr/bin/codeagent" in output
    assert "Backend executable after: /opt/bin/codeagent" in output
    assert "Exact matches: 14 -> 17 (+3)" in output
    assert "False positive risks: 2 -> 0 (-2)" in output
    assert "Backend calls: 18 -> 6 (-12)" in output
    assert "Backend warm-up calls: 0 -> 0 (+0)" in output
    assert "Backend review calls: 18 -> 6 (-12)" in output
    assert "Backend total latency: 9.000s -> 2.400s (-6.600s)" in output


def test_cli_compare_benchmark_json_writes_output_file(tmp_path: Path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "compare.txt"
    before_path.write_text(
        json.dumps(
            {
                "repository": "/tmp/repo",
                "total_cases": 1,
                "exact_matches": 1,
                "accuracy": 100.0,
                "missed_risks": 0,
                "false_positive_risks": 0,
                "unresolved_cases": 0,
                "backend_fallbacks": 0,
                "backend_timeouts": 0,
                "backend_cache_hits": 0,
                "backend_cache_misses": 1,
                "backend_calls": 1,
                "backend_total_seconds": 0.5,
                "backend_average_seconds": 0.5,
            }
        ),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(
            {
                "repository": "/tmp/repo",
                "total_cases": 1,
                "exact_matches": 1,
                "accuracy": 100.0,
                "missed_risks": 0,
                "false_positive_risks": 0,
                "unresolved_cases": 0,
                "backend_fallbacks": 0,
                "backend_timeouts": 0,
                "backend_cache_hits": 1,
                "backend_cache_misses": 0,
                "backend_calls": 0,
                "backend_total_seconds": 0.0,
                "backend_average_seconds": 0.0,
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(
        ["compare-benchmark-json", str(before_path), str(after_path), str(output_path)]
    )

    assert exit_code == 0
    assert "Benchmark comparison export complete." in output
    text = output_path.read_text(encoding="utf-8")
    assert "Backend cache hits: 0 -> 1 (+1)" in text
    assert "Backend review calls: 1 -> 0 (-1)" in text


def test_cli_compare_benchmark_json_accepts_cache_compare_payloads(tmp_path: Path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(
        json.dumps(
            {
                "repository": "/tmp/repo",
                "cache_path": "/tmp/cache.json",
                "cache_cleared_entries": 0,
                "cold": {"exact_matches": 10},
                "warm": {
                    "repository": "/tmp/repo",
                    "total_cases": 18,
                    "exact_matches": 12,
                    "accuracy": 66.7,
                    "missed_risks": 3,
                    "false_positive_risks": 3,
                    "unresolved_cases": 3,
                    "backend_fallbacks": 1,
                    "backend_timeouts": 0,
                    "backend_cache_hits": 8,
                    "backend_cache_misses": 10,
                    "backend_calls": 10,
                    "backend_total_seconds": 5.0,
                    "backend_average_seconds": 0.5,
                },
            }
        ),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(
            {
                "repository": "/tmp/repo",
                "total_cases": 18,
                "exact_matches": 15,
                "accuracy": 83.3,
                "missed_risks": 1,
                "false_positive_risks": 2,
                "unresolved_cases": 1,
                "backend_fallbacks": 0,
                "backend_timeouts": 0,
                "backend_cache_hits": 12,
                "backend_cache_misses": 6,
                "backend_calls": 6,
                "backend_total_seconds": 3.0,
                "backend_average_seconds": 0.5,
            }
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["compare-benchmark-json", str(before_path), str(after_path)])

    assert exit_code == 0
    assert "Repository before: /tmp/repo" in output
    assert "Exact matches: 12 -> 15 (+3)" in output


def test_cli_benchmark_cache_compare_requires_backend_cache(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    exit_code, output = run(["benchmark-cache-compare", str(tmp_path)])

    assert exit_code == 2
    assert output == "benchmark-cache-compare requires --backend-cache PATH"


def test_cli_benchmark_cache_compare_json_requires_backend_cache(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "config" / "sink_rules.json").write_text("[]", encoding="utf-8")
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

    exit_code, output = run(["benchmark-cache-compare-json", str(tmp_path)])

    assert exit_code == 2
    assert output == "benchmark-cache-compare-json requires --backend-cache PATH"


def test_cli_report_outputs_markdown_findings(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["report", str(tmp_path)])

    assert exit_code == 0
    assert "# Lua Nil Risk Report" in output
    assert "risky_verified" in output


def test_cli_export_autofix_outputs_machine_readable_patches(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-autofix", str(tmp_path)])

    assert exit_code == 0
    payload = json.loads(output)
    assert payload[0]["action"] == "insert_before"
    assert payload[0]["start_line"] == 2
    assert payload[0]["replacement"] == "username = username or ''"
    assert payload[0]["expected_original"] == "return string.match(username, '^a')"


def test_cli_apply_autofix_updates_files_from_manifest(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_apply",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", str(manifest)])

    assert exit_code == 0
    assert "Dry run: no" in output
    assert "Applied patches: 1" in output
    assert "Conflicts: 0" in output
    assert target.read_text(encoding="utf-8") == (
        "username = username or ''\n"
        "return string.match(username, '^a')\n"
    )


def test_cli_apply_autofix_dry_run_does_not_write_files(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(username, '^a')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_dry_run",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", "--dry-run", str(manifest)])

    assert exit_code == 0
    assert "Dry run: yes" in output
    assert "Applied patches: 1" in output
    assert "Conflicts: 0" in output
    assert target.read_text(encoding="utf-8") == original


def test_cli_apply_autofix_returns_conflicts_without_writing_files(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(user_name, '^a')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_conflict",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "user_name = user_name or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", str(manifest)])

    assert exit_code == 1
    assert "Dry run: no" in output
    assert "Applied patches: 0" in output
    assert "Conflicts: 1" in output
    assert "anchor line no longer matches expected_original" in output
    assert target.read_text(encoding="utf-8") == original


def test_cli_apply_autofix_reports_missing_manifest() -> None:
    exit_code, output = run(["apply-autofix", "missing-autofix.json"])

    assert exit_code == 2
    assert "missing-autofix.json" in output


def test_cli_apply_autofix_filters_by_case_id(tmp_path: Path) -> None:
    first = tmp_path / "first.lua"
    second = tmp_path / "second.lua"
    first.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    second.write_text("return string.match(token, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_first",
                    "file": str(first),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, '^a')",
                },
                {
                    "case_id": "case_second",
                    "file": str(second),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "token = token or ''",
                    "expected_original": "return string.match(token, '^a')",
                },
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["apply-autofix", "--case-id", "case_second", str(manifest)])

    assert exit_code == 0
    assert "Applied patches: 1" in output
    assert first.read_text(encoding="utf-8") == "return string.match(username, '^a')\n"
    assert second.read_text(encoding="utf-8") == (
        "token = token or ''\n"
        "return string.match(token, '^a')\n"
    )


def test_cli_export_unified_diff_outputs_patch_text(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_diff",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-unified-diff", str(manifest)])

    assert exit_code == 0
    assert f"--- {target}" in output
    assert f"+++ {target}" in output
    assert "+username = username or ''" in output


def test_cli_export_unified_diff_blocks_on_conflicts(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(user_name, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_diff_conflict",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "user_name = user_name or ''",
                    "expected_original": "return string.match(username, '^a')",
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-unified-diff", str(manifest)])

    assert exit_code == 1
    assert "Unified diff export blocked." in output
    assert "Conflicts: 1" in output
    assert "anchor line no longer matches expected_original" in output


def test_cli_export_unified_diff_filters_by_file(tmp_path: Path) -> None:
    first = tmp_path / "first.lua"
    second = tmp_path / "second.lua"
    first.write_text("return string.match(username, '^a')\n", encoding="utf-8")
    second.write_text("return string.match(token, '^a')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_first",
                    "file": str(first),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, '^a')",
                },
                {
                    "case_id": "case_second",
                    "file": str(second),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "token = token or ''",
                    "expected_original": "return string.match(token, '^a')",
                },
            ]
        ),
        encoding="utf-8",
    )

    exit_code, output = run(["export-unified-diff", "--file", str(second), str(manifest)])

    assert exit_code == 0
    assert f"--- {second}" in output
    assert f"+++ {second}" in output
    assert "+token = token or ''" in output
    assert str(first) not in output


def test_cli_baseline_create_writes_baseline_file(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"

    exit_code, output = run(["baseline-create", str(tmp_path), str(baseline_path)])

    assert exit_code == 0
    assert "Baseline entries: 1" in output
    assert baseline_path.exists()


def test_cli_report_new_applies_baseline_filter(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"
    create_exit_code, _ = run(["baseline-create", str(tmp_path), str(baseline_path)])
    assert create_exit_code == 0

    exit_code, output = run(["report-new", str(tmp_path), str(baseline_path)])

    assert exit_code == 0
    assert "No reportable findings." in output


def test_cli_refresh_summaries_writes_summary_cache(tmp_path: Path) -> None:
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
                "local function normalize_name(name, fallback)",
                "  assert(fallback)",
                "  name = name or fallback",
                "  return name",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    summary_path = tmp_path / "data" / "function_summaries.json"

    exit_code, output = run(["refresh-summaries", str(tmp_path), str(summary_path)])

    assert exit_code == 0
    assert "Summary entries: 1" in output
    assert summary_path.exists()


def test_cli_refresh_knowledge_writes_knowledge_cache(tmp_path: Path) -> None:
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
                "local function normalize_name(name)",
                "  name = name or ''",
                "  return name",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    knowledge_path = tmp_path / "data" / "knowledge.json"

    exit_code, output = run(["refresh-knowledge", str(tmp_path), str(knowledge_path)])

    assert exit_code == 0
    assert "Knowledge entries: 1" in output
    assert knowledge_path.exists()


def test_cli_ci_check_fails_when_new_findings_exist(tmp_path: Path) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("[]", encoding="utf-8")

    exit_code, output = run(["ci-check", str(tmp_path), str(baseline_path)])

    assert exit_code == 1
    assert "New findings: 1" in output


def test_cli_report_accepts_backend_option_and_calls_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    skill_path = tmp_path / "custom-skill.md"
    skill_path.write_text("placeholder", encoding="utf-8")
    manifest_path = tmp_path / "provider.json"
    manifest_path.write_text("{}", encoding="utf-8")

    def fake_factory(
        name: str,
        *,
        workdir=None,
        model=None,
        skill_path=None,
        strict_skill=True,
        executable=None,
        timeout_seconds=None,
        max_attempts=None,
        expanded_evidence_retry=None,
        cache_path=None,
        config_overrides=(),
    ):
        captured["name"] = name
        captured["workdir"] = workdir
        captured["model"] = model
        captured["skill_path"] = skill_path
        captured["strict_skill"] = strict_skill
        captured["executable"] = executable
        captured["timeout_seconds"] = timeout_seconds
        captured["max_attempts"] = max_attempts
        captured["expanded_evidence_retry"] = expanded_evidence_retry
        captured["cache_path"] = cache_path
        captured["config_overrides"] = config_overrides
        return None

    def fake_register(manifest_path_arg, *, replace=False):
        captured["backend_manifest_path"] = Path(manifest_path_arg)
        captured["backend_manifest_replace"] = replace

    monkeypatch.setattr("lua_nil_guard.cli.create_adjudication_backend", fake_factory)
    monkeypatch.setattr(
        "lua_nil_guard.cli.register_manifest_backed_adjudication_backend",
        fake_register,
    )

    exit_code, output = run(
        [
            "report",
            "--backend",
            "codeagent",
            "--skill",
            str(skill_path),
            "--allow-skill-fallback",
            "--backend-executable",
            "/tmp/codeagent-bin",
            "--backend-manifest",
            str(manifest_path),
            "--backend-timeout",
            "12.5",
            "--backend-attempts",
            "3",
            "--expanded-evidence-retry",
            "on",
            "--backend-cache",
            str(tmp_path / "codex-cache.json"),
            "--backend-config",
            "model='o3'",
            "--backend-config",
            "features.fast=true",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert captured["name"] == "codeagent"
    assert captured["workdir"] == tmp_path
    assert captured["model"] is None
    assert captured["skill_path"] == skill_path
    assert captured["strict_skill"] is False
    assert captured["executable"] == "/tmp/codeagent-bin"
    assert captured["backend_manifest_path"] == manifest_path
    assert captured["backend_manifest_replace"] is True
    assert captured["timeout_seconds"] == 12.5
    assert captured["max_attempts"] == 3
    assert captured["expanded_evidence_retry"] is True
    assert captured["cache_path"] == (tmp_path / "codex-cache.json")
    assert captured["config_overrides"] == ("model='o3'", "features.fast=true")
    assert "# Lua Nil Risk Report" in output


def test_cli_report_file_accepts_lua_file_and_uses_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    file_path = tmp_path / "src" / "demo.lua"
    file_path.write_text(
        "\n".join(
            [
                "local username = nil",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def fake_factory(
        name: str,
        *,
        workdir=None,
        model=None,
        skill_path=None,
        strict_skill=True,
        executable=None,
        timeout_seconds=None,
        max_attempts=None,
        expanded_evidence_retry=None,
        cache_path=None,
        config_overrides=(),
    ):
        captured["name"] = name
        captured["workdir"] = workdir
        captured["model"] = model
        captured["skill_path"] = skill_path
        captured["strict_skill"] = strict_skill
        captured["executable"] = executable
        captured["timeout_seconds"] = timeout_seconds
        captured["max_attempts"] = max_attempts
        captured["expanded_evidence_retry"] = expanded_evidence_retry
        captured["cache_path"] = cache_path
        captured["config_overrides"] = config_overrides
        return None

    monkeypatch.setattr("lua_nil_guard.cli.create_adjudication_backend", fake_factory)

    exit_code, output = run(["report-file", "--backend", "gemini", str(file_path)])

    assert exit_code == 0
    assert captured["name"] == "gemini"
    assert captured["workdir"] == tmp_path
    assert "# Lua Nil Risk Report" in output


def test_cli_report_rejects_invalid_expanded_evidence_retry_mode() -> None:
    exit_code, output = run(["report", "--expanded-evidence-retry", "maybe", "demo"])

    assert exit_code == 2
    assert output == "--expanded-evidence-retry must be one of: auto, on, off"


def test_cli_report_surfaces_backend_errors_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
                "local username = req.params.username",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    def fake_review(*args, **kwargs):
        raise BackendError("codex backend failed")

    monkeypatch.setattr("lua_nil_guard.cli.run_repository_review", fake_review)

    exit_code, output = run(["report", str(tmp_path)])

    assert exit_code == 2
    assert output == "codex backend failed"


def test_cli_report_rejects_invalid_backend_timeout() -> None:
    exit_code, output = run(["report", "--backend-timeout", "0", "demo"])

    assert exit_code == 2
    assert output == "--backend-timeout must be a positive number"


def test_cli_scan_rejects_invalid_focus_value() -> None:
    exit_code, output = run(["scan", "--focus", "network", "demo"])

    assert exit_code == 2
    assert output == "--focus must be one of: all, string"


def test_cli_report_rejects_invalid_backend_config() -> None:
    exit_code, output = run(["report", "--backend-config", "reasoning_effort", "demo"])

    assert exit_code == 2
    assert output == "--backend-config must be in KEY=VALUE form"


def test_cli_report_surfaces_unsupported_codeagent_backend_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lua_nil_guard.cli.bootstrap_repository", lambda root: object())

    exit_code, output = run(
        [
            "report",
            "--backend",
            "codeagent",
            "--backend-config",
            "features.fast=true",
            "demo",
        ]
    )

    assert exit_code == 2
    assert output == "Provider codeagent does not support backend config overrides"


def test_cli_report_applies_focus_filter_to_repository_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
                "local username = req.params.username",
                "for _, v in pairs(req.params.users or {}) do end",
                "return string.match(username, '^a')",
            ]
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def fake_review(snapshot, backend):
        captured["sink_ids"] = tuple(rule.id for rule in snapshot.sink_rules)
        return ()

    monkeypatch.setattr("lua_nil_guard.cli.create_adjudication_backend", lambda *args, **kwargs: object())
    monkeypatch.setattr("lua_nil_guard.cli.run_repository_review", fake_review)

    exit_code, output = run(["report", "--focus", "string", str(tmp_path)])

    assert exit_code == 0
    assert captured["sink_ids"] == ("string.match.arg1",)
    assert "# Lua Nil Risk Report" in output
