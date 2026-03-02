from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_review_agent.agent_backend import BackendError
from lua_nil_review_agent.cli import run


def test_cli_help_lists_supported_backends() -> None:
    exit_code, output = run(["--help"])

    assert exit_code == 0
    assert "Backend values: heuristic | codex | codeagent" in output
    assert "--allow-skill-fallback" in output
    assert "--backend-executable PATH" in output
    assert "export-autofix" in output
    assert "apply-autofix" in output


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
    assert "Total candidates: 1" in output
    assert "safe_static: 1" in output


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

    def fake_factory(
        name: str,
        *,
        workdir=None,
        model=None,
        skill_path=None,
        strict_skill=True,
        executable=None,
    ):
        captured["name"] = name
        captured["workdir"] = workdir
        captured["model"] = model
        captured["skill_path"] = skill_path
        captured["strict_skill"] = strict_skill
        captured["executable"] = executable
        return None

    monkeypatch.setattr("lua_nil_review_agent.cli.create_adjudication_backend", fake_factory)

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
    assert "# Lua Nil Risk Report" in output


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

    monkeypatch.setattr("lua_nil_review_agent.cli.run_repository_review", fake_review)

    exit_code, output = run(["report", str(tmp_path)])

    assert exit_code == 2
    assert output == "codex backend failed"
