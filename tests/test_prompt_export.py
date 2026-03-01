from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.cli import run
from lua_nil_review_agent.service import bootstrap_repository, export_adjudication_tasks


def test_export_adjudication_tasks_builds_prompt_payloads(tmp_path: Path) -> None:
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

    snapshot = bootstrap_repository(tmp_path)
    tasks = export_adjudication_tasks(snapshot)

    assert len(tasks) == 1
    assert tasks[0]["case_id"]
    assert "Skill: lua-nil-adjudicator" in tasks[0]["prompt"]
    assert "Unknown is not risk." in tasks[0]["prompt"]
    assert tasks[0]["sink_rule_id"] == "string.match.arg1"


def test_cli_export_prompts_writes_json_file(tmp_path: Path) -> None:
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
    output_path = tmp_path / "prompts.json"

    exit_code, output = run(["export-prompts", str(tmp_path), str(output_path)])

    assert exit_code == 0
    assert "Prompt tasks: 1" in output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["sink_rule_id"] == "string.match.arg1"
