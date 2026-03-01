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


def test_export_adjudication_tasks_accepts_custom_skill_path(tmp_path: Path) -> None:
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
    skill_path = tmp_path / "custom-skill.md"
    skill_path.write_text(
        "\n".join(
            [
                "---",
                "name: export-skill",
                "description: Export test skill.",
                "---",
                "",
                "## Goal",
                "- Keep precision high.",
                "",
                "## Required Review Order",
                "1. Read the sink.",
                "",
                "## Canonical Principles",
                "- Unknown is not risk.",
                "- Absence of proof is not proof of bug.",
                "",
                "## Hard Rules",
                "- Return `uncertain` when evidence is incomplete.",
                "- Do not assume undocumented business guarantees.",
                "",
                "## Evidence Checklist",
                "- variable origin",
                "",
                "## Output Contract",
                "- `status`: `safe`, `risky`, or `uncertain`",
                "",
                "## Review Bias",
                "- Prefer silence over speculative warnings.",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    tasks = export_adjudication_tasks(snapshot, skill_path=skill_path)

    assert len(tasks) == 1
    assert "Skill: export-skill" in tasks[0]["prompt"]


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


def test_cli_export_prompts_accepts_skill_option(tmp_path: Path) -> None:
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
    skill_path = tmp_path / "cli-skill.md"
    skill_path.write_text(
        "\n".join(
            [
                "---",
                "name: cli-export-skill",
                "description: CLI export test skill.",
                "---",
                "",
                "## Goal",
                "- Keep precision high.",
                "",
                "## Required Review Order",
                "1. Read the sink.",
                "",
                "## Canonical Principles",
                "- Unknown is not risk.",
                "- Absence of proof is not proof of bug.",
                "",
                "## Hard Rules",
                "- Return `uncertain` when evidence is incomplete.",
                "- Do not assume undocumented business guarantees.",
                "",
                "## Evidence Checklist",
                "- variable origin",
                "",
                "## Output Contract",
                "- `status`: `safe`, `risky`, or `uncertain`",
                "",
                "## Review Bias",
                "- Prefer silence over speculative warnings.",
            ]
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "prompts-with-skill.json"

    exit_code, output = run(
        ["export-prompts", "--skill", str(skill_path), str(tmp_path), str(output_path)]
    )

    assert exit_code == 0
    assert "Prompt tasks: 1" in output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "Skill: cli-export-skill" in payload[0]["prompt"]


def test_cli_export_prompts_allows_skill_fallback(tmp_path: Path) -> None:
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
    broken_skill = tmp_path / "broken-skill.md"
    broken_skill.write_text(
        "\n".join(
            [
                "---",
                "name: broken-skill",
                "description: Broken skill.",
                "---",
                "",
                "## Goal",
                "- Missing required sections.",
            ]
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "fallback-prompts.json"

    exit_code, output = run(
        [
            "export-prompts",
            "--skill",
            str(broken_skill),
            "--allow-skill-fallback",
            str(tmp_path),
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert "Prompt tasks: 1" in output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "Skill: lua-nil-adjudicator" in payload[0]["prompt"]
