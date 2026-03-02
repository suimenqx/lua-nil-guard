from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.models import AutofixPatch
from lua_nil_review_agent.service import apply_autofix_manifest, bootstrap_repository, export_autofix_patches


def test_bootstrap_repository_loads_config_and_discovers_sources(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()

    sink_rules = [
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
    confidence_policy = {
        "levels": ["low", "medium", "high"],
        "default_report_min_confidence": "high",
        "default_include_medium_in_audit": True,
    }

    (config_dir / "sink_rules.json").write_text(json.dumps(sink_rules), encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(confidence_policy),
        encoding="utf-8",
    )
    (src_dir / "demo.lua").write_text("return string.match(name, 'x')", encoding="utf-8")

    snapshot = bootstrap_repository(tmp_path)

    assert snapshot.root == tmp_path
    assert len(snapshot.sink_rules) == 1
    assert snapshot.confidence_policy.default_report_min_confidence == "high"
    assert snapshot.lua_files == (src_dir / "demo.lua",)


def test_export_autofix_patches_writes_reportable_patch_file(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    src_dir = tmp_path / "src"
    config_dir.mkdir()
    src_dir.mkdir()

    sink_rules = [
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
    confidence_policy = {
        "levels": ["low", "medium", "high"],
        "default_report_min_confidence": "high",
        "default_include_medium_in_audit": True,
    }

    (config_dir / "sink_rules.json").write_text(json.dumps(sink_rules), encoding="utf-8")
    (config_dir / "confidence_policy.json").write_text(
        json.dumps(confidence_policy),
        encoding="utf-8",
    )
    (src_dir / "demo.lua").write_text(
        "local username = req.params.username\nreturn string.match(username, 'x')",
        encoding="utf-8",
    )

    snapshot = bootstrap_repository(tmp_path)
    output_path = tmp_path / "data" / "autofix.json"

    patches = export_autofix_patches(snapshot, output_path=output_path)

    assert len(patches) == 1
    patch = patches[0]
    assert patch.action == "insert_before"
    assert patch.start_line == 2
    assert patch.expected_original == "return string.match(username, 'x')"
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["action"] == "insert_before"
    assert payload[0]["replacement"] == "username = username or ''"
    assert payload[0]["expected_original"] == "return string.match(username, 'x')"


def test_apply_autofix_manifest_updates_file_when_expected_original_matches(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    target.write_text("return string.match(username, 'x')\n", encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": "case_1",
                    "file": str(target),
                    "action": "insert_before",
                    "start_line": 1,
                    "end_line": 1,
                    "replacement": "username = username or ''",
                    "expected_original": "return string.match(username, 'x')",
                }
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest)

    assert len(applied) == 1
    assert not conflicts
    assert target.read_text(encoding="utf-8") == (
        "username = username or ''\n"
        "return string.match(username, 'x')\n"
    )


def test_apply_autofix_manifest_dry_run_does_not_write_file(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(username, 'x')\n"
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
                    "expected_original": "return string.match(username, 'x')",
                }
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest, dry_run=True)

    assert len(applied) == 1
    assert not conflicts
    assert target.read_text(encoding="utf-8") == original


def test_apply_autofix_manifest_reports_conflicts_without_writing_file(tmp_path: Path) -> None:
    target = tmp_path / "demo.lua"
    original = "return string.match(user_name, 'x')\n"
    target.write_text(original, encoding="utf-8")
    manifest = tmp_path / "autofix.json"
    patch = AutofixPatch(
        case_id="case_conflict",
        file=str(target),
        action="insert_before",
        start_line=1,
        end_line=1,
        replacement="user_name = user_name or ''",
        expected_original="return string.match(username, 'x')",
    )
    manifest.write_text(
        json.dumps(
            [
                {
                    "case_id": patch.case_id,
                    "file": patch.file,
                    "action": patch.action,
                    "start_line": patch.start_line,
                    "end_line": patch.end_line,
                    "replacement": patch.replacement,
                    "expected_original": patch.expected_original,
                }
            ]
        ),
        encoding="utf-8",
    )

    applied, conflicts = apply_autofix_manifest(manifest)

    assert not applied
    assert len(conflicts) == 1
    assert "anchor line no longer matches expected_original" in conflicts[0]
    assert target.read_text(encoding="utf-8") == original
