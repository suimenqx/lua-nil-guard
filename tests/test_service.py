from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.service import bootstrap_repository, export_autofix_patches


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
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["action"] == "insert_before"
    assert payload[0]["replacement"] == "username = username or ''"
