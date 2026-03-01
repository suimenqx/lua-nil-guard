from __future__ import annotations

import json
from pathlib import Path

from lua_nil_review_agent.service import bootstrap_repository


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
