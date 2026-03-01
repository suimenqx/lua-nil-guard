from __future__ import annotations

from pathlib import Path

from .config_loader import load_confidence_policy, load_sink_rules
from .models import RepositorySnapshot
from .repository import discover_lua_files


def bootstrap_repository(root: str | Path) -> RepositorySnapshot:
    """Load the current repository's core review inputs."""

    root_path = Path(root)
    sink_rules = tuple(load_sink_rules(root_path / "config" / "sink_rules.json"))
    confidence_policy = load_confidence_policy(root_path / "config" / "confidence_policy.json")
    lua_files = tuple(discover_lua_files(root_path))

    return RepositorySnapshot(
        root=root_path,
        sink_rules=sink_rules,
        confidence_policy=confidence_policy,
        lua_files=lua_files,
    )
