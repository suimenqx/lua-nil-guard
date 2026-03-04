from __future__ import annotations

from pathlib import Path


IGNORED_DIR_NAMES = {".git", "__pycache__", ".pytest_cache"}


def discover_lua_files(root: str | Path) -> tuple[Path, ...]:
    """Recursively discover Lua source files under a repository root."""

    root_path = Path(root)
    files: list[Path] = []
    for path in root_path.rglob("*.lua"):
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    files.sort()
    return tuple(files)
