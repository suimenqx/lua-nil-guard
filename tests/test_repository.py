from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.repository import discover_lua_files


def test_discover_lua_files_finds_only_lua_sources(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.lua").write_text("-- ok", encoding="utf-8")
    (tmp_path / "src" / "b.txt").write_text("ignore", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "ignored.lua").write_text("-- ignore", encoding="utf-8")

    files = discover_lua_files(tmp_path)

    assert files == (tmp_path / "src" / "a.lua",)
