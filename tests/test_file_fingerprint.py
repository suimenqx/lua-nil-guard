from __future__ import annotations

import sqlite3
from pathlib import Path

from lua_nil_guard.repository import (
    compute_file_fingerprint,
    ensure_dependency_schema,
    upsert_file_fingerprint,
)


def test_fingerprint_same_content_same_hash(tmp_path: Path) -> None:
    f = tmp_path / "a.lua"
    f.write_text("local x = 1", encoding="utf-8")

    h1 = compute_file_fingerprint(f)
    h2 = compute_file_fingerprint(f)

    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex length


def test_fingerprint_different_content_different_hash(tmp_path: Path) -> None:
    a = tmp_path / "a.lua"
    b = tmp_path / "b.lua"
    a.write_text("local x = 1", encoding="utf-8")
    b.write_text("local x = 2", encoding="utf-8")

    assert compute_file_fingerprint(a) != compute_file_fingerprint(b)


def test_fingerprint_changes_after_modification(tmp_path: Path) -> None:
    f = tmp_path / "a.lua"
    f.write_text("local x = 1", encoding="utf-8")
    h1 = compute_file_fingerprint(f)

    f.write_text("local x = 2", encoding="utf-8")
    h2 = compute_file_fingerprint(f)

    assert h1 != h2


def test_fingerprint_based_on_content_not_mtime(tmp_path: Path) -> None:
    """Same content written at different times has same hash."""
    a = tmp_path / "a.lua"
    b = tmp_path / "b.lua"
    content = "local x = 1"
    a.write_text(content, encoding="utf-8")
    b.write_text(content, encoding="utf-8")

    assert compute_file_fingerprint(a) == compute_file_fingerprint(b)


def test_file_fingerprints_table_roundtrip() -> None:
    conn = sqlite3.connect(":memory:")
    ensure_dependency_schema(conn)

    upsert_file_fingerprint(conn, "src/a.lua", "abc123", 1000000, run_id=1)
    upsert_file_fingerprint(conn, "src/b.lua", "def456", 2000000, run_id=1)
    upsert_file_fingerprint(conn, "src/c.lua", "ghi789", 3000000, run_id=2)
    conn.commit()

    rows = conn.execute(
        "SELECT file_path, content_hash, mtime_ns, last_analyzed_run_id FROM file_fingerprints ORDER BY file_path"
    ).fetchall()

    assert len(rows) == 3
    assert rows[0] == ("src/a.lua", "abc123", 1000000, 1)
    assert rows[1] == ("src/b.lua", "def456", 2000000, 1)
    assert rows[2] == ("src/c.lua", "ghi789", 3000000, 2)


def test_upsert_updates_existing_fingerprint() -> None:
    conn = sqlite3.connect(":memory:")
    ensure_dependency_schema(conn)

    upsert_file_fingerprint(conn, "src/a.lua", "old_hash", 1000, run_id=1)
    upsert_file_fingerprint(conn, "src/a.lua", "new_hash", 2000, run_id=2)
    conn.commit()

    row = conn.execute(
        "SELECT content_hash, mtime_ns, last_analyzed_run_id FROM file_fingerprints WHERE file_path = 'src/a.lua'"
    ).fetchone()

    assert row == ("new_hash", 2000, 2)
