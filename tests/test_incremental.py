from __future__ import annotations

import sqlite3

from lua_nil_guard.incremental import compute_invalidated_facts, should_fallback_to_full
from lua_nil_guard.repository import (
    ensure_dependency_schema,
    insert_fact_dependency,
    upsert_file_fingerprint,
)


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    ensure_dependency_schema(conn)
    return conn


def test_single_file_change_no_cross_dependency() -> None:
    conn = _make_db()
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    insert_fact_dependency(conn, "verdict_001", "verdict", "src/a.lua", run_id=1)
    insert_fact_dependency(conn, "case_002", "candidate", "src/b.lua", run_id=1)
    insert_fact_dependency(conn, "verdict_002", "verdict", "src/b.lua", run_id=1)
    conn.commit()

    result = compute_invalidated_facts(conn, {"src/a.lua"})

    assert "case_001" in result
    assert "verdict_001" in result
    assert "case_002" not in result
    assert "verdict_002" not in result


def test_helper_file_change_propagates() -> None:
    conn = _make_db()
    # case_001 in a.lua depends on helper.lua via a summary
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    insert_fact_dependency(conn, "static_001", "static_result", "src/helper.lua", run_id=1, depends_on_function="resolve")
    insert_fact_dependency(conn, "static_001", "static_result", "src/a.lua", run_id=1)
    insert_fact_dependency(conn, "verdict_001", "verdict", "src/a.lua", run_id=1)
    conn.commit()

    result = compute_invalidated_facts(conn, {"src/helper.lua"})

    assert "static_001" in result


def test_unrelated_file_change_no_propagation() -> None:
    conn = _make_db()
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    conn.commit()

    result = compute_invalidated_facts(conn, {"src/unrelated.lua"})

    assert len(result) == 0


def test_empty_changed_files() -> None:
    conn = _make_db()
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    conn.commit()

    result = compute_invalidated_facts(conn, set())

    assert len(result) == 0


def test_fallback_no_history() -> None:
    conn = _make_db()

    assert should_fallback_to_full(conn, {"src/a.lua"}, total_files=10) is True


def test_fallback_empty_fingerprints() -> None:
    conn = _make_db()
    # Has deps but no fingerprints
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    conn.commit()

    assert should_fallback_to_full(conn, {"src/a.lua"}, total_files=10) is True


def test_fallback_too_many_changed_files() -> None:
    conn = _make_db()
    upsert_file_fingerprint(conn, "src/a.lua", "abc", 1000)
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    conn.commit()

    # 4/10 = 40% > 30%
    changed = {f"src/{i}.lua" for i in range(4)}
    assert should_fallback_to_full(conn, changed, total_files=10) is True


def test_no_fallback_normal_incremental() -> None:
    conn = _make_db()
    upsert_file_fingerprint(conn, "src/a.lua", "abc", 1000)
    upsert_file_fingerprint(conn, "src/b.lua", "def", 2000)
    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    conn.commit()

    assert should_fallback_to_full(conn, {"src/a.lua"}, total_files=10) is False


def test_bfs_terminates_on_cycle() -> None:
    """Ensure the BFS doesn't loop infinitely on circular dependencies."""
    conn = _make_db()
    # A depends on B's file, B depends on A's file (circular)
    insert_fact_dependency(conn, "fact_a", "static_result", "src/b.lua", run_id=1)
    insert_fact_dependency(conn, "fact_b", "static_result", "src/a.lua", run_id=1)
    # Both also depend on their own files
    insert_fact_dependency(conn, "fact_a", "static_result", "src/a.lua", run_id=1)
    insert_fact_dependency(conn, "fact_b", "static_result", "src/b.lua", run_id=1)
    conn.commit()

    # Should terminate
    result = compute_invalidated_facts(conn, {"src/a.lua"})
    assert "fact_a" in result or "fact_b" in result
