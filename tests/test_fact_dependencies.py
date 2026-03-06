from __future__ import annotations

import sqlite3

from lua_nil_guard.repository import (
    ensure_dependency_schema,
    insert_fact_dependency,
)


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    ensure_dependency_schema(conn)
    return conn


def test_candidate_dependency_write() -> None:
    conn = _make_db()

    insert_fact_dependency(conn, "case_001", "candidate", "src/a.lua", run_id=1)
    conn.commit()

    rows = conn.execute("SELECT * FROM fact_dependencies").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "case_001"
    assert rows[0][1] == "candidate"
    assert rows[0][2] == "src/a.lua"


def test_static_result_depends_on_summary_file() -> None:
    conn = _make_db()

    insert_fact_dependency(conn, "static_001", "static_result", "src/helper.lua", run_id=1, depends_on_function="resolve")
    conn.commit()

    rows = conn.execute("SELECT depends_on_file, depends_on_function FROM fact_dependencies").fetchall()
    assert len(rows) == 1
    assert rows[0] == ("src/helper.lua", "resolve")


def test_verdict_dependency_write() -> None:
    conn = _make_db()

    insert_fact_dependency(conn, "verdict_001", "verdict", "src/a.lua", run_id=1)
    insert_fact_dependency(conn, "verdict_001", "verdict", "src/helper.lua", run_id=1)
    conn.commit()

    rows = conn.execute(
        "SELECT depends_on_file FROM fact_dependencies WHERE fact_id = 'verdict_001' ORDER BY depends_on_file"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "src/a.lua"
    assert rows[1][0] == "src/helper.lua"


def test_macro_fact_dependency() -> None:
    conn = _make_db()

    insert_fact_dependency(conn, "static_002", "static_result", "macros/id.lua", run_id=1)
    conn.commit()

    rows = conn.execute(
        "SELECT fact_id, depends_on_file FROM fact_dependencies WHERE depends_on_file = 'macros/id.lua'"
    ).fetchall()
    assert len(rows) == 1


def test_no_cross_file_dependency() -> None:
    conn = _make_db()

    insert_fact_dependency(conn, "case_solo", "candidate", "src/solo.lua", run_id=1)
    conn.commit()

    rows = conn.execute("SELECT * FROM fact_dependencies WHERE fact_id = 'case_solo'").fetchall()
    assert len(rows) == 1
    assert rows[0][2] == "src/solo.lua"
