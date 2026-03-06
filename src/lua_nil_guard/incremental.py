"""Dependency-driven incremental invalidation engine.

Given a set of changed files and a dependency graph stored in SQLite,
compute the minimal set of facts that need to be re-analyzed.
"""

from __future__ import annotations

import sqlite3

from .repository import ensure_dependency_schema


def compute_invalidated_facts(
    conn: sqlite3.Connection,
    changed_files: set[str],
) -> set[str]:
    """BFS along dependency edges to find all facts invalidated by *changed_files*.

    Returns a set of ``fact_id`` values that need re-analysis.
    """

    ensure_dependency_schema(conn)

    if not changed_files:
        return set()

    placeholders = ",".join("?" for _ in changed_files)
    seed_rows = conn.execute(
        f"SELECT DISTINCT fact_id FROM fact_dependencies WHERE depends_on_file IN ({placeholders})",
        list(changed_files),
    ).fetchall()

    invalidated: set[str] = {row[0] for row in seed_rows}
    frontier = set(invalidated)
    visited: set[str] = set(invalidated)

    while frontier:
        placeholders = ",".join("?" for _ in frontier)
        # Find facts that depend on already-invalidated facts via their file
        # (i.e. a verdict depends on a static_result which depends on a changed file)
        next_rows = conn.execute(
            f"""
            SELECT DISTINCT fd2.fact_id
            FROM fact_dependencies fd1
            JOIN fact_dependencies fd2 ON fd2.depends_on_file = fd1.depends_on_file
            WHERE fd1.fact_id IN ({placeholders})
              AND fd2.fact_id NOT IN ({','.join('?' for _ in visited)})
            """,
            list(frontier) + list(visited),
        ).fetchall()

        new_facts = {row[0] for row in next_rows} - visited
        if not new_facts:
            break
        invalidated |= new_facts
        visited |= new_facts
        frontier = new_facts

    return invalidated


def should_fallback_to_full(
    conn: sqlite3.Connection,
    changed_files: set[str],
    total_files: int,
) -> bool:
    """Decide whether an incremental run should fall back to full analysis."""

    ensure_dependency_schema(conn)

    # No history: first run
    fp_count = conn.execute("SELECT COUNT(*) FROM file_fingerprints").fetchone()[0]
    if fp_count == 0:
        return True

    # Changed files > 30%
    if total_files > 0 and len(changed_files) / total_files > 0.3:
        return True

    # Dependency graph integrity: at least one dep record should exist
    dep_count = conn.execute("SELECT COUNT(*) FROM fact_dependencies").fetchone()[0]
    if dep_count == 0:
        return True

    return False
