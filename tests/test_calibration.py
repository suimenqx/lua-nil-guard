from __future__ import annotations

import sqlite3

from lua_nil_guard.calibration import (
    CalibrationBucket,
    ensure_calibration_schema,
    list_buckets,
    lookup_calibration,
    recalibrate,
)


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    ensure_calibration_schema(conn)
    return conn


def _seed_adjudication_records(
    conn: sqlite3.Connection,
    records: list[tuple[str, str, str, str, str | None]],
) -> None:
    """Create adjudication_records table and insert seed data.

    Each record is (sink_type, unknown_reason, predicted_status, predicted_confidence, actual_outcome).
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS adjudication_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sink_type TEXT NOT NULL,
            unknown_reason TEXT NOT NULL,
            predicted_status TEXT,
            predicted_confidence TEXT,
            actual_outcome TEXT
        )
    """)
    conn.executemany(
        "INSERT INTO adjudication_records (sink_type, unknown_reason, predicted_status, predicted_confidence, actual_outcome) "
        "VALUES (?, ?, ?, ?, ?)",
        records,
    )
    conn.commit()


def test_recalibrate_from_empty_records() -> None:
    conn = _make_db()
    # No adjudication_records table at all
    buckets = recalibrate(conn)

    assert buckets == []


def test_recalibrate_computes_correct_precision() -> None:
    conn = _make_db()
    records = [
        ("string.match", "no_bounded_ast_proof", "risky", "high", "risky"),
    ] * 40 + [
        ("string.match", "no_bounded_ast_proof", "risky", "high", "safe"),
    ] * 10
    _seed_adjudication_records(conn, records)

    buckets = recalibrate(conn)

    assert len(buckets) == 1
    bucket = buckets[0]
    assert bucket.sink_type == "string.match"
    assert bucket.unknown_reason == "no_bounded_ast_proof"
    assert bucket.predicted_confidence == "high"
    assert bucket.sample_count == 50
    assert bucket.correct_count == 40
    assert bucket.actual_precision is not None
    assert abs(bucket.actual_precision - 0.8) < 0.01


def test_lookup_calibration_bucket_exists_and_sufficient() -> None:
    conn = _make_db()
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("string.match", "no_bounded_ast_proof", "high", 50, 30, 0.6, "2026-01-01T00:00:00"),
    )
    conn.commit()

    result = lookup_calibration(conn, "string.match", "no_bounded_ast_proof", "high")

    # precision 0.6 < 0.7 → downgrade high → medium
    assert result == "medium"


def test_lookup_calibration_cold_start_returns_original() -> None:
    conn = _make_db()
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("string.match", "no_bounded_ast_proof", "high", 20, 10, 0.5, "2026-01-01T00:00:00"),
    )
    conn.commit()

    result = lookup_calibration(conn, "string.match", "no_bounded_ast_proof", "high")

    # sample_count 20 < 30 (cold start threshold) → return original
    assert result == "high"


def test_lookup_calibration_bucket_not_found_returns_original() -> None:
    conn = _make_db()

    result = lookup_calibration(conn, "string.match", "no_bounded_ast_proof", "high")

    assert result == "high"


def test_lookup_calibration_high_precision_keeps_original() -> None:
    conn = _make_db()
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("string.match", "no_bounded_ast_proof", "high", 50, 45, 0.9, "2026-01-01T00:00:00"),
    )
    conn.commit()

    result = lookup_calibration(conn, "string.match", "no_bounded_ast_proof", "high")

    # precision 0.9 >= 0.7 → keep original
    assert result == "high"


def test_lookup_calibration_medium_downgraded_to_low() -> None:
    conn = _make_db()
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("pairs", "unsupported_control_flow", "medium", 40, 20, 0.5, "2026-01-01T00:00:00"),
    )
    conn.commit()

    result = lookup_calibration(conn, "pairs", "unsupported_control_flow", "medium")

    assert result == "low"


def test_lookup_calibration_custom_threshold() -> None:
    conn = _make_db()
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("string.match", "no_bounded_ast_proof", "high", 10, 5, 0.5, "2026-01-01T00:00:00"),
    )
    conn.commit()

    # With threshold=5, 10 samples is enough
    result = lookup_calibration(
        conn, "string.match", "no_bounded_ast_proof", "high",
        cold_start_threshold=5,
    )
    assert result == "medium"

    # With default threshold=30, 10 samples is cold start
    result = lookup_calibration(conn, "string.match", "no_bounded_ast_proof", "high")
    assert result == "high"


def test_list_buckets_returns_all() -> None:
    conn = _make_db()
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("string.match", "no_bounded_ast_proof", "high", 50, 40, 0.8, "2026-01-01"),
    )
    conn.execute(
        "INSERT INTO calibration_buckets VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("pairs", "", "medium", 30, 25, 0.83, "2026-01-01"),
    )
    conn.commit()

    buckets = list_buckets(conn)

    assert len(buckets) == 2
    assert all(isinstance(b, CalibrationBucket) for b in buckets)


def test_recalibrate_skips_null_actual_outcome() -> None:
    conn = _make_db()
    records = [
        ("string.match", "no_bounded_ast_proof", "risky", "high", "risky"),
        ("string.match", "no_bounded_ast_proof", "risky", "high", None),
        ("string.match", "no_bounded_ast_proof", "risky", "high", None),
    ]
    _seed_adjudication_records(conn, records)

    buckets = recalibrate(conn)

    assert len(buckets) == 1
    assert buckets[0].sample_count == 1  # only the one with actual_outcome
