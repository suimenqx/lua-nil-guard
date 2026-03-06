"""Offline statistical calibration for LLM adjudication confidence.

Collects historical adjudication outcomes, buckets them by
(sink_type, unknown_reason, predicted_confidence), and computes
actual precision per bucket.  The calibration lookup can then
down-grade (or preserve) the LLM-reported confidence based on
real-world accuracy.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


_CALIBRATION_SCHEMA = """\
CREATE TABLE IF NOT EXISTS calibration_buckets (
    sink_type TEXT NOT NULL,
    unknown_reason TEXT NOT NULL,
    predicted_confidence TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    correct_count INTEGER NOT NULL DEFAULT 0,
    actual_precision REAL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (sink_type, unknown_reason, predicted_confidence)
);
"""

_DEFAULT_COLD_START_THRESHOLD = 30
_CONFIDENCE_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}


@dataclass(frozen=True, slots=True)
class CalibrationBucket:
    """One row of the calibration lookup table."""

    sink_type: str
    unknown_reason: str
    predicted_confidence: str
    sample_count: int
    correct_count: int
    actual_precision: float | None
    last_updated: str


def ensure_calibration_schema(conn: sqlite3.Connection) -> None:
    """Create the calibration_buckets table if it does not exist."""

    conn.executescript(_CALIBRATION_SCHEMA)


def recalibrate(conn: sqlite3.Connection) -> list[CalibrationBucket]:
    """Recompute calibration buckets from adjudication_records.

    Requires that adjudication_records has at least ``predicted_status``,
    ``predicted_confidence``, ``actual_outcome``, and ``sink_type`` /
    ``unknown_reason`` columns.  Rows where ``actual_outcome`` is NULL
    are skipped.

    Returns the resulting bucket list.
    """

    ensure_calibration_schema(conn)

    # Check whether the source table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='adjudication_records'"
    )
    if cursor.fetchone() is None:
        return []

    now = datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        """
        SELECT sink_type, unknown_reason, predicted_confidence,
               COUNT(*) AS sample_count,
               SUM(CASE WHEN predicted_status = actual_outcome THEN 1 ELSE 0 END) AS correct_count
        FROM adjudication_records
        WHERE actual_outcome IS NOT NULL
        GROUP BY sink_type, unknown_reason, predicted_confidence
        """
    ).fetchall()

    buckets: list[CalibrationBucket] = []
    conn.execute("DELETE FROM calibration_buckets")
    for sink_type, unknown_reason, predicted_confidence, sample_count, correct_count in rows:
        precision = correct_count / sample_count if sample_count > 0 else None
        conn.execute(
            """
            INSERT INTO calibration_buckets
                (sink_type, unknown_reason, predicted_confidence, sample_count, correct_count, actual_precision, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (sink_type, unknown_reason or "", predicted_confidence, sample_count, correct_count, precision, now),
        )
        buckets.append(
            CalibrationBucket(
                sink_type=sink_type,
                unknown_reason=unknown_reason or "",
                predicted_confidence=predicted_confidence,
                sample_count=sample_count,
                correct_count=correct_count,
                actual_precision=precision,
                last_updated=now,
            )
        )
    conn.commit()
    return buckets


def lookup_calibration(
    conn: sqlite3.Connection,
    sink_type: str,
    unknown_reason: str,
    predicted_confidence: str,
    *,
    cold_start_threshold: int = _DEFAULT_COLD_START_THRESHOLD,
) -> str:
    """Return the calibrated confidence for a given bucket.

    If the bucket does not exist or has fewer than *cold_start_threshold*
    samples, the original *predicted_confidence* is returned unchanged.
    """

    ensure_calibration_schema(conn)

    row = conn.execute(
        """
        SELECT sample_count, actual_precision
        FROM calibration_buckets
        WHERE sink_type = ? AND unknown_reason = ? AND predicted_confidence = ?
        """,
        (sink_type, unknown_reason or "", predicted_confidence),
    ).fetchone()

    if row is None:
        return predicted_confidence

    sample_count, actual_precision = row
    if sample_count < cold_start_threshold:
        return predicted_confidence

    if actual_precision is not None and actual_precision < 0.7:
        return _CONFIDENCE_DOWNGRADE.get(predicted_confidence, predicted_confidence)

    return predicted_confidence


def list_buckets(conn: sqlite3.Connection) -> list[CalibrationBucket]:
    """Return all calibration buckets for reporting."""

    ensure_calibration_schema(conn)

    rows = conn.execute(
        "SELECT sink_type, unknown_reason, predicted_confidence, sample_count, correct_count, actual_precision, last_updated "
        "FROM calibration_buckets ORDER BY sink_type, unknown_reason, predicted_confidence"
    ).fetchall()

    return [
        CalibrationBucket(
            sink_type=r[0],
            unknown_reason=r[1],
            predicted_confidence=r[2],
            sample_count=r[3],
            correct_count=r[4],
            actual_precision=r[5],
            last_updated=r[6],
        )
        for r in rows
    ]
