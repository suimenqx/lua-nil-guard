from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SinkRule:
    """A machine-readable description of a nil-sensitive sink."""

    id: str
    kind: str
    qualified_name: str
    arg_index: int
    nil_sensitive: bool
    failure_mode: str
    default_severity: str
    safe_patterns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConfidencePolicy:
    """Global thresholds used for reporting and audit output."""

    levels: tuple[str, ...]
    default_report_min_confidence: str
    default_include_medium_in_audit: bool
