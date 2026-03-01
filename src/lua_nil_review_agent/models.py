from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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


@dataclass(frozen=True, slots=True)
class CandidateCase:
    """A single sink event collected for downstream review."""

    case_id: str
    file: str
    line: int
    column: int
    sink_rule_id: str
    sink_name: str
    arg_index: int
    expression: str
    symbol: str
    function_scope: str
    static_state: str


@dataclass(frozen=True, slots=True)
class EvidenceTarget:
    """The precise sink location under review."""

    file: str
    line: int
    column: int
    sink: str
    arg_index: int
    expression: str


@dataclass(frozen=True, slots=True)
class EvidencePacket:
    """The structured context sent to adjudication agents."""

    case_id: str
    target: EvidenceTarget
    local_context: str
    related_functions: tuple[str, ...]
    function_summaries: tuple[str, ...]
    knowledge_facts: tuple[str, ...]
    static_reasoning: dict[str, tuple[str, ...] | str]


@dataclass(frozen=True, slots=True)
class Verdict:
    """A final or intermediate adjudication result for a case."""

    case_id: str
    status: str
    confidence: str
    risk_path: tuple[str, ...]
    safety_evidence: tuple[str, ...]
    counterarguments_considered: tuple[str, ...]
    suggested_fix: str | None
    needs_human: bool


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Resolved repository inputs used to start a review run."""

    root: Path
    sink_rules: tuple[SinkRule, ...]
    confidence_policy: ConfidencePolicy
    lua_files: tuple[Path, ...]
