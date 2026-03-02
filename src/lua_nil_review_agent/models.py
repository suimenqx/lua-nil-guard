from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
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
class AutofixPatch:
    """A machine-applicable patch derived from a verified fix suggestion."""

    case_id: str
    file: str
    action: str
    start_line: int
    end_line: int
    replacement: str
    expected_original: str = ""


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
    autofix_patch: AutofixPatch | None = None


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Resolved repository inputs used to start a review run."""

    root: Path
    sink_rules: tuple[SinkRule, ...]
    confidence_policy: ConfidencePolicy
    lua_files: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class StaticAnalysisResult:
    """A bounded local nullability judgment for a single candidate."""

    state: str
    observed_guards: tuple[str, ...]
    origin_candidates: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CandidateAssessment:
    """A candidate paired with its local static analysis result."""

    candidate: CandidateCase
    static_analysis: StaticAnalysisResult


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """A reusable summary of a function's local nil-relevant behavior."""

    function_id: str
    file: str
    function_name: str
    line: int
    params: dict[str, str]
    guards: tuple[str, ...]
    returns: tuple[str, ...]
    confidence: str
    source: str


@dataclass(frozen=True, slots=True)
class KnowledgeFact:
    """A persisted safe/risky fact derived from prior review."""

    key: str
    subject: str
    statement: str
    confidence: str
    source: str


@dataclass(frozen=True, slots=True)
class RoleOpinion:
    """A single agent-role opinion used during adjudication."""

    role: str
    status: str
    confidence: str
    risk_path: tuple[str, ...]
    safety_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    recommended_next_action: str
    suggested_fix: str | None


@dataclass(frozen=True, slots=True)
class AdjudicationRecord:
    """The full prosecutor/defender/judge result set for one case."""

    prosecutor: RoleOpinion
    defender: RoleOpinion
    judge: Verdict


@dataclass(frozen=True, slots=True)
class BenchmarkCaseResult:
    """One labeled benchmark case compared against an observed verdict."""

    case_id: str
    file: str
    expected_status: str
    actual_status: str
    matches_expectation: bool
    backend_failure_reason: str | None = None


@dataclass(frozen=True, slots=True)
class BenchmarkSummary:
    """Aggregate benchmark metrics for labeled review samples."""

    total_cases: int
    exact_matches: int
    expected_risky: int
    expected_safe: int
    expected_uncertain: int
    actual_risky: int
    actual_safe: int
    actual_uncertain: int
    false_positive_risks: int
    missed_risks: int
    unresolved_cases: int
    backend_fallbacks: int
    backend_timeouts: int
    backend_cache_hits: int
    backend_cache_misses: int
    backend_calls: int
    backend_total_seconds: float
    backend_average_seconds: float
    cases: tuple[BenchmarkCaseResult, ...]


def with_candidate_state(candidate: CandidateCase, state: str) -> CandidateCase:
    """Return a candidate copy with an updated static state."""

    return replace(candidate, static_state=state)
