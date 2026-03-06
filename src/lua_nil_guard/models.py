from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
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
    candidate_source: str = "ast_exact"


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
    related_function_contexts: tuple[str, ...] = ()
    static_proofs: tuple["StaticProof", ...] = ()
    static_risk_signals: tuple["StaticRiskSignal", ...] = ()


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
class VerificationSummary:
    """Structured metadata explaining why a verdict was auto-verified or elevated."""

    mode: str
    strongest_proof_kind: str | None = None
    strongest_proof_depth: int | None = None
    strongest_proof_summary: str | None = None
    verification_score: int | None = None
    evidence: tuple[str, ...] = ()


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
    verification_summary: VerificationSummary | None = None


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Resolved repository inputs used to start a review run."""

    root: Path
    sink_rules: tuple[SinkRule, ...]
    confidence_policy: ConfidencePolicy
    lua_files: tuple[Path, ...]
    preprocessor_files: tuple[Path, ...] = ()
    macro_index: "MacroIndex | None" = None
    macro_cache_status: "MacroCacheStatus | None" = None
    function_contracts: tuple["FunctionContract", ...] = ()


@dataclass(frozen=True, slots=True)
class PreprocessorConfig:
    """Repository-level configuration for preprocessor dictionary files."""

    preprocessor_files: tuple[str, ...] = ()
    preprocessor_globs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MacroFact:
    """One parsed and optionally resolved compile-time macro fact."""

    key: str
    kind: str
    value: str | None
    provably_non_nil: bool
    file: str
    line: int
    resolved_kind: str | None = None
    resolved_value: str | None = None
    alias_target: str | None = None


@dataclass(frozen=True, slots=True)
class MacroUnresolvedLine:
    """One macro dictionary line that could not be safely interpreted."""

    file: str
    line: int
    content: str
    reason: str


@dataclass(frozen=True, slots=True)
class MacroIndex:
    """Structured compile-time macro facts available to static analysis."""

    facts: tuple[MacroFact, ...] = ()
    unresolved_lines: tuple[MacroUnresolvedLine, ...] = ()
    fact_by_key: dict[str, MacroFact] = field(default_factory=dict, repr=False, compare=False)
    missing_keys: set[str] = field(default_factory=set, repr=False, compare=False)
    cache_db_path: str | None = None
    cache_connection: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class MacroCacheStatus:
    """Operator-facing summary of compiled macro cache state."""

    path: str
    state: str
    reason: str
    configured_files: tuple[str, ...] = ()
    file_count: int = 0
    fact_count: int = 0
    unresolved_count: int = 0
    parser_version: int = 0


@dataclass(frozen=True, slots=True)
class MacroAuditResult:
    """Operator-facing summary of macro dictionary ingestion."""

    files: tuple[str, ...]
    facts: tuple[MacroFact, ...]
    unresolved_lines: tuple[MacroUnresolvedLine, ...]


@dataclass(frozen=True, slots=True)
class StaticAnalysisResult:
    """A bounded local nullability judgment for a single candidate."""

    state: str
    observed_guards: tuple[str, ...]
    origin_candidates: tuple[str, ...]
    origin_usage_modes: tuple[str, ...] = ()
    origin_return_slots: tuple[int, ...] = ()
    proofs: tuple["StaticProof", ...] = ()
    risk_signals: tuple["StaticRiskSignal", ...] = ()
    analysis_mode: str = "legacy_only"
    unknown_reason: str | None = None
    origin_analysis_mode: str = "legacy_origin_only"
    origin_unknown_reason: str | None = None


@dataclass(frozen=True, slots=True)
class StaticProof:
    """A structured explanation for one local non-nil proof."""

    kind: str
    summary: str
    subject: str
    source_symbol: str | None = None
    source_call: str | None = None
    source_function: str | None = None
    supporting_summaries: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    depth: int = 0


@dataclass(frozen=True, slots=True)
class StaticRiskSignal:
    """A structured explanation for one bounded local risk proof."""

    kind: str
    summary: str
    subject: str
    source_expression: str | None = None
    provenance: tuple[str, ...] = ()
    depth: int = 0


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
    qualified_name: str
    line: int
    params: dict[str, str]
    guards: tuple[str, ...]
    returns: tuple[str, ...]
    confidence: str
    source: str
    module_name: str | None = None


@dataclass(frozen=True, slots=True)
class FunctionContract:
    """A user-configured callable contract that can suppress nil-risk false positives."""

    qualified_name: str
    returns_non_nil: bool
    ensures_non_nil_args: tuple[int, ...] = ()
    returns_non_nil_from_args: tuple[int, ...] = ()
    returns_non_nil_from_args_by_return_slot: tuple[tuple[int, tuple[int, ...]], ...] = ()
    requires_guarded_args_by_return_slot: tuple[tuple[int, tuple[int, ...]], ...] = ()
    applies_in_modules: tuple[str, ...] = ()
    applies_in_function_scopes: tuple[str, ...] = ()
    applies_to_top_level_phases: tuple[str, ...] = ()
    applies_to_scope_kinds: tuple[str, ...] = ()
    applies_to_sinks: tuple[str, ...] = ()
    applies_to_call_roles: tuple[str, ...] = ()
    applies_to_usage_modes: tuple[str, ...] = ()
    applies_to_return_slots: tuple[int, ...] = ()
    applies_with_arg_count: int | None = None
    required_literal_args: tuple[tuple[int, tuple[str, ...]], ...] = ()
    required_arg_shapes: tuple[tuple[int, tuple[str, ...]], ...] = ()
    required_arg_roots: tuple[tuple[int, tuple[str, ...]], ...] = ()
    required_arg_prefixes: tuple[tuple[int, tuple[str, ...]], ...] = ()
    required_arg_access_paths: tuple[tuple[int, tuple[str, ...]], ...] = ()
    notes: str | None = None


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
class SinglePassJudgment:
    """A single-pass structured adjudication result (V3 replacement for multi-role)."""

    verdict: Verdict
    raw_response: str
    backend_metadata: dict = field(default_factory=dict, compare=False)


@dataclass(frozen=True, slots=True)
class AnnotationFact:
    """A nil-guard annotation parsed from a Lua comment."""

    function_id: str
    file: str
    line: int
    annotation_type: str
    param_name: str | None = None
    param_index: int | None = None
    return_slot: int | None = None
    nullability: str = "non_nil"
    condition: str | None = None
    raw_text: str = ""


@dataclass(frozen=True, slots=True)
class AnnotationVerification:
    """Result of verifying an annotation against its function body."""

    annotation: AnnotationFact
    consistent: bool
    evidence: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    confidence: str = "low"


@dataclass(frozen=True, slots=True)
class AdjudicationPolicy:
    """Controls the adjudication mode and calibration settings."""

    adjudication_mode: str = "single_pass"
    ab_test_enabled: bool = False
    ab_test_split_ratio: float = 0.5
    ab_test_seed: int = 42
    calibration_cold_start_threshold: int = 30
    calibration_recalibrate_interval_runs: int = 5


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
    backend_name: str
    backend_model: str | None
    backend_executable: str | None
    cases: tuple[BenchmarkCaseResult, ...]
    backend_warmup_calls: int = 0
    backend_warmup_total_seconds: float = 0.0
    backend_review_calls: int = 0
    backend_review_total_seconds: float = 0.0
    backend_review_average_seconds: float = 0.0
    ast_primary_cases: int = 0
    ast_fallback_to_legacy_cases: int = 0
    legacy_only_cases: int = 0


@dataclass(frozen=True, slots=True)
class BenchmarkCacheComparison:
    """A two-pass benchmark result for cold and warm backend cache runs."""

    cache_path: str
    cache_cleared_entries: int
    cold: BenchmarkSummary
    warm: BenchmarkSummary


@dataclass(frozen=True, slots=True)
class ImprovementProposal:
    """A draft-only suggestion for improving precision on unresolved review cases."""

    kind: str
    case_id: str
    file: str
    status: str
    confidence: str
    reason: str
    suggested_contract: FunctionContract | None = None
    suggested_pattern: str | None = None
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ImprovementAnalytics:
    """Aggregate counts derived from draft improvement proposals."""

    total_proposals: int
    unique_cases: int
    unresolved_proposals: int
    medium_reportable_proposals: int
    by_kind: tuple[tuple[str, int], ...]
    by_reason: tuple[tuple[str, int], ...]
    by_pattern: tuple[tuple[str, int], ...] = ()
    by_contract: tuple[tuple[str, int], ...] = ()
    unresolved_by_kind: tuple[tuple[str, int], ...] = ()
    medium_reportable_by_kind: tuple[tuple[str, int], ...] = ()


def with_candidate_state(candidate: CandidateCase, state: str) -> CandidateCase:
    """Return a candidate copy with an updated static state."""

    return replace(candidate, static_state=state)
