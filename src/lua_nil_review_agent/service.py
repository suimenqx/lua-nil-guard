from __future__ import annotations

import difflib
from dataclasses import dataclass
import json
import re
from pathlib import Path
from typing import Callable

from .adjudication import attach_autofix_patch
from .agent_driver_models import AgentProviderSpec
from .agent_backend import AdjudicationBackend, CliAgentBackend, HeuristicAdjudicationBackend
from .collector import collect_candidates
from .config_loader import load_confidence_policy, load_function_contracts, load_sink_rules
from .knowledge import (
    KnowledgeBase,
    contract_applies_in_function_scope,
    contract_applies_in_module,
    contract_applies_to_call,
    contract_applies_to_sink,
    derive_facts_from_contracts,
    derive_facts_from_summaries,
    facts_for_subject,
)
from .models import (
    AdjudicationRecord,
    AutofixPatch,
    BenchmarkCacheComparison,
    BenchmarkCaseResult,
    BenchmarkSummary,
    CandidateAssessment,
    EvidencePacket,
    RepositorySnapshot,
    SinkRule,
    Verdict,
    with_candidate_state,
)
from .pipeline import build_evidence_packet, should_report
from .prompting import build_adjudication_prompt
from .repository import discover_lua_files
from .summaries import SummaryStore, detect_module_name, summarize_source
from .static_analysis import analyze_candidate
from .verification import verify_verdict


_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*)\s*\(")
_CALL_EXPRESSION_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*)\s*\((.*)\)\s*$"
)
_INLINE_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*)\s*\("
)
_FUNCTION_BLOCK_RE = re.compile(
    r"\b(?:local\s+)?function(?:\s+[A-Za-z_][A-Za-z0-9_.:]*|\s*)\s*\("
)
_CONTROL_FLOW_START_RE = re.compile(r"^\s*(if|for|while)\b")
_LUA_KEYWORDS = frozenset(
    {
        "and",
        "break",
        "do",
        "elseif",
        "end",
        "for",
        "function",
        "if",
        "local",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "until",
        "while",
    }
)
_MAX_RELATED_FUNCTION_CONTEXTS = 4
_MAX_RELATED_FUNCTION_CONTEXT_LINES = 48
_MAX_RELATED_FUNCTION_SUMMARIES = 8
_EXPANDED_RELATED_FUNCTION_CONTEXTS = 6
_EXPANDED_RELATED_FUNCTION_CONTEXT_LINES = 72
_EXPANDED_RELATED_FUNCTION_SUMMARIES = 12
_TRUNCATED_CONTEXT_MARKER = "  ... (truncated)"


@dataclass(frozen=True, slots=True)
class _FunctionContextBlock:
    qualified_name: str
    file: str
    line: int
    evidence_score: int
    rendered: str
    callees: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RelatedEvidenceSelection:
    function_names: tuple[str, ...]
    summary_texts: tuple[str, ...]
    context_texts: tuple[str, ...]


def bootstrap_repository(root: str | Path) -> RepositorySnapshot:
    """Load the current repository's core review inputs."""

    root_path = Path(root)
    sink_rules = tuple(load_sink_rules(root_path / "config" / "sink_rules.json"))
    confidence_policy = load_confidence_policy(root_path / "config" / "confidence_policy.json")
    lua_files = tuple(discover_lua_files(root_path))
    contracts_path = root_path / "config" / "function_contracts.json"
    function_contracts = (
        tuple(load_function_contracts(contracts_path))
        if contracts_path.is_file()
        else ()
    )

    return RepositorySnapshot(
        root=root_path,
        sink_rules=sink_rules,
        confidence_policy=confidence_policy,
        lua_files=lua_files,
        function_contracts=function_contracts,
    )


def find_repository_root_for_file(file_path: str | Path) -> Path:
    """Resolve the nearest repository root for a Lua file by walking up to config/."""

    target = Path(file_path).resolve(strict=False)
    if target.suffix.lower() != ".lua":
        raise ValueError(f"single-file review requires a .lua file: {file_path}")
    if not target.is_file():
        raise FileNotFoundError(f"Lua file not found: {file_path}")

    for candidate_root in target.parents:
        config_dir = candidate_root / "config"
        if (
            (config_dir / "sink_rules.json").is_file()
            and (config_dir / "confidence_policy.json").is_file()
        ):
            return candidate_root

    raise ValueError(
        "Could not locate repository root for Lua file. "
        "Expected config/sink_rules.json and config/confidence_policy.json in this "
        f"directory or an ancestor: {file_path}"
    )


def review_source(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
    *,
    function_contracts: tuple[object, ...] = (),
) -> tuple[CandidateAssessment, ...]:
    """Collect candidates from one source file and attach local static analysis."""

    assessments: list[CandidateAssessment] = []
    for candidate in collect_candidates(file_path, source, sink_rules):
        static_analysis = analyze_candidate(
            source,
            candidate,
            function_contracts=tuple(function_contracts),
        )
        assessments.append(
            CandidateAssessment(
                candidate=with_candidate_state(candidate, static_analysis.state),
                static_analysis=static_analysis,
            )
        )
    return tuple(assessments)


def review_repository(snapshot: RepositorySnapshot) -> tuple[CandidateAssessment, ...]:
    """Run the current static first-pass review across all discovered Lua files."""

    assessments: list[CandidateAssessment] = []
    for file_path in snapshot.lua_files:
        source = file_path.read_text(encoding="utf-8")
        assessments.extend(
            review_source(
                file_path,
                source,
                snapshot.sink_rules,
                function_contracts=snapshot.function_contracts,
            )
        )
    return tuple(assessments)


def review_repository_file(
    snapshot: RepositorySnapshot,
    file_path: str | Path,
) -> tuple[CandidateAssessment, ...]:
    """Run the current static first-pass review for one Lua file in a repository snapshot."""

    resolved_file = _resolve_snapshot_lua_file(snapshot, file_path)
    source = resolved_file.read_text(encoding="utf-8")
    return review_source(
        resolved_file,
        source,
        snapshot.sink_rules,
        function_contracts=snapshot.function_contracts,
    )


def prepare_evidence_packet(
    assessment: CandidateAssessment,
    source: str,
    *,
    related_functions: tuple[str, ...] = (),
    function_summaries: tuple[str, ...] = (),
    knowledge_facts: tuple[str, ...] = (),
    related_function_contexts: tuple[str, ...] = (),
    context_radius: int = 2,
) -> EvidencePacket:
    """Convert a locally analyzed candidate into an agent-ready evidence packet."""

    lines = source.splitlines()
    start = max(0, assessment.candidate.line - 1 - context_radius)
    end = min(len(lines), assessment.candidate.line + context_radius)
    local_context = "\n".join(lines[start:end])

    return build_evidence_packet(
        candidate=assessment.candidate,
        local_context=local_context,
        related_functions=related_functions,
        function_summaries=function_summaries,
        knowledge_facts=knowledge_facts,
        origin_candidates=assessment.static_analysis.origin_candidates,
        origin_usage_modes=assessment.static_analysis.origin_usage_modes,
        observed_guards=assessment.static_analysis.observed_guards,
        related_function_contexts=related_function_contexts,
    )


def run_repository_review(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> tuple[Verdict, ...]:
    """Run the current end-to-end local review pipeline across a repository."""

    assessments = review_repository(snapshot)
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    adjudication_backend = backend or HeuristicAdjudicationBackend()

    return _run_review_from_assessments(
        snapshot,
        assessments,
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
    )


def run_file_review(
    snapshot: RepositorySnapshot,
    file_path: str | Path,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> tuple[Verdict, ...]:
    """Run the current end-to-end review pipeline for one Lua file with repository context."""

    assessments = review_repository_file(snapshot, file_path)
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    adjudication_backend = backend or HeuristicAdjudicationBackend()

    return _run_review_from_assessments(
        snapshot,
        assessments,
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
    )


def benchmark_repository_review(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> BenchmarkSummary:
    """Run a labeled semantic benchmark over provable_* Lua review fixtures."""

    assessments = review_repository(snapshot)
    labeled_assessments = tuple(
        (assessment, _expected_benchmark_label(assessment.candidate.file))
        for assessment in assessments
        if _expected_benchmark_label(assessment.candidate.file) is not None
    )
    if not labeled_assessments:
        raise ValueError(
            "benchmark requires labeled files named provable_risky_*, "
            "provable_safe_* or provable_uncertain_*"
        )

    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = (
        _load_knowledge_facts(snapshot, knowledge_path)
        if knowledge_path is not None
        else _merge_knowledge_facts(
            derive_facts_from_summaries(summaries),
            derive_facts_from_contracts(snapshot.function_contracts),
        )
    )
    adjudication_backend = backend or HeuristicAdjudicationBackend()
    verdicts = _run_review_from_assessments(
        snapshot,
        tuple(assessment for assessment, _ in labeled_assessments),
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
    )
    verdict_by_case_id = {verdict.case_id: verdict for verdict in verdicts}

    cases: list[BenchmarkCaseResult] = []
    for assessment, expected in labeled_assessments:
        verdict = verdict_by_case_id[assessment.candidate.case_id]
        actual = _normalize_benchmark_status(verdict.status)
        backend_failure_reason = _extract_backend_failure_reason(verdict)
        cases.append(
            BenchmarkCaseResult(
                case_id=assessment.candidate.case_id,
                file=assessment.candidate.file,
                expected_status=expected,
                actual_status=actual,
                matches_expectation=actual == expected,
                backend_failure_reason=backend_failure_reason,
            )
        )

    expected_risky = sum(1 for case in cases if case.expected_status == "risky")
    expected_safe = sum(1 for case in cases if case.expected_status == "safe")
    expected_uncertain = sum(1 for case in cases if case.expected_status == "uncertain")
    actual_risky = sum(1 for case in cases if case.actual_status == "risky")
    actual_safe = sum(1 for case in cases if case.actual_status == "safe")
    actual_uncertain = sum(1 for case in cases if case.actual_status == "uncertain")
    backend_cache_hits = _backend_metric(adjudication_backend, "cache_hits")
    backend_cache_misses = _backend_metric(adjudication_backend, "cache_misses")
    backend_calls = _backend_metric(adjudication_backend, "backend_call_count")
    backend_total_seconds = _backend_float_metric(adjudication_backend, "backend_total_seconds")
    backend_warmup_calls = _backend_metric(adjudication_backend, "backend_warmup_call_count")
    backend_warmup_total_seconds = _backend_float_metric(
        adjudication_backend,
        "backend_warmup_total_seconds",
    )
    backend_average_seconds = 0.0
    if backend_calls:
        backend_average_seconds = backend_total_seconds / backend_calls
    backend_review_calls = max(0, backend_calls - backend_warmup_calls)
    backend_review_total_seconds = max(0.0, backend_total_seconds - backend_warmup_total_seconds)
    backend_review_average_seconds = 0.0
    if backend_review_calls:
        backend_review_average_seconds = backend_review_total_seconds / backend_review_calls
    backend_name = _backend_name(adjudication_backend)
    backend_model = _backend_optional_string(adjudication_backend, "model")
    backend_executable = _backend_optional_string(adjudication_backend, "executable")

    return BenchmarkSummary(
        total_cases=len(cases),
        exact_matches=sum(1 for case in cases if case.matches_expectation),
        expected_risky=expected_risky,
        expected_safe=expected_safe,
        expected_uncertain=expected_uncertain,
        actual_risky=actual_risky,
        actual_safe=actual_safe,
        actual_uncertain=actual_uncertain,
        false_positive_risks=sum(
            1 for case in cases if case.actual_status == "risky" and case.expected_status != "risky"
        ),
        missed_risks=sum(
            1 for case in cases if case.expected_status == "risky" and case.actual_status != "risky"
        ),
        unresolved_cases=sum(
            1
            for case in cases
            if case.actual_status == "uncertain" and case.expected_status in {"risky", "safe"}
        ),
        backend_fallbacks=sum(1 for case in cases if case.backend_failure_reason is not None),
        backend_timeouts=sum(
            1
            for case in cases
            if case.backend_failure_reason is not None
            and "timed out" in case.backend_failure_reason.lower()
        ),
        backend_cache_hits=backend_cache_hits,
        backend_cache_misses=backend_cache_misses,
        backend_calls=backend_calls,
        backend_total_seconds=backend_total_seconds,
        backend_average_seconds=backend_average_seconds,
        backend_name=backend_name,
        backend_model=backend_model,
        backend_executable=backend_executable,
        cases=tuple(cases),
        backend_warmup_calls=backend_warmup_calls,
        backend_warmup_total_seconds=backend_warmup_total_seconds,
        backend_review_calls=backend_review_calls,
        backend_review_total_seconds=backend_review_total_seconds,
        backend_review_average_seconds=backend_review_average_seconds,
    )


def benchmark_cache_compare(
    snapshot: RepositorySnapshot,
    *,
    backend_factory: Callable[[], AdjudicationBackend],
    cache_path: str | Path,
    knowledge_path: str | Path | None = None,
) -> BenchmarkCacheComparison:
    """Run benchmark twice to compare cold-start and warm-cache backend behavior."""

    cleared_entries = clear_backend_cache(cache_path)
    cold_backend = backend_factory()
    cold = benchmark_repository_review(
        snapshot,
        backend=cold_backend,
        knowledge_path=knowledge_path,
    )
    warm_backend = backend_factory()
    warm = benchmark_repository_review(
        snapshot,
        backend=warm_backend,
        knowledge_path=knowledge_path,
    )
    return BenchmarkCacheComparison(
        cache_path=str(Path(cache_path)),
        cache_cleared_entries=cleared_entries,
        cold=cold,
        warm=warm,
    )


def _run_review_from_assessments(
    snapshot: RepositorySnapshot,
    assessments: tuple[CandidateAssessment, ...],
    *,
    adjudication_backend: AdjudicationBackend,
    summary_text_by_name: dict[str, tuple[str, ...]],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    file_module_by_path: dict[str, str | None],
    facts: tuple[object, ...],
) -> tuple[Verdict, ...]:
    sink_rule_by_id = {rule.id: rule for rule in snapshot.sink_rules}
    assessments_by_file: dict[str, list[CandidateAssessment]] = {}
    for assessment in assessments:
        assessments_by_file.setdefault(assessment.candidate.file, []).append(assessment)

    verdicts: list[Verdict] = []
    for file_path in snapshot.lua_files:
        source = file_path.read_text(encoding="utf-8")
        for assessment in assessments_by_file.get(str(file_path), ()):
            related_evidence = _build_related_evidence(
                assessment,
                summary_text_by_name=summary_text_by_name,
                function_context_by_name=function_context_by_name,
                file_module_by_path=file_module_by_path,
            )
            knowledge_facts = _knowledge_facts_for_assessment(
                assessment,
                related_evidence.function_names,
                facts,
                function_contracts=snapshot.function_contracts,
                current_module=file_module_by_path.get(_normalize_path_key(assessment.candidate.file)),
            )
            packet = prepare_evidence_packet(
                assessment,
                source,
                related_functions=related_evidence.function_names,
                function_summaries=related_evidence.summary_texts,
                knowledge_facts=knowledge_facts,
                related_function_contexts=related_evidence.context_texts,
            )
            adjudication = adjudication_backend.adjudicate(
                packet,
                sink_rule_by_id[assessment.candidate.sink_rule_id],
            )
            verdict = attach_autofix_patch(
                adjudication.judge,
                packet,
                sink_rule_by_id[assessment.candidate.sink_rule_id],
            )
            final_verdict = verify_verdict(verdict, packet)
            if _should_retry_with_expanded_evidence(
                adjudication_backend,
                adjudication,
                final_verdict,
            ):
                expanded_related_evidence = _build_related_evidence(
                    assessment,
                    summary_text_by_name=summary_text_by_name,
                    function_context_by_name=function_context_by_name,
                    file_module_by_path=file_module_by_path,
                    max_depth=2,
                    max_contexts=_EXPANDED_RELATED_FUNCTION_CONTEXTS,
                    max_context_lines=_EXPANDED_RELATED_FUNCTION_CONTEXT_LINES,
                    max_summary_items=_EXPANDED_RELATED_FUNCTION_SUMMARIES,
                )
                if expanded_related_evidence != related_evidence:
                    expanded_packet = prepare_evidence_packet(
                        assessment,
                        source,
                        related_functions=expanded_related_evidence.function_names,
                        function_summaries=expanded_related_evidence.summary_texts,
                        knowledge_facts=_knowledge_facts_for_assessment(
                            assessment,
                            expanded_related_evidence.function_names,
                            facts,
                            function_contracts=snapshot.function_contracts,
                            current_module=file_module_by_path.get(
                                _normalize_path_key(assessment.candidate.file)
                            ),
                        ),
                        related_function_contexts=expanded_related_evidence.context_texts,
                    )
                    expanded_adjudication = adjudication_backend.adjudicate(
                        expanded_packet,
                        sink_rule_by_id[assessment.candidate.sink_rule_id],
                    )
                    expanded_verdict = attach_autofix_patch(
                        expanded_adjudication.judge,
                        expanded_packet,
                        sink_rule_by_id[assessment.candidate.sink_rule_id],
                    )
                    final_verdict = verify_verdict(expanded_verdict, expanded_packet)
            verdicts.append(final_verdict)
    return tuple(verdicts)


def refresh_summary_cache(
    snapshot: RepositorySnapshot,
    *,
    summary_path: str | Path | None = None,
) -> tuple[object, ...]:
    """Rebuild and persist the repository function summary cache."""

    summaries = _collect_repository_summaries(snapshot)
    path = Path(summary_path) if summary_path is not None else snapshot.root / "data" / "function_summaries.json"
    SummaryStore(path).save(summaries)
    return summaries


def refresh_knowledge_base(
    snapshot: RepositorySnapshot,
    *,
    knowledge_path: str | Path | None = None,
) -> tuple[object, ...]:
    """Rebuild and persist repository knowledge facts derived from summaries."""

    summaries = _collect_repository_summaries(snapshot)
    facts = _merge_knowledge_facts(
        derive_facts_from_summaries(summaries),
        derive_facts_from_contracts(snapshot.function_contracts),
    )
    path = Path(knowledge_path) if knowledge_path is not None else snapshot.root / "data" / "knowledge.json"
    KnowledgeBase(path).save(facts)
    return facts


def export_adjudication_tasks(
    snapshot: RepositorySnapshot,
    *,
    knowledge_path: str | Path | None = None,
    output_path: str | Path | None = None,
    skill_path: str | Path | None = None,
    strict_skill: bool = True,
) -> tuple[dict[str, object], ...]:
    """Export agent-ready prompt tasks for all collected candidates."""

    sink_rule_by_id = {rule.id: rule for rule in snapshot.sink_rules}
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    tasks: list[dict[str, object]] = []

    for file_path in snapshot.lua_files:
        source = file_path.read_text(encoding="utf-8")
        for assessment in review_source(
            file_path,
            source,
            snapshot.sink_rules,
            function_contracts=snapshot.function_contracts,
        ):
            related_evidence = _build_related_evidence(
                assessment,
                summary_text_by_name=summary_text_by_name,
                function_context_by_name=function_context_by_name,
                file_module_by_path=file_module_by_path,
            )
            knowledge_facts = tuple(
                _knowledge_facts_for_assessment(
                    assessment,
                    related_evidence.function_names,
                    facts,
                    function_contracts=snapshot.function_contracts,
                    current_module=file_module_by_path.get(_normalize_path_key(assessment.candidate.file)),
                )
            )
            packet = prepare_evidence_packet(
                assessment,
                source,
                related_functions=related_evidence.function_names,
                function_summaries=related_evidence.summary_texts,
                knowledge_facts=knowledge_facts,
                related_function_contexts=related_evidence.context_texts,
            )
            sink_rule = sink_rule_by_id[assessment.candidate.sink_rule_id]
            tasks.append(
                {
                    "case_id": assessment.candidate.case_id,
                    "sink_rule_id": sink_rule.id,
                    "file": assessment.candidate.file,
                    "line": assessment.candidate.line,
                    "function_scope": assessment.candidate.function_scope,
                    "prompt": build_adjudication_prompt(
                        packet=packet,
                        sink_rule=sink_rule,
                        skill_path=skill_path,
                        strict_skill=strict_skill,
                    ),
                }
            )

    task_tuple = tuple(tasks)
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(task_tuple, indent=2, sort_keys=True), encoding="utf-8")
    return task_tuple


def export_autofix_patches(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
    output_path: str | Path | None = None,
    audit_mode: bool = False,
) -> tuple[AutofixPatch, ...]:
    """Export machine-applicable autofix patches for current reportable findings."""

    verdicts = run_repository_review(
        snapshot,
        backend=backend,
        knowledge_path=knowledge_path,
    )
    patches = tuple(
        verdict.autofix_patch
        for verdict in verdicts
        if verdict.autofix_patch is not None
        and should_report(verdict, snapshot.confidence_policy, audit_mode=audit_mode)
    )
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps([_serialize_autofix_patch(patch) for patch in patches], indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return patches


def clear_backend_cache(cache_path: str | Path) -> int:
    """Remove a persisted backend cache file and return the removed entry count."""

    path = Path(cache_path)
    if not path.exists():
        return 0

    removed_entries = 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        removed_entries = len(payload)

    path.unlink()
    return removed_entries


def apply_autofix_manifest(
    manifest_path: str | Path,
    *,
    dry_run: bool = False,
    case_ids: tuple[str, ...] = (),
    file_paths: tuple[str | Path, ...] = (),
) -> tuple[tuple[AutofixPatch, ...], tuple[str, ...]]:
    """Apply an exported autofix manifest with per-file conflict checks."""

    patches = _filter_autofix_patches(
        _load_autofix_manifest(manifest_path),
        case_ids=case_ids,
        file_paths=file_paths,
    )
    grouped: dict[Path, list[AutofixPatch]] = {}
    for patch in patches:
        grouped.setdefault(Path(patch.file), []).append(patch)

    applied: list[AutofixPatch] = []
    conflicts: list[str] = []

    for file_path, file_patches in grouped.items():
        file_applied, file_conflicts = _apply_autofix_group(
            file_path,
            tuple(file_patches),
            dry_run=dry_run,
        )
        applied.extend(file_applied)
        conflicts.extend(file_conflicts)

    return tuple(applied), tuple(conflicts)


def export_autofix_unified_diff(
    manifest_path: str | Path,
    *,
    output_path: str | Path | None = None,
    case_ids: tuple[str, ...] = (),
    file_paths: tuple[str | Path, ...] = (),
) -> tuple[str, tuple[str, ...]]:
    """Render a unified diff from an exported autofix manifest."""

    patches = _filter_autofix_patches(
        _load_autofix_manifest(manifest_path),
        case_ids=case_ids,
        file_paths=file_paths,
    )
    grouped: dict[Path, list[AutofixPatch]] = {}
    for patch in patches:
        grouped.setdefault(Path(patch.file), []).append(patch)

    diffs: list[str] = []
    conflicts: list[str] = []

    for file_path, file_patches in grouped.items():
        original_text, updated_text, _, file_conflicts = _simulate_autofix_group(
            file_path,
            tuple(file_patches),
        )
        if file_conflicts:
            conflicts.extend(file_conflicts)
            continue
        if original_text == updated_text:
            continue
        diff_text = _build_unified_diff(file_path, original_text, updated_text)
        if diff_text:
            diffs.append(diff_text)

    if conflicts:
        return "", tuple(conflicts)

    rendered = "\n".join(diffs).rstrip()
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"{rendered}\n" if rendered else "", encoding="utf-8")
    return rendered, ()


def _collect_repository_summaries(snapshot: RepositorySnapshot) -> tuple[object, ...]:
    summaries: list[object] = []
    for file_path in snapshot.lua_files:
        source = file_path.read_text(encoding="utf-8")
        summaries.extend(summarize_source(file_path, source))
    return tuple(summaries)


def _load_autofix_manifest(manifest_path: str | Path) -> tuple[AutofixPatch, ...]:
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("autofix manifest must be a JSON array")
    return tuple(_deserialize_autofix_patch(item) for item in payload)


def _deserialize_autofix_patch(payload: object) -> AutofixPatch:
    if not isinstance(payload, dict):
        raise ValueError("autofix manifest entries must be JSON objects")

    required_string_keys = ("case_id", "file", "action", "replacement")
    for key in required_string_keys:
        value = payload.get(key)
        if not isinstance(value, str):
            raise ValueError(f"autofix patch field {key} must be a string")

    start_line = payload.get("start_line")
    end_line = payload.get("end_line")
    if not isinstance(start_line, int) or not isinstance(end_line, int):
        raise ValueError("autofix patch start_line and end_line must be integers")

    expected_original = payload.get("expected_original", "")
    if not isinstance(expected_original, str):
        raise ValueError("autofix patch expected_original must be a string")

    return AutofixPatch(
        case_id=payload["case_id"],
        file=payload["file"],
        action=payload["action"],
        start_line=start_line,
        end_line=end_line,
        replacement=payload["replacement"],
        expected_original=expected_original,
    )


def _filter_autofix_patches(
    patches: tuple[AutofixPatch, ...],
    *,
    case_ids: tuple[str, ...] = (),
    file_paths: tuple[str | Path, ...] = (),
) -> tuple[AutofixPatch, ...]:
    case_filter = set(case_ids)
    file_filter = {_normalize_path_key(file_path) for file_path in file_paths}
    filtered: list[AutofixPatch] = []

    for patch in patches:
        if case_filter and patch.case_id not in case_filter:
            continue
        if file_filter and _normalize_path_key(patch.file) not in file_filter:
            continue
        filtered.append(patch)
    return tuple(filtered)


def _apply_autofix_group(
    file_path: Path,
    patches: tuple[AutofixPatch, ...],
    *,
    dry_run: bool = False,
) -> tuple[tuple[AutofixPatch, ...], tuple[str, ...]]:
    original_text, updated_text, applied, conflicts = _simulate_autofix_group(file_path, patches)
    if conflicts:
        return (), conflicts

    if dry_run:
        return applied, ()

    file_path.write_text(updated_text, encoding="utf-8")
    return applied, ()


def _build_summary_text_index(summaries: tuple[object, ...]) -> dict[str, tuple[str, ...]]:
    index: dict[str, list[str]] = {}
    for summary in summaries:
        text = (
            f"{summary.qualified_name} params={summary.params} "
            f"guards={list(summary.guards)} returns={list(summary.returns)}"
        )
        index.setdefault(summary.qualified_name, []).append(text)
    return {key: tuple(value) for key, value in index.items()}


def _build_function_context_index(
    snapshot: RepositorySnapshot,
    summaries: tuple[object, ...],
) -> dict[str, tuple[_FunctionContextBlock, ...]]:
    path_lookup = {str(path): path for path in snapshot.lua_files}
    source_lookup: dict[str, str] = {}
    index: dict[str, list[_FunctionContextBlock]] = {}
    known_function_names = {
        summary.qualified_name
        for summary in summaries
        if isinstance(getattr(summary, "qualified_name", None), str)
    }

    for summary in summaries:
        path_key = str(summary.file)
        file_path = path_lookup.get(path_key, Path(path_key))
        if path_key not in source_lookup:
            try:
                source_lookup[path_key] = file_path.read_text(encoding="utf-8")
            except OSError:
                continue
        snippet, callees = _extract_function_context_snippet(
            source_lookup[path_key],
            summary.line,
            summary.module_name,
            known_function_names,
        )
        if not snippet:
            continue
        rendered = "\n".join(
            [
                f"{summary.qualified_name} @ {summary.file}:{summary.line}",
                snippet,
            ]
        )
        index.setdefault(summary.qualified_name, []).append(
            _FunctionContextBlock(
                qualified_name=summary.qualified_name,
                file=str(summary.file),
                line=summary.line,
                evidence_score=_summary_evidence_score(summary),
                rendered=rendered,
                callees=callees,
            )
        )

    return {key: tuple(value) for key, value in index.items()}


def _extract_function_context_snippet(
    source: str,
    start_line: int,
    module_name: str | None,
    known_function_names: set[str],
) -> tuple[str, tuple[str, ...]]:
    lines = source.splitlines()
    start_index = max(0, start_line - 1)
    if start_index >= len(lines):
        return "", ()

    snippet_lines = [lines[start_index]]
    callee_names: list[str] = []
    depth = 1
    index = start_index + 1

    while index < len(lines):
        line = lines[index]
        snippet_lines.append(line)
        callee_names.extend(
            _call_names_from_line(
                line,
                default_module=module_name,
                known_function_names=known_function_names,
            )
        )
        depth += _opened_block_count(line)
        depth -= _closed_block_count(line)
        if depth <= 0:
            break
        index += 1

    while snippet_lines and not snippet_lines[-1].strip():
        snippet_lines.pop()
    return "\n".join(snippet_lines), tuple(dict.fromkeys(callee_names))


def _summary_evidence_score(summary: object) -> int:
    score = 0
    guards = getattr(summary, "guards", ())
    returns = getattr(summary, "returns", ())
    if isinstance(guards, tuple) and guards:
        score += 2
    if isinstance(returns, tuple) and returns:
        score += 1
    return score


def _build_related_evidence(
    assessment: CandidateAssessment,
    *,
    summary_text_by_name: dict[str, tuple[str, ...]],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    file_module_by_path: dict[str, str | None],
    max_depth: int = 1,
    max_contexts: int = _MAX_RELATED_FUNCTION_CONTEXTS,
    max_context_lines: int = _MAX_RELATED_FUNCTION_CONTEXT_LINES,
    max_summary_items: int = _MAX_RELATED_FUNCTION_SUMMARIES,
) -> _RelatedEvidenceSelection:
    current_file_key = _normalize_path_key(assessment.candidate.file)
    known_function_names = frozenset(
        set(summary_text_by_name) | set(function_context_by_name)
    )
    direct_related_functions = _related_functions_from_assessment(
        assessment,
        current_module=file_module_by_path.get(current_file_key),
        known_function_names=known_function_names,
    )
    ordered_functions, depth_by_function = _expand_related_functions(
        direct_related_functions,
        function_context_by_name,
        max_depth=max_depth,
    )
    selected_contexts = _select_related_function_contexts(
        ordered_functions,
        depth_by_function=depth_by_function,
        function_context_by_name=function_context_by_name,
        current_file=assessment.candidate.file,
        max_contexts=max_contexts,
        max_context_lines=max_context_lines,
    )

    function_names: list[str] = list(direct_related_functions)
    for qualified_name, _ in selected_contexts:
        if qualified_name not in function_names:
            function_names.append(qualified_name)
    for qualified_name in ordered_functions:
        if qualified_name in function_names:
            continue
        if summary_text_by_name.get(qualified_name):
            function_names.append(qualified_name)

    summary_texts = _select_function_summaries(
        tuple(function_names),
        summary_text_by_name=summary_text_by_name,
        max_items=max_summary_items,
    )
    context_texts = tuple(rendered for _, rendered in selected_contexts)

    return _RelatedEvidenceSelection(
        function_names=tuple(function_names),
        summary_texts=summary_texts,
        context_texts=context_texts,
    )


def _knowledge_facts_for_assessment(
    assessment: CandidateAssessment,
    related_functions: tuple[str, ...],
    facts: tuple[object, ...],
    *,
    function_contracts: tuple[object, ...] = (),
    current_module: str | None = None,
) -> tuple[object, ...]:
    applicable_contracts = tuple(
        contract
        for contract in function_contracts
        if contract_applies_in_module(contract, current_module)
        and contract_applies_in_function_scope(
            contract,
            assessment.candidate.function_scope,
        )
        and contract_applies_to_sink(
            contract,
            current_sink_rule_id=assessment.candidate.sink_rule_id,
            current_sink_name=assessment.candidate.sink_name,
        )
    )
    fact_texts = list(
        fact
        for subject in related_functions + (assessment.candidate.function_scope,)
        for fact in facts_for_subject(facts, subject)
    )
    call_contexts_by_function = _contract_calls_from_assessment(
        assessment,
        current_module=current_module,
        known_function_names=frozenset(contract.qualified_name for contract in applicable_contracts),
    )
    scoped_contract_statements = [
        fact.statement
        for fact in derive_facts_from_contracts(
            applicable_contracts,
            current_module=current_module,
            current_function_scope=assessment.candidate.function_scope,
            current_sink_rule_id=assessment.candidate.sink_rule_id,
            current_sink_name=assessment.candidate.sink_name,
        )
        if fact.subject in related_functions
    ]
    for contract in applicable_contracts:
        if not contract.returns_non_nil:
            continue
        if contract.qualified_name not in related_functions:
            continue
        if not (
            contract.applies_to_call_roles
            or contract.applies_to_usage_modes
            or contract.applies_with_arg_count
            or contract.required_literal_args
        ):
            continue
        call_contexts = call_contexts_by_function.get(contract.qualified_name, ())
        if not any(
            contract_applies_to_call(
                contract,
                arg_count=len(args),
                arg_values=args,
                call_role=call_role,
                usage_mode=usage_mode,
            )
            for args, call_role, usage_mode in call_contexts
        ):
            continue
        scoped_contract_statements.append(
            f"{contract.qualified_name} returns non-nil value"
        )
    for fact in scoped_contract_statements:
        fact_texts.append(fact)
    return tuple(dict.fromkeys(fact_texts))


def _should_retry_with_expanded_evidence(
    backend: AdjudicationBackend,
    adjudication: AdjudicationRecord,
    verdict: Verdict,
) -> bool:
    if verdict.status != "uncertain":
        return False
    if not _supports_expanded_evidence_retry(backend):
        return False
    return "expand_context" in {
        adjudication.prosecutor.recommended_next_action,
        adjudication.defender.recommended_next_action,
    }


def _supports_expanded_evidence_retry(backend: AdjudicationBackend) -> bool:
    if isinstance(backend, CliAgentBackend):
        explicit_setting = getattr(backend, "expanded_evidence_retry", None)
        if isinstance(explicit_setting, bool):
            return explicit_setting
        max_attempts = getattr(backend, "max_attempts", 1)
        return isinstance(max_attempts, int) and max_attempts == 1
    return bool(getattr(backend, "supports_expanded_evidence_retry", False))


def _select_function_summaries(
    function_names: tuple[str, ...],
    *,
    summary_text_by_name: dict[str, tuple[str, ...]],
    max_items: int,
) -> tuple[str, ...]:
    selected: list[str] = []
    for function_name in function_names:
        for summary_text in summary_text_by_name.get(function_name, ()):
            if len(selected) >= max_items:
                return tuple(selected)
            selected.append(summary_text)
    return tuple(selected)


def _select_related_function_contexts(
    ordered_functions: tuple[str, ...],
    *,
    depth_by_function: dict[str, int],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    current_file: str,
    max_contexts: int,
    max_context_lines: int,
) -> tuple[tuple[str, str], ...]:
    candidates: list[_FunctionContextBlock] = []
    current_file_key = _normalize_path_key(current_file)
    function_order = {name: index for index, name in enumerate(ordered_functions)}

    for function_name in ordered_functions:
        candidates.extend(function_context_by_name.get(function_name, ()))

    candidates.sort(
        key=lambda block: (
            depth_by_function.get(block.qualified_name, max(function_order.values(), default=0) + 1),
            0 if _normalize_path_key(block.file) == current_file_key else 1,
            -block.evidence_score,
            function_order.get(block.qualified_name, len(function_order)),
            block.line,
            block.file,
        )
    )

    selected: list[tuple[str, str]] = []
    seen_contexts: set[str] = set()
    used_lines = 0

    for block in candidates:
        if len(selected) >= max_contexts:
            break
        if block.rendered in seen_contexts:
            continue

        remaining_lines = max_context_lines - used_lines
        if remaining_lines <= 0:
            break

        rendered = block.rendered
        block_line_count = len(rendered.splitlines())
        if block_line_count > remaining_lines:
            if remaining_lines < 3:
                break
            rendered = _truncate_context_text(rendered, remaining_lines)

        selected.append((block.qualified_name, rendered))
        seen_contexts.add(block.rendered)
        used_lines += len(rendered.splitlines())

    return tuple(selected)


def _truncate_context_text(rendered: str, max_lines: int) -> str:
    lines = rendered.splitlines()
    if len(lines) <= max_lines:
        return rendered
    if max_lines <= 1:
        return lines[0]
    truncated = lines[: max_lines - 1]
    truncated.append(_TRUNCATED_CONTEXT_MARKER)
    return "\n".join(truncated)


def _call_names_from_line(
    line: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, ...]:
    code = _strip_lua_comment(line)
    if not code.strip():
        return ()
    if re.match(r"^\s*(?:local\s+)?function\b", code):
        return ()
    names = []
    for match in _INLINE_CALL_RE.finditer(code):
        raw_name = match.group(1)
        short_name = raw_name.rsplit(".", 1)[-1].rsplit(":", 1)[-1]
        if short_name in _LUA_KEYWORDS:
            continue
        names.append(
            _resolve_related_name(
                raw_name,
                default_module=default_module,
                known_function_names=known_function_names,
            )
        )
    return tuple(dict.fromkeys(names))


def _opened_block_count(line: str) -> int:
    code = _strip_lua_comment(line).strip()
    if not code:
        return 0

    count = 0
    if _FUNCTION_BLOCK_RE.search(code):
        count += len(_FUNCTION_BLOCK_RE.findall(code))

    control_match = _CONTROL_FLOW_START_RE.match(code)
    if control_match is not None:
        keyword = control_match.group(1)
        if keyword == "if" and re.search(r"\bthen\b", code):
            count += 1
        elif keyword in {"for", "while"} and re.search(r"\bdo\b", code):
            count += 1
    elif code == "do":
        count += 1

    if re.match(r"^\s*repeat\b", code):
        count += 1

    return count


def _closed_block_count(line: str) -> int:
    code = _strip_lua_comment(line)
    if not code.strip():
        return 0
    return len(re.findall(r"\bend\b", code)) + len(re.findall(r"\buntil\b", code))


def _strip_lua_comment(line: str) -> str:
    return line.partition("--")[0]


def _load_knowledge_facts(
    snapshot: RepositorySnapshot,
    knowledge_path: str | Path | None,
) -> tuple[object, ...]:
    path = Path(knowledge_path) if knowledge_path is not None else snapshot.root / "data" / "knowledge.json"
    return KnowledgeBase(path).load()


def _merge_knowledge_facts(*fact_groups: tuple[object, ...]) -> tuple[object, ...]:
    merged: list[object] = []
    seen: set[tuple[object, object, object]] = set()

    for group in fact_groups:
        for fact in group:
            key = (
                getattr(fact, "key", None),
                getattr(fact, "subject", None),
                getattr(fact, "statement", None),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(fact)
    return tuple(merged)


def _expected_benchmark_label(file_path: str) -> str | None:
    name = Path(file_path).name
    if name.startswith("provable_risky_"):
        return "risky"
    if name.startswith("provable_safe_"):
        return "safe"
    if name.startswith("provable_uncertain_"):
        return "uncertain"
    return None


def _normalize_benchmark_status(status: str) -> str:
    if status in {"risky", "risky_verified"}:
        return "risky"
    if status in {"safe", "safe_verified"}:
        return "safe"
    return "uncertain"


def _extract_backend_failure_reason(verdict: Verdict) -> str | None:
    if verdict.status != "uncertain":
        return None
    for item in verdict.counterarguments_considered:
        if item.startswith("CLI backend command"):
            return item
    return None


def _backend_metric(backend: object, name: str) -> int:
    value = getattr(backend, name, 0)
    if isinstance(value, int) and value >= 0:
        return value
    return 0


def _backend_float_metric(backend: object, name: str) -> float:
    value = getattr(backend, name, 0.0)
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return 0.0


def _backend_name(backend: object) -> str:
    provider_spec = getattr(backend, "provider_spec", None)
    if isinstance(provider_spec, AgentProviderSpec):
        return provider_spec.name
    name = backend.__class__.__name__
    if name == "HeuristicAdjudicationBackend":
        return "heuristic"
    if name == "CodexCliBackend":
        return "codex"
    if name == "CodeAgentCliBackend":
        return "codeagent"
    return name


def _backend_optional_string(backend: object, name: str) -> str | None:
    value = getattr(backend, name, None)
    if isinstance(value, str):
        return value
    return None


def _serialize_autofix_patch(patch: AutofixPatch) -> dict[str, object]:
    return {
        "case_id": patch.case_id,
        "file": patch.file,
        "action": patch.action,
        "start_line": patch.start_line,
        "end_line": patch.end_line,
        "replacement": patch.replacement,
        "expected_original": patch.expected_original,
    }


def _simulate_autofix_group(
    file_path: Path,
    patches: tuple[AutofixPatch, ...],
) -> tuple[str, str, tuple[AutofixPatch, ...], tuple[str, ...]]:
    if not file_path.exists():
        conflicts = tuple(f"{patch.case_id}: target file not found: {file_path}" for patch in patches)
        return "", "", (), conflicts

    original_text = file_path.read_text(encoding="utf-8")
    trailing_newline = original_text.endswith("\n")
    trial_lines = original_text.splitlines()
    applied: list[AutofixPatch] = []
    conflicts: list[str] = []

    ordered = sorted(patches, key=lambda patch: (patch.start_line, patch.end_line), reverse=True)
    for patch in ordered:
        conflict = _validate_autofix_patch(trial_lines, patch)
        if conflict is not None:
            conflicts.append(f"{patch.case_id}: {conflict}")
            continue
        _apply_autofix_patch_to_lines(trial_lines, patch)
        applied.append(patch)

    if conflicts:
        return original_text, original_text, (), tuple(conflicts)

    updated_text = _render_text_from_lines(trial_lines, trailing_newline=trailing_newline)
    return original_text, updated_text, tuple(applied), ()


def _build_unified_diff(file_path: Path, original_text: str, updated_text: str) -> str:
    original_lines = original_text.splitlines()
    updated_lines = updated_text.splitlines()
    diff_lines = list(
        difflib.unified_diff(
            original_lines,
            updated_lines,
            fromfile=str(file_path),
            tofile=str(file_path),
            lineterm="",
        )
    )
    return "\n".join(diff_lines)


def _normalize_path_key(path: str | Path) -> str:
    return str(Path(path).resolve(strict=False))


def _resolve_snapshot_lua_file(snapshot: RepositorySnapshot, file_path: str | Path) -> Path:
    target_key = _normalize_path_key(file_path)
    for candidate in snapshot.lua_files:
        if _normalize_path_key(candidate) == target_key:
            return candidate
    raise ValueError(f"File is not a discovered Lua source in repository: {file_path}")


def _render_text_from_lines(lines: list[str], *, trailing_newline: bool) -> str:
    rendered = "\n".join(lines)
    if trailing_newline:
        return f"{rendered}\n"
    return rendered


def _validate_autofix_patch(lines: list[str], patch: AutofixPatch) -> str | None:
    if patch.start_line < 1 or patch.end_line < patch.start_line:
        return "invalid patch line range"
    if patch.action not in {"insert_before", "replace_range"}:
        return f"unsupported patch action: {patch.action}"
    if not patch.expected_original:
        return "patch is missing expected_original"

    start_index = patch.start_line - 1
    end_index = patch.end_line

    if patch.action == "insert_before":
        if start_index >= len(lines):
            return "anchor line is out of range"
        current = lines[start_index]
        if current != patch.expected_original:
            return "anchor line no longer matches expected_original"
        return None

    if end_index > len(lines):
        return "replace range is out of range"
    current = "\n".join(lines[start_index:end_index])
    if current != patch.expected_original:
        return "replace range no longer matches expected_original"
    return None


def _apply_autofix_patch_to_lines(lines: list[str], patch: AutofixPatch) -> None:
    start_index = patch.start_line - 1
    replacement_lines = patch.replacement.splitlines()

    if patch.action == "insert_before":
        lines[start_index:start_index] = replacement_lines
        return

    end_index = patch.end_line
    lines[start_index:end_index] = replacement_lines


def _expand_related_functions(
    related_functions: tuple[str, ...],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    *,
    max_depth: int,
) -> tuple[tuple[str, ...], dict[str, int]]:
    ordered: list[str] = []
    depth_by_function: dict[str, int] = {}
    queue = [(function_name, 0) for function_name in tuple(dict.fromkeys(related_functions))]

    while queue:
        function_name, depth = queue.pop(0)
        if function_name in depth_by_function:
            continue
        depth_by_function[function_name] = depth
        ordered.append(function_name)
        if depth >= max_depth:
            continue
        for context in function_context_by_name.get(function_name, ()):
            for callee in context.callees:
                if callee in depth_by_function or callee not in function_context_by_name:
                    continue
                queue.append((callee, depth + 1))

    return tuple(ordered), depth_by_function


def _related_functions_from_assessment(
    assessment: CandidateAssessment,
    *,
    current_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, ...]:
    related: list[str] = []
    for origin in assessment.static_analysis.origin_candidates:
        resolved = _call_name_from_expression(
            origin,
            default_module=current_module,
            known_function_names=known_function_names,
        )
        if resolved is not None:
            related.append(resolved)
    return tuple(dict.fromkeys(related))


def _call_name_from_expression(
    expression: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> str | None:
    match = _CALL_RE.match(expression)
    if match is None:
        return None
    return _resolve_related_name(
        match.group(1),
        default_module=default_module,
        known_function_names=known_function_names,
    )


def _contract_calls_from_assessment(
    assessment: CandidateAssessment,
    *,
    current_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> dict[str, tuple[tuple[tuple[str, ...], str, str | None], ...]]:
    call_args: dict[str, list[tuple[tuple[str, ...], str, str | None]]] = {}
    usage_modes = assessment.static_analysis.origin_usage_modes
    for index, origin in enumerate(assessment.static_analysis.origin_candidates):
        parsed = _parse_call_expression(
            origin,
            default_module=current_module,
            known_function_names=known_function_names,
        )
        if parsed is None:
            continue
        function_name, args = parsed
        usage_mode = usage_modes[index] if index < len(usage_modes) else _usage_mode_for_origin(
            assessment,
            origin,
        )
        call_args.setdefault(function_name, []).append(
            (args, _call_role_for_origin(assessment, origin), usage_mode)
        )
    return {key: tuple(value) for key, value in call_args.items()}


def _parse_call_expression(
    expression: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, tuple[str, ...]] | None:
    match = _CALL_EXPRESSION_RE.match(_strip_lua_comment(expression).strip())
    if match is None:
        return None
    return (
        _resolve_related_name(
            match.group(1),
            default_module=default_module,
            known_function_names=known_function_names,
        ),
        tuple(_split_top_level_values(match.group(2))),
    )


def _resolve_related_name(
    raw_name: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> str:
    normalized = raw_name.strip().replace(":", ".")
    if "." in normalized:
        return normalized
    if default_module:
        module_qualified = f"{default_module}.{normalized}"
        if module_qualified in known_function_names:
            return module_qualified
    if normalized in known_function_names:
        return normalized
    return normalized


def _split_top_level_values(values_text: str) -> list[str]:
    values: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(values_text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            values.append(values_text[start:index].strip())
            start = index + 1

    tail = values_text[start:].strip()
    if tail:
        values.append(tail)
    return values


def _strip_lua_comment(line: str) -> str:
    return line.partition("--")[0]


def _call_role_for_origin(assessment: CandidateAssessment, origin: str) -> str:
    if origin == assessment.candidate.expression:
        return "sink_expression"
    return "assignment_origin"


def _usage_mode_for_origin(assessment: CandidateAssessment, origin: str) -> str:
    if origin == assessment.candidate.expression:
        return "direct_sink"
    return "single_assignment"


def _build_file_module_index(snapshot: RepositorySnapshot) -> dict[str, str | None]:
    index: dict[str, str | None] = {}
    for file_path in snapshot.lua_files:
        try:
            source = file_path.read_text(encoding="utf-8")
        except OSError:
            continue
        index[_normalize_path_key(file_path)] = detect_module_name(source)
    return index
