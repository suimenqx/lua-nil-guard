from __future__ import annotations

import re
from pathlib import Path

from .adjudication import adjudicate_packet
from .collector import collect_candidates
from .config_loader import load_confidence_policy, load_sink_rules
from .knowledge import KnowledgeBase, facts_for_subject
from .models import CandidateAssessment, EvidencePacket, RepositorySnapshot, SinkRule, Verdict, with_candidate_state
from .pipeline import build_evidence_packet
from .repository import discover_lua_files
from .summaries import SummaryStore, summarize_source
from .static_analysis import analyze_candidate
from .verification import verify_verdict


_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def bootstrap_repository(root: str | Path) -> RepositorySnapshot:
    """Load the current repository's core review inputs."""

    root_path = Path(root)
    sink_rules = tuple(load_sink_rules(root_path / "config" / "sink_rules.json"))
    confidence_policy = load_confidence_policy(root_path / "config" / "confidence_policy.json")
    lua_files = tuple(discover_lua_files(root_path))

    return RepositorySnapshot(
        root=root_path,
        sink_rules=sink_rules,
        confidence_policy=confidence_policy,
        lua_files=lua_files,
    )


def review_source(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
) -> tuple[CandidateAssessment, ...]:
    """Collect candidates from one source file and attach local static analysis."""

    assessments: list[CandidateAssessment] = []
    for candidate in collect_candidates(file_path, source, sink_rules):
        static_analysis = analyze_candidate(source, candidate)
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
        assessments.extend(review_source(file_path, source, snapshot.sink_rules))
    return tuple(assessments)


def prepare_evidence_packet(
    assessment: CandidateAssessment,
    source: str,
    *,
    related_functions: tuple[str, ...] = (),
    function_summaries: tuple[str, ...] = (),
    knowledge_facts: tuple[str, ...] = (),
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
        observed_guards=assessment.static_analysis.observed_guards,
    )


def run_repository_review(
    snapshot: RepositorySnapshot,
    *,
    knowledge_path: str | Path | None = None,
) -> tuple[Verdict, ...]:
    """Run the current end-to-end local review pipeline across a repository."""

    sink_rule_by_id = {rule.id: rule for rule in snapshot.sink_rules}
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    facts = _load_knowledge_facts(snapshot, knowledge_path)

    verdicts: list[Verdict] = []
    for file_path in snapshot.lua_files:
        source = file_path.read_text(encoding="utf-8")
        for assessment in review_source(file_path, source, snapshot.sink_rules):
            related_functions = _related_functions_from_assessment(assessment)
            function_summaries = tuple(
                summary
                for function_name in related_functions
                for summary in summary_text_by_name.get(function_name, ())
            )
            knowledge_facts = tuple(
                fact
                for subject in related_functions + (assessment.candidate.function_scope,)
                for fact in facts_for_subject(facts, subject)
            )
            packet = prepare_evidence_packet(
                assessment,
                source,
                related_functions=related_functions,
                function_summaries=function_summaries,
                knowledge_facts=knowledge_facts,
            )
            adjudication = adjudicate_packet(packet, sink_rule_by_id[assessment.candidate.sink_rule_id])
            verdicts.append(verify_verdict(adjudication.judge, packet))
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


def _collect_repository_summaries(snapshot: RepositorySnapshot) -> tuple[object, ...]:
    summaries: list[object] = []
    for file_path in snapshot.lua_files:
        source = file_path.read_text(encoding="utf-8")
        summaries.extend(summarize_source(file_path, source))
    return tuple(summaries)


def _build_summary_text_index(summaries: tuple[object, ...]) -> dict[str, tuple[str, ...]]:
    index: dict[str, list[str]] = {}
    for summary in summaries:
        text = (
            f"{summary.function_name} params={summary.params} "
            f"guards={list(summary.guards)} returns={list(summary.returns)}"
        )
        index.setdefault(summary.function_name, []).append(text)
    return {key: tuple(value) for key, value in index.items()}


def _load_knowledge_facts(
    snapshot: RepositorySnapshot,
    knowledge_path: str | Path | None,
) -> tuple[object, ...]:
    path = Path(knowledge_path) if knowledge_path is not None else snapshot.root / "data" / "knowledge.json"
    return KnowledgeBase(path).load()


def _related_functions_from_assessment(assessment: CandidateAssessment) -> tuple[str, ...]:
    related: list[str] = []
    for origin in assessment.static_analysis.origin_candidates:
        match = _CALL_RE.match(origin)
        if match is not None:
            related.append(match.group(1))
    return tuple(dict.fromkeys(related))
