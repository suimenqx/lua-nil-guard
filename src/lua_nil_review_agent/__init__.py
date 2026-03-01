"""Foundational package for the Lua nil risk review agent."""

from .adjudication import adjudicate_packet
from .baseline import BaselineStore, build_baseline, filter_new_findings
from .cli import main, run
from .collector import collect_candidates
from .config_loader import ConfigError, load_confidence_policy, load_sink_rules
from .knowledge import KnowledgeBase, facts_for_subject
from .models import (
    AdjudicationRecord,
    CandidateAssessment,
    CandidateCase,
    ConfidencePolicy,
    EvidencePacket,
    EvidenceTarget,
    RepositorySnapshot,
    FunctionSummary,
    KnowledgeFact,
    RoleOpinion,
    SinkRule,
    StaticAnalysisResult,
    Verdict,
    with_candidate_state,
)
from .pipeline import build_evidence_packet, should_report
from .prompting import build_adjudication_prompt
from .reporting import render_markdown_report
from .repository import discover_lua_files
from .service import (
    bootstrap_repository,
    prepare_evidence_packet,
    refresh_summary_cache,
    review_repository,
    run_repository_review,
    review_source,
)
from .summaries import SummaryStore, summarize_source
from .static_analysis import analyze_candidate
from .verification import verify_verdict

__all__ = [
    "AdjudicationRecord",
    "BaselineStore",
    "CandidateAssessment",
    "CandidateCase",
    "ConfidencePolicy",
    "ConfigError",
    "EvidencePacket",
    "EvidenceTarget",
    "FunctionSummary",
    "KnowledgeBase",
    "KnowledgeFact",
    "RoleOpinion",
    "RepositorySnapshot",
    "SinkRule",
    "SummaryStore",
    "StaticAnalysisResult",
    "Verdict",
    "with_candidate_state",
    "adjudicate_packet",
    "bootstrap_repository",
    "build_baseline",
    "build_adjudication_prompt",
    "build_evidence_packet",
    "collect_candidates",
    "discover_lua_files",
    "facts_for_subject",
    "filter_new_findings",
    "load_confidence_policy",
    "load_sink_rules",
    "main",
    "analyze_candidate",
    "summarize_source",
    "prepare_evidence_packet",
    "refresh_summary_cache",
    "review_repository",
    "render_markdown_report",
    "run",
    "run_repository_review",
    "review_source",
    "should_report",
    "verify_verdict",
]
