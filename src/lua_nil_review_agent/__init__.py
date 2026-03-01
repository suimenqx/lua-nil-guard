"""Foundational package for the Lua nil risk review agent."""

from .cli import main, run
from .collector import collect_candidates
from .config_loader import ConfigError, load_confidence_policy, load_sink_rules
from .models import (
    CandidateAssessment,
    CandidateCase,
    ConfidencePolicy,
    EvidencePacket,
    EvidenceTarget,
    RepositorySnapshot,
    SinkRule,
    StaticAnalysisResult,
    Verdict,
    with_candidate_state,
)
from .pipeline import build_evidence_packet, should_report
from .prompting import build_adjudication_prompt
from .reporting import render_markdown_report
from .repository import discover_lua_files
from .service import bootstrap_repository, review_repository, review_source
from .static_analysis import analyze_candidate

__all__ = [
    "CandidateAssessment",
    "CandidateCase",
    "ConfidencePolicy",
    "ConfigError",
    "EvidencePacket",
    "EvidenceTarget",
    "RepositorySnapshot",
    "SinkRule",
    "StaticAnalysisResult",
    "Verdict",
    "with_candidate_state",
    "bootstrap_repository",
    "build_adjudication_prompt",
    "build_evidence_packet",
    "collect_candidates",
    "discover_lua_files",
    "load_confidence_policy",
    "load_sink_rules",
    "main",
    "analyze_candidate",
    "review_repository",
    "render_markdown_report",
    "run",
    "review_source",
    "should_report",
]
