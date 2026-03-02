"""Foundational package for the Lua nil risk review agent."""

from .agent_backend import (
    AdjudicationBackend,
    BackendError,
    CliAgentBackend,
    CodeAgentCliBackend,
    CodexCliBackend,
    HeuristicAdjudicationBackend,
    create_adjudication_backend,
)
from .adjudication import adjudicate_packet
from .baseline import BaselineStore, build_baseline, filter_new_findings
from .cli import main, run
from .collector import collect_candidates
from .config_loader import ConfigError, load_confidence_policy, load_sink_rules
from .knowledge import KnowledgeBase, derive_facts_from_summaries, facts_for_subject
from .models import (
    AdjudicationRecord,
    AutofixPatch,
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
from .parser_backend import collect_call_sites, get_parser_backend_info
from .prompting import build_adjudication_prompt
from .reporting import render_json_report, render_markdown_report
from .repository import discover_lua_files
from .skill_runtime import (
    ADJUDICATOR_SKILL_CONTRACT,
    SkillDefinition,
    SkillRuntimeError,
    compile_adjudicator_skill_header,
    default_adjudicator_skill_path,
    fallback_adjudicator_skill_header,
    load_adjudicator_skill,
    load_skill_definition,
)
from .service import (
    apply_autofix_manifest,
    bootstrap_repository,
    export_adjudication_tasks,
    export_autofix_patches,
    export_autofix_unified_diff,
    refresh_knowledge_base,
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
    "AdjudicationBackend",
    "ADJUDICATOR_SKILL_CONTRACT",
    "AutofixPatch",
    "BackendError",
    "BaselineStore",
    "CliAgentBackend",
    "CandidateAssessment",
    "CandidateCase",
    "ConfidencePolicy",
    "ConfigError",
    "CodeAgentCliBackend",
    "EvidencePacket",
    "EvidenceTarget",
    "FunctionSummary",
    "KnowledgeBase",
    "KnowledgeFact",
    "CodexCliBackend",
    "HeuristicAdjudicationBackend",
    "RoleOpinion",
    "RepositorySnapshot",
    "SinkRule",
    "SkillDefinition",
    "SkillRuntimeError",
    "SummaryStore",
    "StaticAnalysisResult",
    "Verdict",
    "with_candidate_state",
    "adjudicate_packet",
    "apply_autofix_manifest",
    "bootstrap_repository",
    "build_baseline",
    "build_adjudication_prompt",
    "build_evidence_packet",
    "collect_candidates",
    "collect_call_sites",
    "create_adjudication_backend",
    "discover_lua_files",
    "compile_adjudicator_skill_header",
    "default_adjudicator_skill_path",
    "derive_facts_from_summaries",
    "export_adjudication_tasks",
    "export_autofix_patches",
    "export_autofix_unified_diff",
    "fallback_adjudicator_skill_header",
    "facts_for_subject",
    "filter_new_findings",
    "load_confidence_policy",
    "load_adjudicator_skill",
    "load_sink_rules",
    "load_skill_definition",
    "main",
    "analyze_candidate",
    "get_parser_backend_info",
    "summarize_source",
    "prepare_evidence_packet",
    "refresh_knowledge_base",
    "refresh_summary_cache",
    "review_repository",
    "render_json_report",
    "render_markdown_report",
    "run",
    "run_repository_review",
    "review_source",
    "should_report",
    "verify_verdict",
]
