"""Foundational package for the Lua nil risk review agent."""

from .config_loader import ConfigError, load_confidence_policy, load_sink_rules
from .models import (
    CandidateCase,
    ConfidencePolicy,
    EvidencePacket,
    EvidenceTarget,
    RepositorySnapshot,
    SinkRule,
    Verdict,
)
from .pipeline import build_evidence_packet, should_report
from .prompting import build_adjudication_prompt
from .reporting import render_markdown_report
from .repository import discover_lua_files
from .service import bootstrap_repository

__all__ = [
    "CandidateCase",
    "ConfidencePolicy",
    "ConfigError",
    "EvidencePacket",
    "EvidenceTarget",
    "RepositorySnapshot",
    "SinkRule",
    "Verdict",
    "bootstrap_repository",
    "build_adjudication_prompt",
    "build_evidence_packet",
    "discover_lua_files",
    "load_confidence_policy",
    "load_sink_rules",
    "render_markdown_report",
    "should_report",
]
