from __future__ import annotations

from pathlib import Path

from .collector import collect_candidates
from .config_loader import load_confidence_policy, load_sink_rules
from .models import CandidateAssessment, RepositorySnapshot, SinkRule, with_candidate_state
from .repository import discover_lua_files
from .static_analysis import analyze_candidate


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
