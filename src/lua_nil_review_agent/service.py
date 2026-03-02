from __future__ import annotations

import json
import re
from pathlib import Path

from .adjudication import attach_autofix_patch
from .agent_backend import AdjudicationBackend, HeuristicAdjudicationBackend
from .collector import collect_candidates
from .config_loader import load_confidence_policy, load_sink_rules
from .knowledge import KnowledgeBase, derive_facts_from_summaries, facts_for_subject
from .models import AutofixPatch, CandidateAssessment, EvidencePacket, RepositorySnapshot, SinkRule, Verdict, with_candidate_state
from .pipeline import build_evidence_packet, should_report
from .prompting import build_adjudication_prompt
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
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> tuple[Verdict, ...]:
    """Run the current end-to-end local review pipeline across a repository."""

    sink_rule_by_id = {rule.id: rule for rule in snapshot.sink_rules}
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    adjudication_backend = backend or HeuristicAdjudicationBackend()

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
            adjudication = adjudication_backend.adjudicate(
                packet,
                sink_rule_by_id[assessment.candidate.sink_rule_id],
            )
            verdict = attach_autofix_patch(
                adjudication.judge,
                packet,
                sink_rule_by_id[assessment.candidate.sink_rule_id],
            )
            verdicts.append(verify_verdict(verdict, packet))
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
    facts = derive_facts_from_summaries(summaries)
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
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    tasks: list[dict[str, object]] = []

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


def apply_autofix_manifest(
    manifest_path: str | Path,
) -> tuple[tuple[AutofixPatch, ...], tuple[str, ...]]:
    """Apply an exported autofix manifest with per-file conflict checks."""

    patches = _load_autofix_manifest(manifest_path)
    grouped: dict[Path, list[AutofixPatch]] = {}
    for patch in patches:
        grouped.setdefault(Path(patch.file), []).append(patch)

    applied: list[AutofixPatch] = []
    conflicts: list[str] = []

    for file_path, file_patches in grouped.items():
        file_applied, file_conflicts = _apply_autofix_group(file_path, tuple(file_patches))
        applied.extend(file_applied)
        conflicts.extend(file_conflicts)

    return tuple(applied), tuple(conflicts)


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


def _apply_autofix_group(
    file_path: Path,
    patches: tuple[AutofixPatch, ...],
) -> tuple[tuple[AutofixPatch, ...], tuple[str, ...]]:
    if not file_path.exists():
        return (), tuple(f"{patch.case_id}: target file not found: {file_path}" for patch in patches)

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
        return (), tuple(conflicts)

    updated_text = "\n".join(trial_lines)
    if trailing_newline:
        updated_text = f"{updated_text}\n"
    file_path.write_text(updated_text, encoding="utf-8")
    return tuple(applied), ()


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


def _related_functions_from_assessment(assessment: CandidateAssessment) -> tuple[str, ...]:
    related: list[str] = []
    for origin in assessment.static_analysis.origin_candidates:
        match = _CALL_RE.match(origin)
        if match is not None:
            related.append(match.group(1))
    return tuple(dict.fromkeys(related))
