from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Sequence

from .agent_backend import BackendError, create_adjudication_backend
from .baseline import BaselineStore, build_baseline, filter_new_findings
from .parser_backend import get_parser_backend_info
from .reporting import render_json_report, render_markdown_report
from .skill_runtime import SkillRuntimeError
from .service import (
    apply_autofix_manifest,
    bootstrap_repository,
    export_adjudication_tasks,
    export_autofix_patches,
    export_autofix_unified_diff,
    refresh_knowledge_base,
    refresh_summary_cache,
    review_repository,
    run_repository_review,
)


def run(argv: Sequence[str]) -> tuple[int, str]:
    """Execute the minimal CLI and return an exit code with rendered output."""

    args = list(argv)
    if not args or args[0] in {"-h", "--help"}:
        return 0, _usage()

    command = args[0]
    if command == "scan":
        if len(args) != 2:
            return 2, "scan requires exactly one repository path"
        root = Path(args[1])
        snapshot = bootstrap_repository(root)
        assessments = review_repository(snapshot)
        return 0, _render_scan_summary(snapshot.root, assessments)

    if command == "report":
        try:
            backend_name, model, skill_path, strict_skill, executable, positional = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "report requires exactly one repository path"
        root = Path(positional[0])
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=create_adjudication_backend(
                    backend_name,
                    workdir=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                ),
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        return 0, render_markdown_report(verdicts, snapshot.confidence_policy)

    if command == "report-json":
        try:
            backend_name, model, skill_path, strict_skill, executable, positional = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "report-json requires exactly one repository path"
        root = Path(positional[0])
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=create_adjudication_backend(
                    backend_name,
                    workdir=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                ),
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        return 0, render_json_report(verdicts, snapshot.confidence_policy)

    if command == "baseline-create":
        try:
            backend_name, model, skill_path, strict_skill, executable, positional = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 2:
            return 2, "baseline-create requires a repository path and output path"
        root = Path(positional[0])
        baseline_path = Path(positional[1])
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=create_adjudication_backend(
                    backend_name,
                    workdir=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                ),
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        baseline = build_baseline(verdicts, snapshot.confidence_policy)
        BaselineStore(baseline_path).save(baseline)
        return 0, "\n".join(
            [
                "Baseline created.",
                f"Baseline entries: {len(baseline)}",
                f"Output: {baseline_path}",
            ]
        )

    if command == "report-new":
        try:
            backend_name, model, skill_path, strict_skill, executable, positional = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 2:
            return 2, "report-new requires a repository path and baseline path"
        root = Path(positional[0])
        baseline_path = Path(positional[1])
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=create_adjudication_backend(
                    backend_name,
                    workdir=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                ),
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        filtered = filter_new_findings(
            verdicts,
            BaselineStore(baseline_path).load(),
            snapshot.confidence_policy,
        )
        return 0, render_markdown_report(filtered, snapshot.confidence_policy)

    if command == "refresh-summaries":
        if len(args) not in {2, 3}:
            return 2, "refresh-summaries requires a repository path and optional output path"
        root = Path(args[1])
        summary_path = Path(args[2]) if len(args) == 3 else None
        snapshot = bootstrap_repository(root)
        summaries = refresh_summary_cache(snapshot, summary_path=summary_path)
        target = summary_path or (snapshot.root / "data" / "function_summaries.json")
        return 0, "\n".join(
            [
                "Summary cache refreshed.",
                f"Summary entries: {len(summaries)}",
                f"Output: {target}",
            ]
        )

    if command == "refresh-knowledge":
        if len(args) not in {2, 3}:
            return 2, "refresh-knowledge requires a repository path and optional output path"
        root = Path(args[1])
        knowledge_path = Path(args[2]) if len(args) == 3 else None
        snapshot = bootstrap_repository(root)
        facts = refresh_knowledge_base(snapshot, knowledge_path=knowledge_path)
        target = knowledge_path or (snapshot.root / "data" / "knowledge.json")
        return 0, "\n".join(
            [
                "Knowledge cache refreshed.",
                f"Knowledge entries: {len(facts)}",
                f"Output: {target}",
            ]
        )

    if command == "ci-check":
        try:
            backend_name, model, skill_path, strict_skill, executable, positional = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 2:
            return 2, "ci-check requires a repository path and baseline path"
        root = Path(positional[0])
        baseline_path = Path(positional[1])
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=create_adjudication_backend(
                    backend_name,
                    workdir=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                ),
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        filtered = filter_new_findings(
            verdicts,
            BaselineStore(baseline_path).load(),
            snapshot.confidence_policy,
        )
        exit_code = 1 if filtered else 0
        return exit_code, "\n".join(
            [
                "CI check complete.",
                f"New findings: {len(filtered)}",
            ]
        )

    if command == "export-prompts":
        try:
            skill_path, strict_skill, positional = _parse_export_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "export-prompts requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        snapshot = bootstrap_repository(root)
        try:
            tasks = export_adjudication_tasks(
                snapshot,
                output_path=output_path,
                skill_path=skill_path,
                strict_skill=strict_skill,
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        if output_path is None:
            return 0, json.dumps(tasks, indent=2, sort_keys=True)
        return 0, "\n".join(
            [
                "Prompt export complete.",
                f"Prompt tasks: {len(tasks)}",
                f"Output: {output_path}",
            ]
        )

    if command == "export-autofix":
        try:
            backend_name, model, skill_path, strict_skill, executable, positional = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "export-autofix requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        snapshot = bootstrap_repository(root)
        try:
            patches = export_autofix_patches(
                snapshot,
                backend=create_adjudication_backend(
                    backend_name,
                    workdir=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                ),
                output_path=output_path,
            )
        except (SkillRuntimeError, BackendError) as exc:
            return 2, str(exc)
        if output_path is None:
            payload = [
                {
                    "case_id": patch.case_id,
                    "file": patch.file,
                    "action": patch.action,
                    "start_line": patch.start_line,
                    "end_line": patch.end_line,
                    "replacement": patch.replacement,
                    "expected_original": patch.expected_original,
                }
                for patch in patches
            ]
            return 0, json.dumps(payload, indent=2, sort_keys=True)
        return 0, "\n".join(
            [
                "Autofix export complete.",
                f"Autofix patches: {len(patches)}",
                f"Output: {output_path}",
            ]
        )

    if command == "apply-autofix":
        dry_run = False
        positional: list[str] = []
        for token in args[1:]:
            if token == "--dry-run":
                dry_run = True
                continue
            positional.append(token)
        if len(positional) != 1:
            return 2, "apply-autofix requires exactly one autofix manifest path"
        try:
            applied, conflicts = apply_autofix_manifest(
                Path(positional[0]),
                dry_run=dry_run,
            )
        except (ValueError, OSError) as exc:
            return 2, str(exc)
        lines = [
            "Autofix apply complete.",
            f"Dry run: {'yes' if dry_run else 'no'}",
            f"Applied patches: {len(applied)}",
            f"Conflicts: {len(conflicts)}",
        ]
        if conflicts:
            lines.extend(conflicts)
            return 1, "\n".join(lines)
        return 0, "\n".join(lines)

    if command == "export-unified-diff":
        if len(args) not in {2, 3}:
            return 2, "export-unified-diff requires an autofix manifest path and optional output path"
        manifest_path = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            diff_text, conflicts = export_autofix_unified_diff(
                manifest_path,
                output_path=output_path,
            )
        except (ValueError, OSError) as exc:
            return 2, str(exc)
        if conflicts:
            lines = [
                "Unified diff export blocked.",
                f"Conflicts: {len(conflicts)}",
            ]
            lines.extend(conflicts)
            return 1, "\n".join(lines)
        if output_path is None:
            return 0, diff_text or "No unified diff output."
        return 0, "\n".join(
            [
                "Unified diff export complete.",
                f"Output: {output_path}",
            ]
        )

    return 2, _usage()


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point."""

    import sys

    exit_code, output = run(sys.argv[1:] if argv is None else argv)
    print(output)
    return exit_code


def _render_scan_summary(root: Path, assessments: tuple[object, ...]) -> str:
    backend_info = get_parser_backend_info()
    counts = Counter(
        assessment.candidate.static_state
        for assessment in assessments
    )

    lines = [
        "# Lua Nil Review Static Summary",
        "",
        f"Repository: {root}",
        f"Parser backend: {backend_info.name}",
        f"Total candidates: {len(assessments)}",
    ]

    for state in ("safe_static", "unknown_static", "risky_static"):
        lines.append(f"{state}: {counts.get(state, 0)}")

    return "\n".join(lines)


def _usage() -> str:
    return "\n".join(
        [
            "Usage:",
            "  lua-nil-review-agent scan <repository>",
            "  lua-nil-review-agent report [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] <repository>",
            "  lua-nil-review-agent report-json [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] <repository>",
            "  lua-nil-review-agent baseline-create [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] <repository> <output>",
            "  lua-nil-review-agent report-new [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] <repository> <baseline>",
            "  lua-nil-review-agent refresh-summaries <repository> [output]",
            "  lua-nil-review-agent refresh-knowledge <repository> [output]",
            "  lua-nil-review-agent ci-check [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] <repository> <baseline>",
            "  lua-nil-review-agent export-prompts [--skill SKILL] [--allow-skill-fallback] <repository> [output]",
            "  lua-nil-review-agent export-autofix [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] <repository> [output]",
            "  lua-nil-review-agent apply-autofix [--dry-run] <autofix-manifest>",
            "  lua-nil-review-agent export-unified-diff <autofix-manifest> [output]",
            "",
            "Backend values: heuristic | codex | codeagent",
        ]
    )


def _parse_review_options(
    args: list[str],
) -> tuple[str, str | None, Path | None, bool, str | None, list[str]]:
    backend_name = "heuristic"
    model: str | None = None
    skill_path: Path | None = None
    strict_skill = True
    executable: str | None = None
    positional: list[str] = []
    index = 0

    while index < len(args):
        token = args[index]
        if token == "--backend":
            if index + 1 >= len(args):
                raise ValueError("--backend requires a value")
            backend_name = args[index + 1]
            index += 2
            continue
        if token == "--model":
            if index + 1 >= len(args):
                raise ValueError("--model requires a value")
            model = args[index + 1]
            index += 2
            continue
        if token == "--skill":
            if index + 1 >= len(args):
                raise ValueError("--skill requires a value")
            skill_path = Path(args[index + 1])
            index += 2
            continue
        if token == "--allow-skill-fallback":
            strict_skill = False
            index += 1
            continue
        if token == "--backend-executable":
            if index + 1 >= len(args):
                raise ValueError("--backend-executable requires a value")
            executable = args[index + 1]
            index += 2
            continue
        positional.append(token)
        index += 1

    return backend_name, model, skill_path, strict_skill, executable, positional


def _parse_export_options(args: list[str]) -> tuple[Path | None, bool, list[str]]:
    skill_path: Path | None = None
    strict_skill = True
    positional: list[str] = []
    index = 0

    while index < len(args):
        token = args[index]
        if token == "--skill":
            if index + 1 >= len(args):
                raise ValueError("--skill requires a value")
            skill_path = Path(args[index + 1])
            index += 2
            continue
        if token == "--allow-skill-fallback":
            strict_skill = False
            index += 1
            continue
        positional.append(token)
        index += 1

    return skill_path, strict_skill, positional


if __name__ == "__main__":
    raise SystemExit(main())
