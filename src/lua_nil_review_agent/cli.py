from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Sequence

from .baseline import BaselineStore, build_baseline, filter_new_findings
from .reporting import render_json_report, render_markdown_report
from .service import (
    bootstrap_repository,
    export_adjudication_tasks,
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
        if len(args) != 2:
            return 2, "report requires exactly one repository path"
        root = Path(args[1])
        snapshot = bootstrap_repository(root)
        verdicts = run_repository_review(snapshot)
        return 0, render_markdown_report(verdicts, snapshot.confidence_policy)

    if command == "report-json":
        if len(args) != 2:
            return 2, "report-json requires exactly one repository path"
        root = Path(args[1])
        snapshot = bootstrap_repository(root)
        verdicts = run_repository_review(snapshot)
        return 0, render_json_report(verdicts, snapshot.confidence_policy)

    if command == "baseline-create":
        if len(args) != 3:
            return 2, "baseline-create requires a repository path and output path"
        root = Path(args[1])
        baseline_path = Path(args[2])
        snapshot = bootstrap_repository(root)
        verdicts = run_repository_review(snapshot)
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
        if len(args) != 3:
            return 2, "report-new requires a repository path and baseline path"
        root = Path(args[1])
        baseline_path = Path(args[2])
        snapshot = bootstrap_repository(root)
        verdicts = run_repository_review(snapshot)
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
        if len(args) != 3:
            return 2, "ci-check requires a repository path and baseline path"
        root = Path(args[1])
        baseline_path = Path(args[2])
        snapshot = bootstrap_repository(root)
        verdicts = run_repository_review(snapshot)
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
        if len(args) not in {2, 3}:
            return 2, "export-prompts requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        snapshot = bootstrap_repository(root)
        tasks = export_adjudication_tasks(snapshot, output_path=output_path)
        if output_path is None:
            return 0, json.dumps(tasks, indent=2, sort_keys=True)
        return 0, "\n".join(
            [
                "Prompt export complete.",
                f"Prompt tasks: {len(tasks)}",
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
    counts = Counter(
        assessment.candidate.static_state
        for assessment in assessments
    )

    lines = [
        "# Lua Nil Review Static Summary",
        "",
        f"Repository: {root}",
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
            "  lua-nil-review-agent report <repository>",
            "  lua-nil-review-agent report-json <repository>",
            "  lua-nil-review-agent baseline-create <repository> <output>",
            "  lua-nil-review-agent report-new <repository> <baseline>",
            "  lua-nil-review-agent refresh-summaries <repository> [output]",
            "  lua-nil-review-agent refresh-knowledge <repository> [output]",
            "  lua-nil-review-agent ci-check <repository> <baseline>",
            "  lua-nil-review-agent export-prompts <repository> [output]",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
