from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Sequence

from .service import bootstrap_repository, review_repository


def run(argv: Sequence[str]) -> tuple[int, str]:
    """Execute the minimal CLI and return an exit code with rendered output."""

    args = list(argv)
    if not args or args[0] in {"-h", "--help"}:
        return 0, _usage()

    command = args[0]
    if command != "scan":
        return 2, _usage()
    if len(args) != 2:
        return 2, "scan requires exactly one repository path"

    root = Path(args[1])
    snapshot = bootstrap_repository(root)
    assessments = review_repository(snapshot)
    return 0, _render_scan_summary(snapshot.root, assessments)


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
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
