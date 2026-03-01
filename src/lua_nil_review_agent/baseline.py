from __future__ import annotations

import json
from pathlib import Path

from .models import ConfidencePolicy, Verdict
from .pipeline import should_report


class BaselineStore:
    """Persist previously accepted finding keys."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> tuple[str, ...]:
        if not self.path.exists():
            return ()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return tuple(item for item in data if isinstance(item, str))

    def save(self, case_ids: tuple[str, ...]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(list(case_ids), indent=2), encoding="utf-8")


def build_baseline(
    verdicts: tuple[Verdict, ...],
    policy: ConfidencePolicy,
) -> tuple[str, ...]:
    """Create a baseline key set from current reportable findings."""

    return tuple(verdict.case_id for verdict in verdicts if should_report(verdict, policy))


def filter_new_findings(
    verdicts: tuple[Verdict, ...],
    baseline_case_ids: tuple[str, ...],
    policy: ConfidencePolicy,
) -> tuple[Verdict, ...]:
    """Return only reportable findings not already present in baseline."""

    seen = set(baseline_case_ids)
    return tuple(
        verdict
        for verdict in verdicts
        if should_report(verdict, policy) and verdict.case_id not in seen
    )
