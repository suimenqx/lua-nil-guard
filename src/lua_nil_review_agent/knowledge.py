from __future__ import annotations

import json
from pathlib import Path

from .models import KnowledgeFact


class KnowledgeBase:
    """Persist repository facts as JSON."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> tuple[KnowledgeFact, ...]:
        if not self.path.exists():
            return ()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return tuple(
            KnowledgeFact(
                key=item["key"],
                subject=item["subject"],
                statement=item["statement"],
                confidence=item["confidence"],
                source=item["source"],
            )
            for item in data
        )

    def save(self, facts: tuple[KnowledgeFact, ...]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "key": fact.key,
                "subject": fact.subject,
                "statement": fact.statement,
                "confidence": fact.confidence,
                "source": fact.source,
            }
            for fact in facts
        ]
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def facts_for_subject(facts: tuple[KnowledgeFact, ...], subject: str) -> tuple[str, ...]:
    """Return the statements relevant to a single subject."""

    return tuple(fact.statement for fact in facts if fact.subject == subject)
