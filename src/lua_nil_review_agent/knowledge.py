from __future__ import annotations

import json
from pathlib import Path

from .models import FunctionContract, FunctionSummary, KnowledgeFact


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


def derive_facts_from_summaries(summaries: tuple[FunctionSummary, ...]) -> tuple[KnowledgeFact, ...]:
    """Derive reusable knowledge facts from function summaries."""

    facts: list[KnowledgeFact] = []
    for summary in summaries:
        if _returns_non_nil_value(summary):
            facts.append(
                KnowledgeFact(
                    key=f"{summary.qualified_name}.returns_non_nil",
                    subject=summary.qualified_name,
                    statement=f"{summary.qualified_name} returns non-nil value",
                    confidence="medium",
                    source="summary",
                )
            )
    return tuple(facts)


def derive_facts_from_contracts(
    contracts: tuple[FunctionContract, ...],
) -> tuple[KnowledgeFact, ...]:
    """Convert configured contracts into high-confidence reusable safety facts."""

    facts: list[KnowledgeFact] = []
    for contract in contracts:
        if contract.returns_non_nil:
            facts.append(
                KnowledgeFact(
                    key=f"{contract.qualified_name}.contract_returns_non_nil",
                    subject=contract.qualified_name,
                    statement=f"{contract.qualified_name} returns non-nil value",
                    confidence="high",
                    source="config",
                )
            )
    return tuple(facts)


def _returns_non_nil_value(summary: FunctionSummary) -> bool:
    for returned in summary.returns:
        first_value = _first_return_value(returned)
        if first_value.startswith(("'", '"', "{")):
            return True
        if first_value in summary.params:
            for guard in summary.guards:
                if guard.startswith(f"{first_value} = {first_value} or "):
                    return True
            if summary.params[first_value] == "non_nil_required":
                return True
    return False


def _first_return_value(returned: str) -> str:
    values = _split_top_level_values(returned)
    if not values:
        return returned.strip()
    return values[0]


def _split_top_level_values(values_text: str) -> list[str]:
    values: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(values_text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            values.append(values_text[start:index].strip())
            start = index + 1

    tail = values_text[start:].strip()
    if tail:
        values.append(tail)
    return values
