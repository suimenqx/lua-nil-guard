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
    *,
    current_module: str | None = None,
    current_function_scope: str | None = None,
    current_top_level_phase: str | None = None,
    current_scope_kind: str | None = None,
    current_sink_rule_id: str | None = None,
    current_sink_name: str | None = None,
) -> tuple[KnowledgeFact, ...]:
    """Convert configured contracts into high-confidence reusable safety facts."""

    facts: list[KnowledgeFact] = []
    for contract in contracts:
        if not contract_applies_in_module(contract, current_module):
            continue
        if not contract_applies_in_function_scope(contract, current_function_scope):
            continue
        if not contract_applies_to_top_level_phase(contract, current_top_level_phase):
            continue
        if not contract_applies_to_scope_kind(contract, current_scope_kind):
            continue
        if not contract_applies_to_sink(
            contract,
            current_sink_rule_id=current_sink_rule_id,
            current_sink_name=current_sink_name,
        ):
            continue
        if not contract_applies_to_call(contract, arg_count=None):
            continue
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


def contract_applies_in_module(
    contract: FunctionContract,
    current_module: str | None,
) -> bool:
    """Return whether a contract is active for the current caller module."""

    if not contract.applies_in_modules:
        return True
    if current_module is None:
        return False
    return current_module in contract.applies_in_modules


def contract_applies_in_function_scope(
    contract: FunctionContract,
    current_function_scope: str | None,
) -> bool:
    """Return whether a contract is active for the current caller function scope."""

    if not contract.applies_in_function_scopes:
        return True
    if current_function_scope is None:
        return False
    return current_function_scope in contract.applies_in_function_scopes


def contract_applies_to_top_level_phase(
    contract: FunctionContract,
    current_top_level_phase: str | None,
) -> bool:
    """Return whether a contract is active for the current top-level phase."""

    if not contract.applies_to_top_level_phases:
        return True
    if current_top_level_phase is None:
        return False
    return current_top_level_phase in contract.applies_to_top_level_phases


def contract_applies_to_scope_kind(
    contract: FunctionContract,
    current_scope_kind: str | None,
) -> bool:
    """Return whether a contract is active for the current caller scope kind."""

    if not contract.applies_to_scope_kinds:
        return True
    if current_scope_kind is None:
        return False
    return current_scope_kind in contract.applies_to_scope_kinds


def contract_applies_to_sink(
    contract: FunctionContract,
    *,
    current_sink_rule_id: str | None,
    current_sink_name: str | None,
) -> bool:
    """Return whether a contract is active for the current sink target."""

    if not contract.applies_to_sinks:
        return True
    candidates = {current_sink_rule_id, current_sink_name}
    return any(item in candidates for item in contract.applies_to_sinks)


def contract_applies_to_call(
    contract: FunctionContract,
    *,
    arg_count: int | None,
    arg_values: tuple[str, ...] | None = None,
    call_role: str | None = None,
    usage_mode: str | None = None,
) -> bool:
    """Return whether a contract is active for the current call shape."""

    if contract.applies_to_call_roles:
        if call_role is None:
            return False
        if call_role not in contract.applies_to_call_roles:
            return False
    if contract.applies_to_usage_modes:
        if usage_mode is None:
            return False
        if usage_mode not in contract.applies_to_usage_modes:
            return False

    if contract.applies_with_arg_count is None:
        arg_count_matches = True
    else:
        if arg_count is None:
            return False
        arg_count_matches = arg_count == contract.applies_with_arg_count
    if not arg_count_matches:
        return False

    if not contract.required_literal_args:
        return True
    if arg_values is None:
        return False

    for index, allowed_literals in contract.required_literal_args:
        if index < 1 or index > len(arg_values):
            return False
        if arg_values[index - 1].strip() not in allowed_literals:
            return False
    return True


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
