from __future__ import annotations

import re

from .collector import top_level_phase_for_prefix
from .knowledge import (
    contract_applies_in_function_scope,
    contract_applies_in_module,
    contract_applies_to_call,
    contract_applies_to_scope_kind,
    contract_applies_to_top_level_phase,
    contract_applies_to_sink,
)
from .models import CandidateCase, FunctionContract, StaticAnalysisResult
from .summaries import detect_module_name


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SIMPLE_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_:.]*)\s*\((.*)\)\s*$")
_FUNCTION_DEF_RE = re.compile(r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_:.]*)\s*\((.*?)\)\s*$")
_ASSIGNMENT_RE = re.compile(r"^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
_MAX_CHAINED_RETURN_PROOF_DEPTH = 2


def analyze_candidate(
    source: str,
    candidate: CandidateCase,
    *,
    function_contracts: tuple[FunctionContract, ...] = (),
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]] | None = None,
) -> StaticAnalysisResult:
    """Apply bounded local heuristics before escalating to agent review."""

    if not _IDENTIFIER_RE.match(candidate.symbol):
        return StaticAnalysisResult(
            state="unknown_static",
            observed_guards=(),
            origin_candidates=(candidate.expression,),
            origin_usage_modes=("direct_sink",),
            origin_return_slots=(1,),
        )

    lines = source.splitlines()
    prior_lines = lines[: max(0, candidate.line - 1)]
    origin_context = _find_last_assignment(prior_lines, candidate.symbol)
    origin = origin_context[0] if origin_context is not None else None
    observed_guards: list[str] = []
    current_module = detect_module_name(source)
    effective_transparent_return_wrappers = (
        dict(transparent_return_wrappers)
        if transparent_return_wrappers is not None
        else collect_transparent_return_wrappers((source,))
    )
    current_scope_kind = _scope_kind_for_function_scope(candidate.function_scope)
    current_top_level_phase = _top_level_phase_for_candidate(source, candidate)

    if _has_active_positive_guard(prior_lines, candidate.symbol):
        observed_guards.append(f"if {candidate.symbol} then")
    if _has_early_exit_guard(prior_lines, candidate.symbol):
        observed_guards.append(f"if not {candidate.symbol} then return")
    if _has_active_assert(prior_lines, candidate.symbol):
        observed_guards.append(f"assert({candidate.symbol})")
    contract_guard = _active_contract_guard(
        prior_lines,
        candidate.symbol,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=candidate.function_scope,
        current_top_level_phase=current_top_level_phase,
        current_scope_kind=current_scope_kind,
        sink_rule_id=candidate.sink_rule_id,
        sink_name=candidate.sink_name,
    )
    if contract_guard is not None:
        observed_guards.append(contract_guard)
    return_contract_guard = _origin_return_contract_guard(
        prior_lines,
        origin_context,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=candidate.function_scope,
        current_top_level_phase=current_top_level_phase,
        current_scope_kind=current_scope_kind,
        sink_rule_id=candidate.sink_rule_id,
        sink_name=candidate.sink_name,
        transparent_return_wrappers=effective_transparent_return_wrappers,
    )
    if return_contract_guard is not None:
        observed_guards.append(return_contract_guard)
    if _has_defaulting_origin(origin):
        observed_guards.append(f"{candidate.symbol} = {candidate.symbol} or ...")

    state = "safe_static" if observed_guards else "unknown_static"
    origins = (origin,) if origin is not None else (candidate.expression,)
    origin_usage_modes = (
        (origin_context[1],)
        if origin_context is not None
        else ("direct_sink",)
    )
    origin_return_slots = (
        (origin_context[2],)
        if origin_context is not None
        else ()
    )
    return StaticAnalysisResult(
        state=state,
        observed_guards=tuple(observed_guards),
        origin_candidates=origins,
        origin_usage_modes=origin_usage_modes,
        origin_return_slots=origin_return_slots,
    )


def _find_last_assignment(lines: list[str], symbol: str) -> tuple[str, str, int] | None:
    single_pattern = re.compile(
        rf"^\s*(?:local\s+)?{re.escape(symbol)}\s*=\s*(.+?)\s*$",
    )
    multi_pattern = re.compile(
        r"^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*=\s*(.+?)\s*$",
    )

    line_paths, final_path = _scan_branch_paths(lines)

    for line, path in zip(reversed(lines), reversed(line_paths)):
        if not _branch_path_is_prefix(path, final_path):
            continue
        match = single_pattern.match(line)
        if match:
            return match.group(1), "single_assignment", 1
        match = multi_pattern.match(line)
        if match:
            names = [name.strip() for name in match.group(1).split(",")]
            if symbol not in names:
                continue

            values = _split_top_level_values(match.group(2))
            if not values:
                continue

            position = names.index(symbol)
            if position < len(values):
                return values[position], "multi_assignment", 1
            if len(values) == 1:
                # A single function call can populate multiple targets in Lua.
                return values[0], "multi_assignment", position + 1
    return None


def _has_active_positive_guard(lines: list[str], symbol: str) -> bool:
    stack: list[dict[str, int | str]] = []
    invalidated_paths: list[tuple[int, ...]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if any(entry["type"] == "symbol_if" for entry in stack) and _assigns_symbol(stripped, symbol):
            invalidated_paths.append(_current_if_branch_path(stack))
            continue

        if _is_if_open_for_symbol(stripped, symbol):
            stack.append({"type": "symbol_if", "branch": 0})
            continue
        if _is_if_open(stripped):
            stack.append({"type": "if_family", "branch": 0})
            continue
        if _is_elseif_line(stripped):
            if stack and stack[-1]["type"] in {"if_family", "symbol_if"}:
                stack[-1]["type"] = "symbol_if" if _is_elseif_for_symbol(stripped, symbol) else "if_family"
                stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            continue
        if stripped == "else":
            if stack and stack[-1]["type"] in {"if_family", "symbol_if"}:
                stack[-1]["type"] = "if_family"
                stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            continue
        if _opens_non_if_block(stripped):
            stack.append({"type": "block"})
            continue
        if _closes_block(stripped) and stack:
            stack.pop()

    current_path = _current_if_branch_path(stack)
    for guard_path in _active_positive_guard_paths(stack):
        if any(
            _branch_path_is_prefix(guard_path, invalidated_path)
            and _branch_path_is_prefix(invalidated_path, current_path)
            for invalidated_path in invalidated_paths
        ):
            continue
        return True
    return False


def _has_early_exit_guard(lines: list[str], symbol: str) -> bool:
    stack: list[dict[str, int | str]] = []
    valid_guard_paths: list[tuple[int, ...]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if stack and stack[-1]["type"] == "neg_guard_pending":
            if _is_early_exit_statement(stripped):
                stack[-1]["type"] = "neg_guard_exit"
                continue
            if stripped != "end":
                stack[-1]["type"] = "if_family"

        if valid_guard_paths and _assigns_symbol(stripped, symbol):
            valid_guard_paths.clear()

        if _is_negative_guard_for_symbol(stripped, symbol):
            stack.append({"type": "neg_guard_pending", "branch": 0})
            continue
        if _is_if_open_for_symbol(stripped, symbol):
            stack.append({"type": "if_family", "branch": 0})
            continue
        if _is_if_open(stripped):
            stack.append({"type": "if_family", "branch": 0})
            continue
        if _is_elseif_line(stripped):
            if stack and stack[-1]["type"] in {"if_family", "neg_guard_pending", "neg_guard_exit"}:
                stack[-1]["type"] = "if_family"
                stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            continue
        if stripped == "else":
            if stack and stack[-1]["type"] in {"if_family", "neg_guard_pending", "neg_guard_exit"}:
                stack[-1]["type"] = "if_family"
                stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            continue
        if _opens_non_if_block(stripped):
            stack.append({"type": "block"})
            continue
        if _closes_block(stripped) and stack:
            closing = stack.pop()
            if closing["type"] == "neg_guard_exit":
                valid_guard_paths.append(_current_if_branch_path(stack))

    current_path = _current_if_branch_path(stack)
    return any(_branch_path_is_prefix(path, current_path) for path in valid_guard_paths)


def _has_active_assert(lines: list[str], symbol: str) -> bool:
    pattern = re.compile(rf"\bassert\s*\(\s*{re.escape(symbol)}(?:\s*[,)\]])")
    line_paths, final_path = _scan_branch_paths(lines)
    active_assert = False

    for line, path in zip(lines, line_paths):
        if not _branch_path_is_prefix(path, final_path):
            continue

        stripped = line.strip()
        if not stripped:
            continue

        if _assigns_symbol(stripped, symbol):
            active_assert = False
            continue
        if pattern.search(line):
            active_assert = True

    return active_assert


def _has_defaulting_origin(origin: str | None) -> bool:
    if origin is None:
        return False
    if " or " not in origin:
        return False
    # Lua's common ternary idiom `cond and nil or value` can still yield nil on a
    # reachable branch, so it is not equivalent to a non-nil defaulting guard.
    if " and nil or " in origin:
        return False
    return True


def _active_contract_guard(
    lines: list[str],
    symbol: str,
    *,
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
) -> str | None:
    contract_by_name = {
        contract.qualified_name: contract
        for contract in function_contracts
        if contract.ensures_non_nil_args
        and contract_applies_in_module(contract, current_module)
        and contract_applies_in_function_scope(contract, current_function_scope)
        and contract_applies_to_top_level_phase(contract, current_top_level_phase)
        and contract_applies_to_scope_kind(contract, current_scope_kind)
        and contract_applies_to_sink(
            contract,
            current_sink_rule_id=sink_rule_id,
            current_sink_name=sink_name,
        )
    }
    if not contract_by_name:
        return None

    line_paths, final_path = _scan_branch_paths(lines)
    active_guard: str | None = None
    known_contract_names = frozenset(contract_by_name)

    for line, path in zip(lines, line_paths):
        if not _branch_path_is_prefix(path, final_path):
            continue

        stripped = _strip_lua_comment(line).strip()
        if not stripped:
            continue

        if _assigns_symbol(stripped, symbol):
            active_guard = None
            continue

        parsed_call = _parse_simple_call(stripped)
        if parsed_call is None:
            continue

        raw_name, args = parsed_call
        resolved_name = _resolve_contract_name(
            raw_name,
            current_module=current_module,
            known_contract_names=known_contract_names,
        )
        contract = contract_by_name.get(resolved_name)
        if contract is None:
            continue
        if not contract_applies_to_call(
            contract,
            arg_count=len(args),
            arg_values=args,
            call_role="guard_call",
        ):
            continue
        if _contract_matches_symbol(contract, args, symbol):
            active_guard = f"{resolved_name}({symbol})"

    return active_guard


def _origin_return_contract_guard(
    lines: list[str],
    origin_context: tuple[str, str, int] | None,
    *,
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
) -> str | None:
    if origin_context is None:
        return None
    origin, usage_mode, return_slot = origin_context

    contract_by_name = {
        contract.qualified_name: contract
        for contract in function_contracts
        if (
            contract.returns_non_nil_from_args
            or contract.returns_non_nil_from_args_by_return_slot
        )
        and contract_applies_in_module(contract, current_module)
        and contract_applies_in_function_scope(contract, current_function_scope)
        and contract_applies_to_top_level_phase(contract, current_top_level_phase)
        and contract_applies_to_scope_kind(contract, current_scope_kind)
        and contract_applies_to_sink(
            contract,
            current_sink_rule_id=sink_rule_id,
            current_sink_name=sink_name,
        )
    }
    parsed_call = _parse_simple_call(_strip_lua_comment(origin).strip())
    if parsed_call is None:
        return None

    raw_name, args = parsed_call
    resolved_name = _resolve_contract_name(
        raw_name,
        current_module=current_module,
        known_contract_names=frozenset(contract_by_name),
    )
    contract = contract_by_name.get(resolved_name)
    if contract is not None and contract_applies_to_call(
        contract,
        arg_count=len(args),
        arg_values=args,
        call_role="assignment_origin",
        usage_mode=usage_mode,
        return_slot=return_slot,
    ):
        required_args = _required_return_args_for_slot(contract, return_slot)
        if required_args is not None and _contract_has_all_required_args(required_args, args):
            guarded_args = _required_guarded_args_for_slot(contract, return_slot)
            if _contract_has_guarded_args(
                guarded_args,
                args,
                lines=lines,
                return_contracts=contract_by_name,
                function_contracts=function_contracts,
                current_module=current_module,
                current_function_scope=current_function_scope,
                current_top_level_phase=current_top_level_phase,
                current_scope_kind=current_scope_kind,
                sink_rule_id=sink_rule_id,
                sink_name=sink_name,
                transparent_return_wrappers=transparent_return_wrappers,
                remaining_chain_depth=_MAX_CHAINED_RETURN_PROOF_DEPTH,
            ):
                return f"{resolved_name}(...) returns non-nil"

    wrapper_name = _resolve_contract_name(
        raw_name,
        current_module=current_module,
        known_contract_names=frozenset(transparent_return_wrappers),
    )
    if _transparent_wrapper_returns_safe_value(
        wrapper_name,
        args,
        return_slot=return_slot,
        lines=lines,
        return_contracts=contract_by_name,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=current_function_scope,
        current_top_level_phase=current_top_level_phase,
        current_scope_kind=current_scope_kind,
        sink_rule_id=sink_rule_id,
        sink_name=sink_name,
        transparent_return_wrappers=transparent_return_wrappers,
        remaining_chain_depth=_MAX_CHAINED_RETURN_PROOF_DEPTH,
    ):
        return f"{wrapper_name}(...) preserves or defaults to non-nil"
    return None


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


def _parse_simple_call(stripped_line: str) -> tuple[str, tuple[str, ...]] | None:
    match = _SIMPLE_CALL_RE.match(stripped_line)
    if match is None:
        return None
    return match.group(1), tuple(_split_top_level_values(match.group(2)))


def _resolve_contract_name(
    raw_name: str,
    *,
    current_module: str | None,
    known_contract_names: frozenset[str],
) -> str:
    normalized = raw_name.replace(":", ".")
    if "." in normalized:
        return normalized
    if current_module:
        module_qualified = f"{current_module}.{normalized}"
        if module_qualified in known_contract_names:
            return module_qualified
    return normalized


def _contract_matches_symbol(
    contract: FunctionContract,
    args: tuple[str, ...],
    symbol: str,
) -> bool:
    for index in contract.ensures_non_nil_args:
        if 1 <= index <= len(args) and args[index - 1].strip() == symbol:
            return True
    return False


def _contract_has_all_required_args(
    required_positions: tuple[int, ...],
    args: tuple[str, ...],
) -> bool:
    return all(1 <= index <= len(args) for index in required_positions)


def _required_return_args_for_slot(
    contract: FunctionContract,
    return_slot: int,
) -> tuple[int, ...] | None:
    for slot, positions in contract.returns_non_nil_from_args_by_return_slot:
        if slot == return_slot:
            return positions
    if contract.returns_non_nil_from_args:
        return contract.returns_non_nil_from_args
    if contract.returns_non_nil_from_args_by_return_slot:
        return None
    return ()


def _required_guarded_args_for_slot(
    contract: FunctionContract,
    return_slot: int,
) -> tuple[int, ...]:
    for slot, positions in contract.requires_guarded_args_by_return_slot:
        if slot == return_slot:
            return positions
    return ()


def _contract_has_guarded_args(
    required_positions: tuple[int, ...],
    args: tuple[str, ...],
    *,
    lines: list[str],
    return_contracts: dict[str, FunctionContract],
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
    remaining_chain_depth: int,
) -> bool:
    for index in required_positions:
        if index < 1 or index > len(args):
            return False
        symbol = args[index - 1].strip()
        if not _IDENTIFIER_RE.match(symbol):
            return False
        if _is_symbol_guarded(
            lines,
            symbol,
            return_contracts=return_contracts,
            function_contracts=function_contracts,
            current_module=current_module,
            current_function_scope=current_function_scope,
            current_top_level_phase=current_top_level_phase,
            current_scope_kind=current_scope_kind,
            sink_rule_id=sink_rule_id,
            sink_name=sink_name,
            transparent_return_wrappers=transparent_return_wrappers,
            remaining_chain_depth=remaining_chain_depth,
        ):
            continue
        return False
    return True


def _is_symbol_guarded(
    lines: list[str],
    symbol: str,
    *,
    return_contracts: dict[str, FunctionContract],
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
    remaining_chain_depth: int,
) -> bool:
    if _has_active_positive_guard(lines, symbol):
        return True
    if _has_early_exit_guard(lines, symbol):
        return True
    if _has_active_assert(lines, symbol):
        return True
    return (
        (
            _active_contract_guard(
                lines,
                symbol,
                function_contracts=function_contracts,
                current_module=current_module,
                current_function_scope=current_function_scope,
                current_top_level_phase=current_top_level_phase,
                current_scope_kind=current_scope_kind,
                sink_rule_id=sink_rule_id,
                sink_name=sink_name,
            )
            is not None
        )
        or _is_symbol_derived_from_safe_return_chain(
            lines,
            symbol,
            return_contracts=return_contracts,
            function_contracts=function_contracts,
            current_module=current_module,
            current_function_scope=current_function_scope,
            current_top_level_phase=current_top_level_phase,
            current_scope_kind=current_scope_kind,
            sink_rule_id=sink_rule_id,
            sink_name=sink_name,
            transparent_return_wrappers=transparent_return_wrappers,
            remaining_chain_depth=remaining_chain_depth,
        )
    )


def _is_symbol_derived_from_safe_return_chain(
    lines: list[str],
    symbol: str,
    *,
    return_contracts: dict[str, FunctionContract],
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
    remaining_chain_depth: int,
) -> bool:
    if remaining_chain_depth <= 0:
        return False
    origin_context = _find_last_assignment(lines, symbol)
    if origin_context is None:
        return False
    origin, usage_mode, return_slot = origin_context
    if origin.strip() == symbol:
        return False
    parsed_call = _parse_simple_call(_strip_lua_comment(origin).strip())
    if parsed_call is None:
        return _has_defaulting_origin(origin)

    raw_name, args = parsed_call
    resolved_name = _resolve_contract_name(
        raw_name,
        current_module=current_module,
        known_contract_names=frozenset(return_contracts),
    )
    contract = return_contracts.get(resolved_name)
    if contract is not None and contract_applies_to_call(
        contract,
        arg_count=len(args),
        arg_values=args,
        call_role="assignment_origin",
        usage_mode=usage_mode,
        return_slot=return_slot,
    ):
        required_args = _required_return_args_for_slot(contract, return_slot)
        if required_args is not None and _contract_has_all_required_args(required_args, args):
            guarded_args = _required_guarded_args_for_slot(contract, return_slot)
            if _contract_has_guarded_args(
                guarded_args,
                args,
                lines=lines,
                return_contracts=return_contracts,
                function_contracts=function_contracts,
                current_module=current_module,
                current_function_scope=current_function_scope,
                current_top_level_phase=current_top_level_phase,
                current_scope_kind=current_scope_kind,
                sink_rule_id=sink_rule_id,
                sink_name=sink_name,
                transparent_return_wrappers=transparent_return_wrappers,
                remaining_chain_depth=remaining_chain_depth - 1,
            ):
                return True

    wrapper_name = _resolve_contract_name(
        raw_name,
        current_module=current_module,
        known_contract_names=frozenset(transparent_return_wrappers),
    )
    return _transparent_wrapper_returns_safe_value(
        wrapper_name,
        args,
        return_slot=return_slot,
        lines=lines,
        return_contracts=return_contracts,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=current_function_scope,
        current_top_level_phase=current_top_level_phase,
        current_scope_kind=current_scope_kind,
        sink_rule_id=sink_rule_id,
        sink_name=sink_name,
        transparent_return_wrappers=transparent_return_wrappers,
        remaining_chain_depth=remaining_chain_depth,
    )


def _transparent_wrapper_returns_safe_value(
    resolved_name: str,
    args: tuple[str, ...],
    *,
    return_slot: int,
    lines: list[str],
    return_contracts: dict[str, FunctionContract],
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
    remaining_chain_depth: int,
) -> bool:
    passthrough_index = _transparent_wrapper_arg_for_slot(
        transparent_return_wrappers.get(resolved_name),
        return_slot,
    )
    if passthrough_index is None or passthrough_index < 1 or passthrough_index > len(args):
        if passthrough_index == 0:
            return True
        return False
    next_remaining_depth = remaining_chain_depth - 1
    if next_remaining_depth < 0:
        return False
    passthrough_value = args[passthrough_index - 1].strip()
    if not passthrough_value or passthrough_value == resolved_name:
        return False
    if _is_non_nil_literal(passthrough_value):
        return True
    if _IDENTIFIER_RE.match(passthrough_value):
        if _is_symbol_guarded(
            lines,
            passthrough_value,
            return_contracts=return_contracts,
            function_contracts=function_contracts,
            current_module=current_module,
            current_function_scope=current_function_scope,
            current_top_level_phase=current_top_level_phase,
            current_scope_kind=current_scope_kind,
            sink_rule_id=sink_rule_id,
            sink_name=sink_name,
            transparent_return_wrappers=transparent_return_wrappers,
            remaining_chain_depth=next_remaining_depth,
        ):
            return True
        if next_remaining_depth == 0:
            return _has_terminal_safe_return_origin(
                lines,
                passthrough_value,
                return_contracts=return_contracts,
                function_contracts=function_contracts,
                current_module=current_module,
                current_function_scope=current_function_scope,
                current_top_level_phase=current_top_level_phase,
                current_scope_kind=current_scope_kind,
                sink_rule_id=sink_rule_id,
                sink_name=sink_name,
                transparent_return_wrappers=transparent_return_wrappers,
            )
        return False
    return _has_defaulting_origin(passthrough_value)


def _transparent_wrapper_arg_for_slot(
    slot_mappings: tuple[tuple[int, int], ...] | None,
    return_slot: int,
) -> int | None:
    if slot_mappings is None:
        return None
    for slot, arg_index in slot_mappings:
        if slot == return_slot:
            return arg_index
    return None


def _has_terminal_safe_return_origin(
    lines: list[str],
    symbol: str,
    *,
    return_contracts: dict[str, FunctionContract],
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
) -> bool:
    origin_context = _find_last_assignment(lines, symbol)
    if origin_context is None:
        return False
    origin, usage_mode, return_slot = origin_context
    parsed_call = _parse_simple_call(_strip_lua_comment(origin).strip())
    if parsed_call is None:
        return _has_defaulting_origin(origin)

    raw_name, args = parsed_call
    resolved_name = _resolve_contract_name(
        raw_name,
        current_module=current_module,
        known_contract_names=frozenset(return_contracts),
    )
    contract = return_contracts.get(resolved_name)
    if contract is None:
        return False
    if not contract_applies_to_call(
        contract,
        arg_count=len(args),
        arg_values=args,
        call_role="assignment_origin",
        usage_mode=usage_mode,
        return_slot=return_slot,
    ):
        return False

    required_args = _required_return_args_for_slot(contract, return_slot)
    if required_args is None or not _contract_has_all_required_args(required_args, args):
        return False
    guarded_args = _required_guarded_args_for_slot(contract, return_slot)
    return _contract_has_guarded_args(
        guarded_args,
        args,
        lines=lines,
        return_contracts=return_contracts,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=current_function_scope,
        current_top_level_phase=current_top_level_phase,
        current_scope_kind=current_scope_kind,
        sink_rule_id=sink_rule_id,
        sink_name=sink_name,
        transparent_return_wrappers=transparent_return_wrappers,
        remaining_chain_depth=-1,
    )


def collect_transparent_return_wrappers(
    sources: tuple[str, ...],
) -> dict[str, tuple[tuple[int, int], ...]]:
    wrappers: dict[str, tuple[tuple[int, int], ...]] = {}
    for source in sources:
        wrappers.update(
            _collect_transparent_return_wrappers_from_source(
                source,
                current_module=detect_module_name(source),
            )
        )
    return wrappers


def _collect_transparent_return_wrappers_from_source(
    source: str,
    *,
    current_module: str | None,
) -> dict[str, tuple[tuple[int, int], ...]]:
    lines = source.splitlines()
    wrappers: dict[str, tuple[tuple[int, int], ...]] = {}
    index = 0

    while index < len(lines):
        stripped = _strip_lua_comment(lines[index]).strip()
        match = _FUNCTION_DEF_RE.match(stripped)
        if match is None:
            index += 1
            continue

        raw_name = match.group(1)
        params_text = match.group(2).strip()
        params = _split_top_level_values(params_text) if params_text else []
        body_lines: list[str] = []
        depth = 1
        index += 1

        while index < len(lines) and depth > 0:
            body_line = lines[index]
            body_stripped = _strip_lua_comment(body_line).strip()
            if body_stripped and (_is_if_open(body_stripped) or _opens_non_if_block(body_stripped)):
                depth += 1
            if body_stripped and _closes_block(body_stripped):
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            if depth > 0:
                body_lines.append(body_line)
            index += 1

        transparent_mapping = _transparent_return_mapping(body_lines, params)
        if transparent_mapping:
            wrappers[_normalize_defined_function_name(raw_name, current_module=current_module)] = transparent_mapping

    return wrappers


def _transparent_return_mapping(
    body_lines: list[str],
    params: list[str],
) -> tuple[tuple[int, int], ...]:
    meaningful_lines = [
        _strip_lua_comment(line).strip()
        for line in body_lines
        if _strip_lua_comment(line).strip()
    ]
    if len(meaningful_lines) != 1:
        if len(meaningful_lines) == 2:
            return _aliased_wrapper_return_mapping(meaningful_lines, params)
        return ()
    statement = meaningful_lines[0]
    if not statement.startswith("return "):
        return ()
    return _direct_wrapper_return_mapping(statement[len("return ") :], params)


def _direct_wrapper_return_mapping(
    return_text: str,
    params: list[str],
) -> tuple[tuple[int, int], ...]:
    return_values = _split_top_level_values(return_text)
    if not return_values:
        return ()

    mapping: list[tuple[int, int]] = []
    for slot, value in enumerate(return_values, start=1):
        source_arg = _wrapper_return_source_arg(value, params)
        if source_arg is None:
            return ()
        mapping.append((slot, source_arg))
    return tuple(mapping)


def _aliased_wrapper_return_mapping(
    meaningful_lines: list[str],
    params: list[str],
) -> tuple[tuple[int, int], ...]:
    assign_match = _ASSIGNMENT_RE.match(meaningful_lines[0])
    if assign_match is None:
        return ()
    alias = assign_match.group(1)
    if meaningful_lines[1] != f"return {alias}":
        return ()
    source_arg = _wrapper_return_source_arg(assign_match.group(2), params)
    if source_arg is None:
        return ()
    return ((1, source_arg),)


def _wrapper_return_source_arg(
    expression: str,
    params: list[str],
) -> int | None:
    value = expression.strip()
    if value in params:
        return params.index(value) + 1
    if _is_non_nil_literal(value):
        return 0
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+or\s+(.+)$", value)
    if match is None:
        return None
    if match.group(1) not in params:
        return None
    fallback_value = match.group(2).strip()
    if _is_non_nil_literal(fallback_value):
        return 0
    if fallback_value in params:
        return params.index(fallback_value) + 1
    return None


def _is_non_nil_literal(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return True
    if stripped in {"true", "false"}:
        return True
    if re.match(r"^-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$", stripped):
        return True
    return stripped.startswith("{") and stripped.endswith("}")


def _normalize_defined_function_name(
    raw_name: str,
    *,
    current_module: str | None,
) -> str:
    normalized = raw_name.replace(":", ".")
    if "." in normalized or not current_module:
        return normalized
    return f"{current_module}.{normalized}"


def _scope_kind_for_function_scope(function_scope: str | None) -> str | None:
    if function_scope is None:
        return None
    return "top_level" if function_scope == "main" else "function_body"


def _top_level_phase_for_candidate(source: str, candidate: CandidateCase) -> str | None:
    if candidate.function_scope != "main":
        return None
    prefix = "\n".join(source.splitlines()[: max(0, candidate.line - 1)])
    return top_level_phase_for_prefix(prefix)


def _is_if_open_for_symbol(stripped_line: str, symbol: str) -> bool:
    if not _is_if_open(stripped_line):
        return False
    condition = stripped_line[len("if ") : -len(" then")].strip()
    return condition == symbol or condition == f"{symbol} ~= nil"


def _is_if_open(stripped_line: str) -> bool:
    return stripped_line.startswith("if ") and stripped_line.endswith(" then")


def _is_elseif_line(stripped_line: str) -> bool:
    return stripped_line.startswith("elseif ") and stripped_line.endswith(" then")


def _is_elseif_for_symbol(stripped_line: str, symbol: str) -> bool:
    condition = stripped_line[len("elseif ") : -len(" then")].strip()
    return condition == symbol or condition == f"{symbol} ~= nil"


def _opens_non_if_block(stripped_line: str) -> bool:
    return (
        (stripped_line.startswith("for ") and stripped_line.endswith(" do"))
        or (stripped_line.startswith("while ") and stripped_line.endswith(" do"))
        or stripped_line == "do"
        or stripped_line == "repeat"
        or bool(re.match(r"^(?:local\s+)?function\b", stripped_line))
        or bool(re.search(r"(?:=\s*|return\s+)function\b", stripped_line))
    )


def _closes_block(stripped_line: str) -> bool:
    return stripped_line == "end" or stripped_line.startswith("until ")


def _is_negative_guard_for_symbol(stripped_line: str, symbol: str) -> bool:
    return (
        stripped_line == f"if not {symbol} then"
        or stripped_line == f"if {symbol} == nil then"
    )


def _is_early_exit_statement(stripped_line: str) -> bool:
    return (
        stripped_line == "return"
        or stripped_line.startswith("return ")
        or stripped_line.startswith("error(")
        or stripped_line.startswith("assert(false")
    )


def _assigns_symbol(stripped_line: str, symbol: str) -> bool:
    single_pattern = re.compile(
        rf"^(?:local\s+)?{re.escape(symbol)}\s*=\s*.+$",
    )
    if single_pattern.match(stripped_line):
        return True

    multi_pattern = re.compile(
        r"^(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*=\s*.+$",
    )
    match = multi_pattern.match(stripped_line)
    if match is None:
        return False
    names = [name.strip() for name in match.group(1).split(",")]
    return symbol in names


def _scan_branch_paths(lines: list[str]) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    stack: list[dict[str, int | str]] = []
    line_paths: list[tuple[int, ...]] = []

    for line in lines:
        stripped = line.strip()
        if stripped:
            if _is_elseif_line(stripped):
                if stack and stack[-1]["type"] == "if_family":
                    stack[-1]["branch"] = int(stack[-1]["branch"]) + 1
            elif stripped == "else":
                if stack and stack[-1]["type"] == "if_family":
                    stack[-1]["branch"] = int(stack[-1]["branch"]) + 1

        line_paths.append(_current_if_branch_path(stack))

        if not stripped:
            continue
        if _is_if_open(stripped):
            stack.append({"type": "if_family", "branch": 0})
            continue
        if _opens_non_if_block(stripped):
            stack.append({"type": "block"})
            continue
        if _closes_block(stripped) and stack:
            stack.pop()

    return tuple(line_paths), _current_if_branch_path(stack)


def _strip_lua_comment(line: str) -> str:
    return line.partition("--")[0]


def _current_if_branch_path(stack: list[dict[str, int | str]]) -> tuple[int, ...]:
    return tuple(
        int(entry["branch"])
        for entry in stack
        if entry["type"] in {"if_family", "symbol_if", "neg_guard_pending", "neg_guard_exit"}
    )


def _branch_path_is_prefix(path: tuple[int, ...], current_path: tuple[int, ...]) -> bool:
    if len(path) > len(current_path):
        return False
    return current_path[: len(path)] == path


def _active_positive_guard_paths(stack: list[dict[str, int | str]]) -> tuple[tuple[int, ...], ...]:
    paths: list[tuple[int, ...]] = []
    current: list[int] = []
    for entry in stack:
        if entry["type"] not in {"if_family", "symbol_if"}:
            continue
        current.append(int(entry["branch"]))
        if entry["type"] == "symbol_if":
            paths.append(tuple(current))
    return tuple(paths)
