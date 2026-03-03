from __future__ import annotations

import re

from .knowledge import (
    contract_applies_in_function_scope,
    contract_applies_in_module,
    contract_applies_to_call,
    contract_applies_to_sink,
)
from .models import CandidateCase, FunctionContract, StaticAnalysisResult
from .summaries import detect_module_name


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SIMPLE_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_:.]*)\s*\((.*)\)\s*$")


def analyze_candidate(
    source: str,
    candidate: CandidateCase,
    *,
    function_contracts: tuple[FunctionContract, ...] = (),
) -> StaticAnalysisResult:
    """Apply bounded local heuristics before escalating to agent review."""

    if not _IDENTIFIER_RE.match(candidate.symbol):
        return StaticAnalysisResult(
            state="unknown_static",
            observed_guards=(),
            origin_candidates=(candidate.expression,),
            origin_usage_modes=("direct_sink",),
        )

    lines = source.splitlines()
    prior_lines = lines[: max(0, candidate.line - 1)]
    origin_context = _find_last_assignment(prior_lines, candidate.symbol)
    origin = origin_context[0] if origin_context is not None else None
    observed_guards: list[str] = []
    current_module = detect_module_name(source)

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
        sink_rule_id=candidate.sink_rule_id,
        sink_name=candidate.sink_name,
    )
    if contract_guard is not None:
        observed_guards.append(contract_guard)
    return_contract_guard = _origin_return_contract_guard(
        origin_context,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=candidate.function_scope,
        sink_rule_id=candidate.sink_rule_id,
        sink_name=candidate.sink_name,
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
    return StaticAnalysisResult(
        state=state,
        observed_guards=tuple(observed_guards),
        origin_candidates=origins,
        origin_usage_modes=origin_usage_modes,
    )


def _find_last_assignment(lines: list[str], symbol: str) -> tuple[str, str] | None:
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
            return match.group(1), "single_assignment"
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
                return values[position], "multi_assignment"
            if len(values) == 1:
                # A single function call can populate multiple targets in Lua.
                return values[0], "multi_assignment"
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
    sink_rule_id: str,
    sink_name: str,
) -> str | None:
    contract_by_name = {
        contract.qualified_name: contract
        for contract in function_contracts
        if contract.ensures_non_nil_args
        and contract_applies_in_module(contract, current_module)
        and contract_applies_in_function_scope(contract, current_function_scope)
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
    origin_context: tuple[str, str] | None,
    *,
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    sink_rule_id: str,
    sink_name: str,
) -> str | None:
    if origin_context is None:
        return None
    origin, usage_mode = origin_context

    contract_by_name = {
        contract.qualified_name: contract
        for contract in function_contracts
        if contract.returns_non_nil_from_args
        and contract_applies_in_module(contract, current_module)
        and contract_applies_in_function_scope(contract, current_function_scope)
        and contract_applies_to_sink(
            contract,
            current_sink_rule_id=sink_rule_id,
            current_sink_name=sink_name,
        )
    }
    if not contract_by_name:
        return None

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
    if contract is None:
        return None
    if not contract_applies_to_call(
        contract,
        arg_count=len(args),
        arg_values=args,
        call_role="assignment_origin",
        usage_mode=usage_mode,
    ):
        return None

    if not _contract_has_all_required_args(contract.returns_non_nil_from_args, args):
        return None
    return f"{resolved_name}(...) returns non-nil"


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
