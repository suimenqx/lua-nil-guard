from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .collector import top_level_phase_for_prefix
from .knowledge import (
    contract_applies_in_function_scope,
    contract_applies_in_module,
    contract_applies_to_call,
    contract_applies_to_scope_kind,
    contract_applies_to_top_level_phase,
    contract_applies_to_sink,
    extract_access_path,
)
from .models import CandidateCase, FunctionContract, StaticAnalysisResult, StaticProof
from .parser_backend import _load_lua_language
from .summaries import detect_module_name


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SIMPLE_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_:.]*)\s*\((.*)\)\s*$")
_FUNCTION_DEF_RE = re.compile(r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_:.]*)\s*\((.*?)\)\s*$")
_ASSIGNMENT_RE = re.compile(r"^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
_MAX_CHAINED_RETURN_PROOF_DEPTH = 2
_AST_CONTROL_FLOW_QUERY_PATH = Path(__file__).resolve().parent / "queries" / "lua" / "control_flow.scm"
_AST_CONTROL_FLOW_QUERY_TEXT: str | None = None


@dataclass(frozen=True, slots=True)
class _AstGuardOutcome:
    proofs: tuple[StaticProof, ...]
    analysis_mode: str
    unknown_reason: str | None = None


@dataclass(frozen=True, slots=True)
class _AstControlFlowContext:
    tree: object
    source_bytes: bytes
    captures: dict[str, tuple[object, ...]]


def analyze_candidate(
    source: str,
    candidate: CandidateCase,
    *,
    function_contracts: tuple[FunctionContract, ...] = (),
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]] | None = None,
) -> StaticAnalysisResult:
    """Apply bounded local heuristics before escalating to agent review."""

    if not _is_trackable_symbol(candidate.symbol):
        return StaticAnalysisResult(
            state="unknown_static",
            observed_guards=(),
            origin_candidates=(candidate.expression,),
            origin_usage_modes=("direct_sink",),
            origin_return_slots=(1,),
            proofs=(),
        )

    lines = source.splitlines()
    prior_lines = lines[: max(0, candidate.line - 1)]
    origin_context = _find_last_assignment(prior_lines, candidate.symbol)
    origin_detail = _find_last_assignment_detail(prior_lines, candidate.symbol)
    origin = origin_context[0] if origin_context is not None else None
    proofs: list[StaticProof] = []
    current_module = detect_module_name(source)
    effective_transparent_return_wrappers = (
        dict(transparent_return_wrappers)
        if transparent_return_wrappers is not None
        else collect_transparent_return_wrappers((source,))
    )
    ast_guard_outcome = _analyze_guards_with_ast(source, candidate)
    analysis_mode = ast_guard_outcome.analysis_mode
    unknown_reason = ast_guard_outcome.unknown_reason
    current_scope_kind = _scope_kind_for_function_scope(candidate.function_scope)
    current_top_level_phase = _top_level_phase_for_candidate(source, candidate)

    if ast_guard_outcome.analysis_mode == "ast_primary":
        proofs.extend(ast_guard_outcome.proofs)
    else:
        if _has_active_positive_guard(prior_lines, candidate.symbol):
            proofs.append(_build_positive_guard_proof(candidate.symbol))
        if _has_early_exit_guard(prior_lines, candidate.symbol):
            proofs.append(_build_early_exit_guard_proof(candidate.symbol))
        if _has_active_assert(prior_lines, candidate.symbol):
            proofs.append(_build_assert_guard_proof(candidate.symbol))
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
        proofs.append(contract_guard)
    guarded_field_origin_proof = _guarded_field_origin_proof(
        prior_lines,
        origin_detail,
        subject=candidate.symbol,
    )
    if guarded_field_origin_proof is not None:
        proofs.append(guarded_field_origin_proof)
    return_contract_guard = _origin_return_contract_guard(
        prior_lines,
        origin_context,
        subject=candidate.symbol,
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
        proofs.append(return_contract_guard)
    if _has_defaulting_origin(origin):
        proofs.append(_build_defaulting_origin_proof(candidate.symbol, origin))

    deduped_proofs = _dedupe_proofs(tuple(proofs))
    observed_guards = tuple(proof.summary for proof in deduped_proofs)
    state = "safe_static" if deduped_proofs else "unknown_static"
    if deduped_proofs:
        unknown_reason = None
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
        proofs=deduped_proofs,
        analysis_mode=analysis_mode,
        unknown_reason=unknown_reason,
    )


def _analyze_guards_with_ast(source: str, candidate: CandidateCase) -> _AstGuardOutcome:
    context = _parse_control_flow_tree(source)
    if context is None:
        return _AstGuardOutcome(proofs=(), analysis_mode="legacy_only")

    target_node = _resolve_candidate_node(context.tree.root_node, candidate)
    if target_node is None:
        return _AstGuardOutcome(
            proofs=(),
            analysis_mode="ast_fallback_to_legacy",
            unknown_reason="unresolved_ast_node",
        )

    unknown_reason = _classify_ast_unknown_reason(source, context, target_node, candidate)
    if unknown_reason is not None:
        return _AstGuardOutcome(
            proofs=(),
            analysis_mode="ast_fallback_to_legacy",
            unknown_reason=unknown_reason,
        )

    proofs: list[StaticProof] = []
    positive_guard = _ast_positive_guard_proof(target_node, candidate.symbol, context.source_bytes)
    if positive_guard is not None:
        proofs.append(positive_guard)
    repeat_until_guard = _ast_repeat_until_guard_proof(
        target_node,
        candidate.symbol,
        context.source_bytes,
    )
    if repeat_until_guard is not None:
        proofs.append(repeat_until_guard)
    early_exit_guard = _ast_early_exit_guard_proof(target_node, candidate.symbol, context.source_bytes)
    if early_exit_guard is not None:
        proofs.append(early_exit_guard)
    assert_guard = _ast_assert_guard_proof(target_node, candidate.symbol, context.source_bytes)
    if assert_guard is not None:
        proofs.append(assert_guard)

    if proofs:
        return _AstGuardOutcome(
            proofs=_dedupe_proofs(tuple(proofs)),
            analysis_mode="ast_primary",
        )

    return _AstGuardOutcome(
        proofs=(),
        analysis_mode="ast_fallback_to_legacy",
    )


def _parse_control_flow_tree(source: str):
    language = _load_lua_language()
    if language is None:
        return None
    try:
        from tree_sitter import Parser, Query, QueryCursor
    except Exception:
        return None

    try:
        query = Query(language, _load_ast_control_flow_query_text())
        parser = Parser()
        parser.language = language
        source_bytes = source.encode("utf-8")
        tree = parser.parse(source_bytes)
        captures = {
            name: tuple(nodes)
            for name, nodes in QueryCursor(query).captures(tree.root_node).items()
        }
    except Exception:
        return None
    return _AstControlFlowContext(
        tree=tree,
        source_bytes=source_bytes,
        captures=captures,
    )


def _load_ast_control_flow_query_text() -> str:
    global _AST_CONTROL_FLOW_QUERY_TEXT
    if _AST_CONTROL_FLOW_QUERY_TEXT is None:
        _AST_CONTROL_FLOW_QUERY_TEXT = _AST_CONTROL_FLOW_QUERY_PATH.read_text(encoding="utf-8")
    return _AST_CONTROL_FLOW_QUERY_TEXT


def _resolve_candidate_node(root_node, candidate: CandidateCase):
    row = max(0, candidate.line - 1)
    start_column = max(0, candidate.column - 1)
    end_column = start_column + max(1, len(candidate.symbol))
    try:
        node = root_node.descendant_for_point_range((row, start_column), (row, end_column))
    except Exception:
        return None
    while node is not None and not node.is_named:
        node = node.parent
    return node


def _classify_ast_unknown_reason(
    source: str,
    context: _AstControlFlowContext,
    target_node,
    candidate: CandidateCase,
) -> str | None:
    for capture_name in ("while", "for"):
        if any(_node_contains(node, target_node) for node in context.captures.get(capture_name, ())):
            return "unsupported_control_flow"

    prefix = "\n".join(source.splitlines()[: max(0, candidate.line)])
    if "setmetatable(" in prefix or "__index" in prefix or "getmetatable(" in prefix:
        return "dynamic_metatable"

    if "[" in candidate.expression and not re.search(r"\[\s*(['\"])[^'\"]+\1\s*\]", candidate.expression):
        return "dynamic_index_expression"

    return None


def _ast_positive_guard_proof(target_node, symbol: str, source_bytes: bytes) -> StaticProof | None:
    ancestor = target_node
    while ancestor is not None:
        if ancestor.type in {"if_statement", "elseif_statement"}:
            consequence = ancestor.child_by_field_name("consequence")
            condition = ancestor.child_by_field_name("condition")
            if (
                consequence is not None
                and _node_contains(consequence, target_node)
                and _condition_is_positive_symbol_check(condition, symbol)
                and not _path_has_assignment_between(consequence, target_node, symbol, source_bytes)
            ):
                return _build_positive_guard_proof(symbol)
        ancestor = ancestor.parent
    return None


def _ast_repeat_until_guard_proof(target_node, symbol: str, source_bytes: bytes) -> StaticProof | None:
    if _find_preceding_repeat_until_guard(target_node, symbol, source_bytes):
        return _build_repeat_until_guard_proof(symbol)
    return None


def _ast_early_exit_guard_proof(target_node, symbol: str, source_bytes: bytes) -> StaticProof | None:
    if _find_preceding_guard_node(
        target_node,
        symbol,
        source_bytes,
        guard_kind="early_exit",
    ):
        return _build_early_exit_guard_proof(symbol)
    return None


def _ast_assert_guard_proof(target_node, symbol: str, source_bytes: bytes) -> StaticProof | None:
    if _find_preceding_guard_node(
        target_node,
        symbol,
        source_bytes,
        guard_kind="assert",
    ):
        return _build_assert_guard_proof(symbol)
    return None


def _find_preceding_guard_node(target_node, symbol: str, source_bytes: bytes, *, guard_kind: str) -> bool:
    current = target_node
    while current is not None and current.parent is not None:
        parent = current.parent
        for sibling in reversed(_preceding_named_siblings(parent, current)):
            if _subtree_assigns_symbol(sibling, symbol, source_bytes):
                return False
            if guard_kind == "early_exit" and _node_is_negative_guard_exit(sibling, symbol, source_bytes):
                return True
            if guard_kind == "assert" and _node_is_assert_guard(sibling, symbol, source_bytes):
                return True
        current = parent
    return False


def _find_preceding_repeat_until_guard(target_node, symbol: str, source_bytes: bytes) -> bool:
    current = target_node
    while current is not None and current.parent is not None:
        parent = current.parent
        for sibling in reversed(_preceding_named_siblings(parent, current)):
            if _node_is_repeat_until_guard(sibling, symbol, source_bytes):
                return True
            if _subtree_assigns_symbol(sibling, symbol, source_bytes):
                return False
        current = parent
    return False


def _preceding_named_siblings(parent, node) -> tuple[object, ...]:
    siblings: list[object] = []
    for child in parent.named_children:
        if child.start_byte >= node.start_byte:
            break
        siblings.append(child)
    return tuple(siblings)


def _subtree_assigns_symbol(node, symbol: str, source_bytes: bytes) -> bool:
    stack: list[tuple[object, bool]] = [(node, False)]
    while stack:
        current, nested_scope = stack.pop()
        if current.type == "variable_declaration":
            assignment = next(
                (child for child in current.named_children if child.type == "assignment_statement"),
                None,
            )
            if assignment is not None and not nested_scope and _assignment_node_targets_symbol(
                assignment,
                symbol,
                source_bytes,
            ):
                return True
            continue
        if current.type == "assignment_statement" and _assignment_node_targets_symbol(
            current,
            symbol,
            source_bytes,
        ):
            return True
        if current.type == "function_declaration":
            name = current.child_by_field_name("name")
            is_local_function = _is_local_function_declaration(current)
            if (
                name is not None
                and _node_text(source_bytes, name).strip() == symbol
                and (not nested_scope or not is_local_function)
            ):
                return True
            body = current.child_by_field_name("body")
            if body is not None:
                stack.append((body, True))
            continue
        if current.type in {
            "do_statement",
            "while_statement",
            "repeat_statement",
            "for_statement",
            "for_in_statement",
        }:
            for child in reversed(current.named_children):
                stack.append((child, True))
            continue
        for child in reversed(current.named_children):
            stack.append((child, nested_scope))
    return False


def _assignment_node_targets_symbol(node, symbol: str, source_bytes: bytes) -> bool:
    if not node.children:
        return False
    variable_list = node.children[0]
    if variable_list.type != "variable_list":
        return False
    return any(
        _same_symbol_reference(_node_text(source_bytes, child), symbol)
        for child in variable_list.named_children
    )


def _is_local_function_declaration(node) -> bool:
    return bool(node.children) and node.children[0].type == "local"


def _node_is_negative_guard_exit(node, symbol: str, source_bytes: bytes) -> bool:
    if node.type != "if_statement":
        return False
    if node.child_by_field_name("alternative") is not None:
        return False
    condition = node.child_by_field_name("condition")
    consequence = node.child_by_field_name("consequence")
    if not _condition_is_negative_symbol_check(condition, symbol):
        return False
    if consequence is None:
        return False
    return _block_guarantees_early_exit(consequence, source_bytes)


def _node_is_assert_guard(node, symbol: str, source_bytes: bytes) -> bool:
    if node.type != "function_call":
        return False
    name_node = node.children[0] if node.children else None
    arguments_node = next((child for child in node.children if child.type == "arguments"), None)
    if name_node is None or arguments_node is None:
        return False
    if _node_text(source_bytes, name_node).strip() != "assert":
        return False
    args = tuple(_node_text(source_bytes, child).strip() for child in arguments_node.named_children)
    return bool(args) and _same_symbol_reference(args[0], symbol)


def _node_is_repeat_until_guard(node, symbol: str, source_bytes: bytes) -> bool:
    if node.type != "repeat_statement":
        return False
    body = node.child_by_field_name("body")
    condition = node.child_by_field_name("condition")
    if body is None or condition is None:
        return False
    if not _condition_is_positive_symbol_check(condition, symbol):
        return False
    if _block_contains_nonlocal_break(body):
        return False
    return True


def _block_guarantees_early_exit(block_node, source_bytes: bytes) -> bool:
    statements = list(block_node.named_children)
    if not statements:
        return False
    terminal = statements[-1]
    if terminal.type == "return_statement":
        return True
    if terminal.type == "break_statement":
        return True
    if terminal.type == "function_call":
        return _node_text(source_bytes, terminal).strip().startswith("error(")
    return False


def _block_contains_nonlocal_break(block_node) -> bool:
    stack: list[tuple[object, bool]] = [(block_node, False)]
    while stack:
        current, nested_loop = stack.pop()
        if current.type == "break_statement" and not nested_loop:
            return True
        if current.type == "function_declaration":
            continue
        child_nested_loop = nested_loop or (
            current is not block_node and current.type in {"while_statement", "repeat_statement", "for_statement"}
        )
        for child in reversed(current.named_children):
            stack.append((child, child_nested_loop))
    return False


def _condition_is_positive_symbol_check(condition_node, symbol: str) -> bool:
    if condition_node is None:
        return False
    text = condition_node.text.decode("utf-8").strip()
    return _matches_positive_guard_text(text, symbol)


def _condition_is_negative_symbol_check(condition_node, symbol: str) -> bool:
    if condition_node is None:
        return False
    text = condition_node.text.decode("utf-8").strip()
    return _matches_negative_guard_text(text, symbol)


def _path_has_assignment_between(scope_node, target_node, symbol: str, source_bytes: bytes) -> bool:
    current = target_node
    while current is not None and current != scope_node:
        parent = current.parent
        if parent is None:
            break
        for sibling in reversed(_preceding_named_siblings(parent, current)):
            if _subtree_assigns_symbol(sibling, symbol, source_bytes):
                return True
        current = parent
    return False


def _node_contains(ancestor, node) -> bool:
    return ancestor.start_byte <= node.start_byte and node.end_byte <= ancestor.end_byte


def _node_text(source_bytes: bytes, node) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def _find_last_assignment(lines: list[str], symbol: str) -> tuple[str, str, int] | None:
    detail = _find_last_assignment_detail(lines, symbol)
    if detail is None:
        return None
    origin, usage_mode, return_slot, _ = detail
    return origin, usage_mode, return_slot


def _find_last_assignment_detail(
    lines: list[str],
    symbol: str,
) -> tuple[str, str, int, int] | None:
    line_paths, final_path = _scan_branch_paths(lines)

    for line_index in range(len(lines) - 1, -1, -1):
        line = lines[line_index]
        path = line_paths[line_index]
        if not _branch_path_is_prefix(path, final_path):
            continue
        assignment = _split_assignment_statement(line)
        if assignment is None:
            continue
        targets, values = assignment
        if not targets:
            continue

        matching_index = next(
            (
                index
                for index, target in enumerate(targets)
                if _same_symbol_reference(target, symbol)
            ),
            None,
        )
        if matching_index is None:
            continue
        if not values:
            continue

        usage_mode = "multi_assignment" if len(targets) > 1 else "single_assignment"
        if matching_index < len(values):
            return values[matching_index], usage_mode, 1, line_index
        if len(values) == 1:
            # A single function call can populate multiple targets in Lua.
            return values[0], "multi_assignment", matching_index + 1, line_index
    return None


def _split_assignment_statement(line: str) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    code = _strip_lua_comment(line).strip()
    if not code:
        return None
    if code.startswith(("function ", "local function ")):
        return None

    normalized = code
    if normalized.startswith("local "):
        normalized = normalized[len("local ") :].lstrip()
        if normalized.startswith("function "):
            return None

    split_index = _find_assignment_operator(normalized)
    if split_index is None:
        return None

    lhs = normalized[:split_index].strip()
    rhs = normalized[split_index + 1 :].strip()
    if not lhs or not rhs:
        return None

    targets = tuple(part.strip() for part in _split_top_level_values(lhs) if part.strip())
    values = tuple(part.strip() for part in _split_top_level_values(rhs) if part.strip())
    if not targets:
        return None
    return targets, values


def _find_assignment_operator(statement: str) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(statement):
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
        if depth != 0 or char != "=":
            continue

        previous = statement[index - 1] if index > 0 else ""
        following = statement[index + 1] if index + 1 < len(statement) else ""
        if previous in {"=", "~", "<", ">"} or following == "=":
            continue
        return index

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


def _build_positive_guard_proof(symbol: str) -> StaticProof:
    return StaticProof(
        kind="direct_guard",
        summary=f"if {symbol} then",
        subject=symbol,
        source_symbol=symbol,
        provenance=(f"an active positive branch requires `{symbol}` to be truthy",),
        depth=0,
    )


def _build_repeat_until_guard_proof(symbol: str) -> StaticProof:
    return StaticProof(
        kind="loop_exit_guard",
        summary=f"repeat ... until {symbol}",
        subject=symbol,
        source_symbol=symbol,
        provenance=(f"the loop only reaches the sink after `{symbol}` becomes truthy",),
        depth=0,
    )


def _build_early_exit_guard_proof(symbol: str) -> StaticProof:
    return StaticProof(
        kind="early_exit_guard",
        summary=f"if not {symbol} then return",
        subject=symbol,
        source_symbol=symbol,
        provenance=(f"the nil branch for `{symbol}` exits before the sink",),
        depth=0,
    )


def _build_assert_guard_proof(symbol: str) -> StaticProof:
    return StaticProof(
        kind="assert_guard",
        summary=f"assert({symbol})",
        subject=symbol,
        source_symbol=symbol,
        provenance=(f"`assert` aborts execution if `{symbol}` is nil",),
        depth=0,
    )


def _build_defaulting_origin_proof(symbol: str, origin: str | None) -> StaticProof:
    return StaticProof(
        kind="local_defaulting",
        summary=f"{symbol} = {symbol} or ...",
        subject=symbol,
        source_symbol=symbol,
        source_call=origin,
        provenance=(
            f"assignment `{origin or ''}` uses Lua's non-nil defaulting idiom",
        ),
        depth=0,
    )


def _guarded_field_origin_proof(
    lines: list[str],
    origin_detail: tuple[str, str, int, int] | None,
    *,
    subject: str,
) -> StaticProof | None:
    if origin_detail is None:
        return None
    if not _IDENTIFIER_RE.match(subject):
        return None

    origin, _usage_mode, _return_slot, assignment_line_index = origin_detail
    if extract_access_path(origin) is None:
        return None

    assignment_prefix = lines[:assignment_line_index]
    supporting: list[StaticProof] = []
    if _has_active_positive_guard(assignment_prefix, origin):
        supporting.append(_build_positive_guard_proof(origin))
    if _has_early_exit_guard(assignment_prefix, origin):
        supporting.append(_build_early_exit_guard_proof(origin))
    if _has_active_assert(assignment_prefix, origin):
        supporting.append(_build_assert_guard_proof(origin))

    if not supporting:
        return None

    supporting_summaries = tuple(proof.summary for proof in _dedupe_proofs(tuple(supporting)))
    return StaticProof(
        kind="guarded_field_origin",
        summary=f"{subject} inherits non-nil from {origin}",
        subject=subject,
        source_symbol=origin,
        supporting_summaries=supporting_summaries,
        provenance=(f"`{subject}` is assigned from guarded field path `{origin}`",),
        depth=1,
    )


def _dedupe_proofs(proofs: tuple[StaticProof, ...]) -> tuple[StaticProof, ...]:
    unique: list[StaticProof] = []
    seen: set[tuple[object, ...]] = set()
    for proof in proofs:
        key = (
            proof.kind,
            proof.summary,
            proof.subject,
            proof.source_symbol,
            proof.source_call,
            proof.source_function,
            proof.supporting_summaries,
            proof.provenance,
            proof.depth,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(proof)
    return tuple(unique)


def _contract_matching_symbol_index(
    contract: FunctionContract,
    args: tuple[str, ...],
    symbol: str,
) -> int | None:
    for index in contract.ensures_non_nil_args:
        if 1 <= index <= len(args) and args[index - 1].strip() == symbol:
            return index
    return None


def _build_guarded_arg_supporting_proofs(
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
) -> tuple[StaticProof, ...] | None:
    proofs: list[StaticProof] = []
    for index in required_positions:
        if index < 1 or index > len(args):
            return None
        symbol = args[index - 1].strip()
        if not _IDENTIFIER_RE.match(symbol):
            return None
        proof = _find_symbol_proof(
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
        if proof is None:
            return None
        proofs.append(proof)
    return tuple(proofs)


def _find_symbol_proof(
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
    allow_terminal_origin: bool = False,
) -> StaticProof | None:
    if not _IDENTIFIER_RE.match(symbol):
        return None
    if _has_active_positive_guard(lines, symbol):
        return _build_positive_guard_proof(symbol)
    if _has_early_exit_guard(lines, symbol):
        return _build_early_exit_guard_proof(symbol)
    if _has_active_assert(lines, symbol):
        return _build_assert_guard_proof(symbol)
    contract_proof = _active_contract_guard(
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
    if contract_proof is not None:
        return contract_proof

    if remaining_chain_depth <= 0 and not allow_terminal_origin:
        return None

    origin_context = _find_last_assignment(lines, symbol)
    if origin_context is None:
        return None
    return _build_origin_return_proof(
        lines,
        symbol,
        origin_context,
        return_contracts=return_contracts,
        function_contracts=function_contracts,
        current_module=current_module,
        current_function_scope=current_function_scope,
        current_top_level_phase=current_top_level_phase,
        current_scope_kind=current_scope_kind,
        sink_rule_id=sink_rule_id,
        sink_name=sink_name,
        transparent_return_wrappers=transparent_return_wrappers,
        remaining_chain_depth=max(0, remaining_chain_depth),
    )


def _build_origin_return_proof(
    lines: list[str],
    subject: str,
    origin_context: tuple[str, str, int],
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
    consume_chain_depth: bool = True,
) -> StaticProof | None:
    origin, usage_mode, return_slot = origin_context
    if origin.strip() == subject:
        return None

    parsed_call = _parse_simple_call(_strip_lua_comment(origin).strip())
    if parsed_call is None:
        if _has_defaulting_origin(origin):
            return _build_defaulting_origin_proof(subject, origin)
        return None

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
            supporting_proofs = _build_guarded_arg_supporting_proofs(
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
                remaining_chain_depth=max(
                    0,
                    remaining_chain_depth - (1 if consume_chain_depth else 0),
                ),
            )
            if supporting_proofs is not None:
                supporting_summaries = tuple(proof.summary for proof in supporting_proofs)
                provenance = (
                    f"`{origin}` feeds the sink through `{resolved_name}` return slot {return_slot}",
                ) + tuple(
                    line
                    for proof in supporting_proofs
                    for line in _proof_provenance_lines(proof)
                )
                return StaticProof(
                    kind=(
                        "chained_return_contract"
                        if any(proof.depth > 0 for proof in supporting_proofs)
                        else "return_contract"
                    ),
                    summary=f"{resolved_name}(...) returns non-nil",
                    subject=subject,
                    source_symbol=(
                        args[required_args[0] - 1].strip()
                        if required_args and 1 <= required_args[0] <= len(args)
                        else None
                    ),
                    source_call=origin,
                    source_function=resolved_name,
                    supporting_summaries=supporting_summaries,
                    provenance=provenance,
                    depth=0 if not supporting_proofs else 1 + max(proof.depth for proof in supporting_proofs),
                )

    wrapper_name = _resolve_contract_name(
        raw_name,
        current_module=current_module,
        known_contract_names=frozenset(transparent_return_wrappers),
    )
    return _build_wrapper_return_proof(
        wrapper_name,
        args,
        subject=subject,
        return_slot=return_slot,
        source_call=origin,
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


def _build_wrapper_return_proof(
    resolved_name: str,
    args: tuple[str, ...],
    *,
    subject: str,
    return_slot: int,
    source_call: str,
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
) -> StaticProof | None:
    passthrough_index = _transparent_wrapper_arg_for_slot(
        transparent_return_wrappers.get(resolved_name),
        return_slot,
    )
    if passthrough_index is None:
        return None
    if passthrough_index == 0:
        return StaticProof(
            kind="wrapper_defaulting",
            summary=f"{resolved_name}(...) preserves or defaults to non-nil",
            subject=subject,
            source_call=source_call,
            source_function=resolved_name,
            provenance=(
                f"`{resolved_name}` return slot {return_slot} falls back to a built-in non-nil value",
            ),
            depth=0,
        )
    if passthrough_index < 1 or passthrough_index > len(args):
        return None

    passthrough_value = args[passthrough_index - 1].strip()
    if not passthrough_value or passthrough_value == resolved_name:
        return None
    if _is_non_nil_literal(passthrough_value):
        return StaticProof(
            kind="wrapper_defaulting",
            summary=f"{resolved_name}(...) preserves or defaults to non-nil",
            subject=subject,
            source_call=source_call,
            source_function=resolved_name,
            provenance=(
                f"`{resolved_name}` receives non-nil literal `{passthrough_value}` as fallback input",
            ),
            depth=0,
        )
    if not _IDENTIFIER_RE.match(passthrough_value):
        if _has_defaulting_origin(passthrough_value):
            return StaticProof(
                kind="wrapper_defaulting",
                summary=f"{resolved_name}(...) preserves or defaults to non-nil",
                subject=subject,
                source_call=source_call,
                source_function=resolved_name,
                source_symbol=passthrough_value,
                provenance=(
                    f"`{resolved_name}` forwards `{passthrough_value}`, which already uses defaulting",
                ),
                depth=0,
            )
        return None

    next_depth = remaining_chain_depth - 1
    if next_depth < 0:
        return None
    nested_proof = _find_symbol_proof(
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
        remaining_chain_depth=next_depth,
        allow_terminal_origin=next_depth == 0,
    )
    if nested_proof is None:
        return None

    return StaticProof(
        kind="wrapper_passthrough",
        summary=f"{resolved_name}(...) preserves or defaults to non-nil",
        subject=subject,
        source_symbol=passthrough_value,
        source_call=source_call,
        source_function=resolved_name,
        supporting_summaries=(nested_proof.summary,),
        provenance=(
            f"`{resolved_name}` return slot {return_slot} forwards argument {passthrough_index} `{passthrough_value}`",
        ) + tuple(_proof_provenance_lines(nested_proof)),
        depth=1 + nested_proof.depth,
    )


def _proof_provenance_lines(proof: StaticProof) -> tuple[str, ...]:
    if proof.provenance:
        return proof.provenance
    return (proof.summary,)


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
) -> StaticProof | None:
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
    active_guard: StaticProof | None = None
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
        matching_index = _contract_matching_symbol_index(contract, args, symbol)
        if matching_index is not None:
            active_guard = StaticProof(
                kind="contract_guard",
                summary=f"{resolved_name}({symbol})",
                subject=symbol,
                source_symbol=symbol,
                source_call=stripped,
                source_function=resolved_name,
                provenance=(
                    f"`{resolved_name}` guarantees argument {matching_index} is non-nil",
                ),
                depth=0,
            )

    return active_guard


def _origin_return_contract_guard(
    lines: list[str],
    origin_context: tuple[str, str, int] | None,
    *,
    subject: str,
    function_contracts: tuple[FunctionContract, ...],
    current_module: str | None,
    current_function_scope: str,
    current_top_level_phase: str | None,
    current_scope_kind: str | None,
    sink_rule_id: str,
    sink_name: str,
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]],
) -> StaticProof | None:
    if origin_context is None:
        return None
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
    return _build_origin_return_proof(
        lines,
        subject,
        origin_context,
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
        consume_chain_depth=False,
    )


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


def _is_trackable_symbol(symbol: str) -> bool:
    return _IDENTIFIER_RE.match(symbol) is not None or extract_access_path(symbol) is not None


def _same_symbol_reference(left: str, right: str) -> bool:
    left_value = left.strip()
    right_value = right.strip()
    if left_value == right_value:
        return True
    left_path = extract_access_path(left_value)
    right_path = extract_access_path(right_value)
    return left_path is not None and left_path == right_path


def _matches_positive_guard_text(condition_text: str, symbol: str) -> bool:
    condition = condition_text.strip()
    if _same_symbol_reference(condition, symbol):
        return True
    if condition.endswith(" ~= nil"):
        return _same_symbol_reference(condition[: -len(" ~= nil")], symbol)
    return False


def _matches_negative_guard_text(condition_text: str, symbol: str) -> bool:
    condition = condition_text.strip()
    if condition.startswith("not "):
        return _same_symbol_reference(condition[len("not ") :], symbol)
    if condition.endswith(" == nil"):
        return _same_symbol_reference(condition[: -len(" == nil")], symbol)
    return False


def _is_if_open_for_symbol(stripped_line: str, symbol: str) -> bool:
    if not _is_if_open(stripped_line):
        return False
    condition = stripped_line[len("if ") : -len(" then")].strip()
    return _matches_positive_guard_text(condition, symbol)


def _is_if_open(stripped_line: str) -> bool:
    return stripped_line.startswith("if ") and stripped_line.endswith(" then")


def _is_elseif_line(stripped_line: str) -> bool:
    return stripped_line.startswith("elseif ") and stripped_line.endswith(" then")


def _is_elseif_for_symbol(stripped_line: str, symbol: str) -> bool:
    condition = stripped_line[len("elseif ") : -len(" then")].strip()
    return _matches_positive_guard_text(condition, symbol)


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
    if not _is_if_open(stripped_line):
        return False
    condition = stripped_line[len("if ") : -len(" then")].strip()
    return _matches_negative_guard_text(condition, symbol)


def _is_early_exit_statement(stripped_line: str) -> bool:
    return (
        stripped_line == "return"
        or stripped_line.startswith("return ")
        or stripped_line.startswith("error(")
        or stripped_line.startswith("assert(false")
    )


def _assigns_symbol(stripped_line: str, symbol: str) -> bool:
    assignment = _split_assignment_statement(stripped_line)
    if assignment is None:
        return False
    names, _ = assignment
    return any(_same_symbol_reference(name, symbol) for name in names)


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
