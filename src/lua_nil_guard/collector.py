from __future__ import annotations

import re
from pathlib import Path

from .models import CandidateCase, SinkRule
from .parser_backend import (
    ParserBackendUnavailableError,
    SourceAstIndex,
    build_source_ast_index,
)


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FUNCTION_NAME_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_.:]*)\s*\(",
)
_ANONYMOUS_FUNCTION_RE = re.compile(r"(?:=\s*|return\s+)function\b")
_MODULE_DECLARATION_RE = re.compile(
    r"^\s*module\s*\(\s*(['\"])([^'\"]+)\1(?:\s*,\s*package\.seeall)?\s*\)\s*$",
)
_NUMBER_LITERAL_RE = re.compile(r"^-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_LEXICAL_RECEIVER_ACCESS_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*(?:\.|\[)"
)
_LEXICAL_LENGTH_RE = re.compile(
    r"#\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
)
_LEXICAL_SIMPLE_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*|[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?|\.\d+)")
_BINARY_OPERATOR_BY_NAME = {
    "concat": "..",
    "compare.lt": "<",
    "compare.lte": "<=",
    "compare.gt": ">",
    "compare.gte": ">=",
    "arithmetic.add": "+",
    "arithmetic.sub": "-",
    "arithmetic.mul": "*",
    "arithmetic.div": "/",
    "arithmetic.mod": "%",
    "arithmetic.pow": "^",
}


def collect_candidates(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
) -> tuple[CandidateCase, ...]:
    """Collect nil-sensitive call sites using deterministic lightweight parsing."""

    path_text = str(file_path)
    candidates: list[CandidateCase] = []
    seen_keys: set[tuple[int, int, str, int]] = set()
    source_lines = source.splitlines()
    line_offsets = _line_start_offsets(source_lines)
    ast_index = _load_ast_index(source)
    use_lexical_fallback = ast_index is None or ast_index.has_error
    ast_call_sites_by_name: dict[tuple[str, int], tuple[tuple[str, int, int, int], ...]] = {}
    if ast_index is not None:
        ast_call_sites_by_name = _group_call_sites(ast_index)

    for sink_rule in sink_rules:
        if sink_rule.kind == "function_arg":
            if not use_lexical_fallback and ast_index is not None:
                argument_events = ast_call_sites_by_name.get(
                    (sink_rule.qualified_name, sink_rule.arg_index),
                    (),
                )
            else:
                argument_events = _collect_function_arg_events_lexical(
                    source_lines,
                    line_offsets,
                    sink_rule.qualified_name,
                    sink_rule.arg_index,
                )
            candidate_source = "lexical_fallback" if use_lexical_fallback else "ast_exact"
            for expression, line, column, offset in argument_events:
                _append_candidate(
                    candidates,
                    seen_keys,
                    path_text=path_text,
                    sink_rule=sink_rule,
                    expression=expression,
                    line=line,
                    column=column,
                    source=source,
                    offset=offset,
                    candidate_source=candidate_source,
                )
            continue

        if sink_rule.kind != "receiver":
            if sink_rule.kind == "binary_operand":
                if sink_rule.arg_index not in {1, 2}:
                    continue
                operator = _binary_operator_for_sink(sink_rule.qualified_name)
                if operator is None:
                    continue
                if not use_lexical_fallback and ast_index is not None:
                    operand_events = _collect_binary_operand_events_ast(
                        ast_index,
                        operator=operator,
                        arg_index=sink_rule.arg_index,
                    )
                else:
                    operand_events = _collect_binary_operand_events_lexical(
                        source_lines,
                        line_offsets,
                        operator=operator,
                        arg_index=sink_rule.arg_index,
                    )
                candidate_source = "lexical_fallback" if use_lexical_fallback else "ast_exact"
                for expression, line, column, operand_offset in operand_events:
                    _append_candidate(
                        candidates,
                        seen_keys,
                        path_text=path_text,
                        sink_rule=sink_rule,
                        expression=expression,
                        line=line,
                        column=column,
                        source=source,
                        offset=operand_offset,
                        sink_name_override=sink_rule.id,
                        candidate_source=candidate_source,
                    )
                continue
            if sink_rule.kind != "unary_operand":
                continue

            if not use_lexical_fallback and ast_index is not None:
                operand_events = tuple(
                    (operand.operand, operand.line, operand.column, operand.offset)
                    for operand in ast_index.length_operands
                )
            else:
                operand_events = _collect_length_operand_events_lexical(source_lines, line_offsets)
            candidate_source = "lexical_fallback" if use_lexical_fallback else "ast_exact"
            for expression, line, column, offset in operand_events:
                _append_candidate(
                    candidates,
                    seen_keys,
                    path_text=path_text,
                    sink_rule=sink_rule,
                    expression=expression,
                    line=line,
                    column=column,
                    source=source,
                    offset=offset,
                    candidate_source=candidate_source,
                )
            continue

        if not use_lexical_fallback and ast_index is not None:
            receiver_events = tuple(
                (access.receiver, access.line, access.column, access.offset)
                for access in ast_index.receiver_accesses
            )
        else:
            receiver_events = _collect_receiver_events_lexical(source_lines, line_offsets)
        candidate_source = "lexical_fallback" if use_lexical_fallback else "ast_exact"
        for expression, line, column, offset in receiver_events:
            if _is_module_package_seeall_receiver(expression, line, source_lines):
                continue
            _append_candidate(
                candidates,
                seen_keys,
                path_text=path_text,
                sink_rule=sink_rule,
                expression=expression,
                line=line,
                column=column,
                source=source,
                offset=offset,
                candidate_source=candidate_source,
            )

    candidates.sort(key=lambda item: (item.line, item.column, item.sink_rule_id))
    return tuple(candidates)


def top_level_phase_for_prefix(prefix: str) -> str | None:
    """Return the current top-level phase before a given source prefix."""

    _, top_level_phase = _scan_enclosing_context(prefix)
    return top_level_phase


def _find_enclosing_function(prefix: str) -> str:
    function_scope, _ = _scan_enclosing_context(prefix)
    return function_scope


def _scan_enclosing_context(prefix: str) -> tuple[str, str | None]:
    scope_stack: list[str] = []
    block_stack: list[str] = []
    module_name: str | None = None
    saw_top_level_named_function = False
    for line in prefix.splitlines():
        code = _strip_lua_comment(line)
        stripped = code.strip()
        if not stripped:
            continue
        module_match = _MODULE_DECLARATION_RE.match(code.strip())
        if module_match is not None:
            module_name = module_match.group(2)
            continue

        match = _FUNCTION_NAME_RE.match(code)
        if match:
            if not scope_stack:
                saw_top_level_named_function = True
            scope_stack.append(_qualify_function_name(match.group(1), module_name))
            block_stack.append("function")
            continue

        if _ANONYMOUS_FUNCTION_RE.search(stripped):
            block_stack.append("anon_function")
            continue
        if stripped == "repeat":
            block_stack.append("repeat")
            continue
        if _opens_non_function_block(stripped):
            block_stack.append("block")
            continue
        if stripped == "end":
            if not block_stack:
                continue
            closing = block_stack.pop()
            if closing == "function" and scope_stack:
                scope_stack.pop()
            continue
        if stripped.startswith("until "):
            if block_stack and block_stack[-1] == "repeat":
                block_stack.pop()

    if scope_stack:
        return scope_stack[-1], None
    if saw_top_level_named_function:
        return "main", "post_definitions"
    return "main", "init"


def _qualify_function_name(defined_name: str, module_name: str | None) -> str:
    normalized = defined_name.strip().replace(":", ".")
    if "." in normalized:
        return normalized
    if module_name:
        return f"{module_name}.{normalized}"
    return normalized


def _strip_lua_comment(line: str) -> str:
    comment_index = line.find("--")
    if comment_index == -1:
        return line
    return line[:comment_index]


def _opens_non_function_block(stripped_line: str) -> bool:
    return (
        (stripped_line.startswith("if ") and stripped_line.endswith(" then"))
        or (stripped_line.startswith("elseif ") and stripped_line.endswith(" then"))
        or (stripped_line.startswith("for ") and stripped_line.endswith(" do"))
        or (stripped_line.startswith("while ") and stripped_line.endswith(" do"))
        or stripped_line == "do"
    )


def _is_obviously_non_nil_literal(expression: str) -> bool:
    stripped = expression.strip()
    if stripped == "nil":
        return False
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return True
    if stripped in {"true", "false"}:
        return True
    if _NUMBER_LITERAL_RE.match(stripped):
        return True
    return stripped.startswith("{") and stripped.endswith("}")


def _binary_operator_for_sink(qualified_name: str) -> str | None:
    if qualified_name in _BINARY_OPERATOR_BY_NAME:
        return _BINARY_OPERATOR_BY_NAME[qualified_name]
    if qualified_name in _BINARY_OPERATOR_BY_NAME.values():
        return qualified_name
    return None


def _is_module_package_seeall_receiver(
    expression: str,
    line: int,
    source_lines: list[str],
) -> bool:
    if expression != "package":
        return False
    if line < 1 or line > len(source_lines):
        return False
    return _MODULE_DECLARATION_RE.match(source_lines[line - 1].strip()) is not None


def _append_candidate(
    candidates: list[CandidateCase],
    seen_keys: set[tuple[int, int, str, int]],
    *,
    path_text: str,
    sink_rule: SinkRule,
    expression: str,
    line: int,
    column: int,
    source: str,
    offset: int,
    sink_name_override: str | None = None,
    candidate_source: str,
) -> None:
    expression = expression.strip()
    if not expression or _is_obviously_non_nil_literal(expression):
        return
    dedupe_key = (line, column, sink_rule.id, sink_rule.arg_index)
    if dedupe_key in seen_keys:
        return
    function_scope, _ = _scan_enclosing_context(source[:offset])
    symbol = expression if _IDENTIFIER_RE.match(expression) else expression
    case_id = f"{path_text}:{line}:{column}:{sink_rule.id}"
    candidates.append(
        CandidateCase(
            case_id=case_id,
            file=path_text,
            line=line,
            column=column,
            sink_rule_id=sink_rule.id,
            sink_name=sink_name_override or sink_rule.qualified_name,
            arg_index=sink_rule.arg_index,
            expression=expression,
            symbol=symbol,
            function_scope=function_scope,
            static_state="unknown_static",
            candidate_source=candidate_source,
        )
    )
    seen_keys.add(dedupe_key)


def _load_ast_index(source: str) -> SourceAstIndex | None:
    try:
        return build_source_ast_index(source)
    except ParserBackendUnavailableError:
        return None


def _group_call_sites(
    ast_index: SourceAstIndex,
) -> dict[tuple[str, int], tuple[tuple[str, int, int, int], ...]]:
    grouped: dict[tuple[str, int], list[tuple[str, int, int, int]]] = {}
    for call_site in ast_index.call_sites:
        for arg_index, arg in enumerate(call_site.args, start=1):
            grouped.setdefault(
                (call_site.callee, arg_index),
                [],
            ).append((arg.strip(), call_site.line, call_site.column, call_site.offset))
    return {
        key: tuple(sorted(values, key=lambda item: (item[1], item[2])))
        for key, values in grouped.items()
    }


def _collect_function_arg_events_lexical(
    source_lines: list[str],
    line_offsets: tuple[int, ...],
    qualified_name: str,
    arg_index: int,
) -> tuple[tuple[str, int, int, int], ...]:
    if arg_index < 1:
        return ()
    target = qualified_name.strip()
    if not target:
        return ()
    events: list[tuple[str, int, int, int]] = []
    for idx, raw_line in enumerate(source_lines, start=1):
        code = _strip_lua_comment(raw_line)
        if target not in code:
            continue
        search_from = 0
        while True:
            call_start = code.find(target, search_from)
            if call_start < 0:
                break
            call_end = call_start + len(target)
            before_ok = call_start == 0 or not _is_identifier_char(code[call_start - 1])
            after_ok = call_end >= len(code) or not _is_identifier_char(code[call_end])
            if not before_ok or not after_ok:
                search_from = call_end
                continue
            open_paren = call_end
            while open_paren < len(code) and code[open_paren].isspace():
                open_paren += 1
            if open_paren >= len(code) or code[open_paren] != "(":
                search_from = call_end
                continue
            raw_args_text, parsed_to = _extract_parenthesized_content(code, open_paren)
            if raw_args_text is None:
                search_from = open_paren + 1
                continue
            raw_args = _split_simple_args(raw_args_text)
            if len(raw_args) >= arg_index:
                expression = raw_args[arg_index - 1].strip()
                if expression:
                    relative_arg_pos = raw_args_text.find(expression)
                    arg_start = (
                        open_paren + 1 + relative_arg_pos
                        if relative_arg_pos >= 0
                        else open_paren + 1
                    )
                    column = arg_start + 1
                    offset = line_offsets[idx - 1] + arg_start
                    events.append((expression, idx, column, offset))
            search_from = parsed_to
    return tuple(events)


def _collect_binary_operand_events_ast(
    ast_index: SourceAstIndex,
    *,
    operator: str,
    arg_index: int,
) -> tuple[tuple[str, int, int, int], ...]:
    events: list[tuple[str, int, int, int]] = []
    for operand in ast_index.binary_operands:
        if operand.operator != operator:
            continue
        if arg_index == 1:
            events.append((operand.left, operand.left_line, operand.left_column, operand.left_offset))
        else:
            events.append((operand.right, operand.right_line, operand.right_column, operand.right_offset))
    return tuple(events)


def _collect_binary_operand_events_lexical(
    source_lines: list[str],
    line_offsets: tuple[int, ...],
    *,
    operator: str,
    arg_index: int,
) -> tuple[tuple[str, int, int, int], ...]:
    escaped_operator = re.escape(operator)
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_])(?P<left>{_LEXICAL_SIMPLE_TOKEN_RE.pattern})\s*{escaped_operator}\s*(?P<right>{_LEXICAL_SIMPLE_TOKEN_RE.pattern})"
    )
    events: list[tuple[str, int, int, int]] = []
    target_key = "left" if arg_index == 1 else "right"
    for idx, raw_line in enumerate(source_lines, start=1):
        code = _strip_lua_comment(raw_line)
        for match in pattern.finditer(code):
            expression = match.group(target_key).strip()
            column = match.start(target_key) + 1
            offset = line_offsets[idx - 1] + match.start(target_key)
            events.append((expression, idx, column, offset))
    return tuple(events)


def _collect_length_operand_events_lexical(
    source_lines: list[str],
    line_offsets: tuple[int, ...],
) -> tuple[tuple[str, int, int, int], ...]:
    events: list[tuple[str, int, int, int]] = []
    for idx, raw_line in enumerate(source_lines, start=1):
        code = _strip_lua_comment(raw_line)
        for match in _LEXICAL_LENGTH_RE.finditer(code):
            expression = match.group(1).strip()
            column = match.start(1) + 1
            offset = line_offsets[idx - 1] + match.start(1)
            events.append((expression, idx, column, offset))
    return tuple(events)


def _collect_receiver_events_lexical(
    source_lines: list[str],
    line_offsets: tuple[int, ...],
) -> tuple[tuple[str, int, int, int], ...]:
    events: list[tuple[str, int, int, int]] = []
    for idx, raw_line in enumerate(source_lines, start=1):
        code = _strip_lua_comment(raw_line)
        for match in _LEXICAL_RECEIVER_ACCESS_RE.finditer(code):
            receiver = match.group(1).strip()
            end_index = match.end()
            while end_index < len(code) and code[end_index].isspace():
                end_index += 1
            if end_index < len(code) and code[end_index] in {"(", ":"}:
                continue
            column = match.start(1) + 1
            offset = line_offsets[idx - 1] + match.start(1)
            events.append((receiver, idx, column, offset))
    return tuple(events)


def _line_start_offsets(lines: list[str]) -> tuple[int, ...]:
    offsets: list[int] = []
    current = 0
    for line in lines:
        offsets.append(current)
        current += len(line) + 1
    return tuple(offsets)


def _split_simple_args(raw_args: str) -> tuple[str, ...]:
    if not raw_args.strip():
        return ()
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escape = False
    for char in raw_args:
        if quote is not None:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == "(":
            depth += 1
            current.append(char)
            continue
        if char == ")":
            if depth > 0:
                depth -= 1
                current.append(char)
                continue
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return tuple(part for part in parts if part)


def _extract_parenthesized_content(source: str, open_paren: int) -> tuple[str | None, int]:
    if open_paren >= len(source) or source[open_paren] != "(":
        return None, open_paren + 1
    depth = 1
    quote: str | None = None
    escape = False
    cursor = open_paren + 1
    content: list[str] = []
    while cursor < len(source):
        char = source[cursor]
        if quote is not None:
            content.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            cursor += 1
            continue
        if char in {"'", '"'}:
            quote = char
            content.append(char)
            cursor += 1
            continue
        if char == "(":
            depth += 1
            content.append(char)
            cursor += 1
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return "".join(content), cursor + 1
            content.append(char)
            cursor += 1
            continue
        content.append(char)
        cursor += 1
    return None, cursor


def _is_identifier_char(char: str) -> bool:
    return char.isalnum() or char == "_"
