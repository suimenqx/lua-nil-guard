from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path

from .models import CandidateCase, DomainKnowledgeConfig, DomainKnowledgeRule, SinkRule


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
_LEXICAL_BINARY_TOKEN_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.:]*\([^()]*\)"
    r"|[A-Za-z_][A-Za-z0-9_.]*"
    r"|[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?|\.\d+)"
    r"|'(?:\\.|[^'])*'"
    r'|"(?:\\.|[^"])*"'
)
_ROOT_SYMBOL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")
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


@dataclass(frozen=True, slots=True)
class _CompiledDomainSkipRule:
    id: str
    pattern: re.Pattern[str]
    applies_to_sinks: tuple[str, ...]


def collect_candidates(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
    *,
    domain_knowledge: DomainKnowledgeConfig | None = None,
) -> tuple[CandidateCase, ...]:
    """Collect nil-sensitive call sites using deterministic lightweight parsing."""

    if not sink_rules:
        return ()

    domain_skip_rules = _compile_domain_skip_rules(domain_knowledge)
    path_text = str(file_path)
    candidates: list[CandidateCase] = []
    seen_keys: set[tuple[int, int, str, int]] = set()
    source_lines = source.splitlines()
    line_offsets = _line_start_offsets(source_lines)

    for sink_rule in sink_rules:
        candidate_source = "lexical_fallback"
        if sink_rule.kind == "function_arg":
            argument_events = _collect_function_arg_events_lexical(
                source_lines,
                line_offsets,
                sink_rule.qualified_name,
                sink_rule.arg_index,
            )
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
                    domain_skip_rules=domain_skip_rules,
                )
            continue

        if sink_rule.kind != "receiver":
            if sink_rule.kind == "binary_operand":
                if sink_rule.arg_index not in {1, 2}:
                    continue
                operator = _binary_operator_for_sink(sink_rule.qualified_name)
                if operator is None:
                    continue
                operand_events = _collect_binary_operand_events_lexical(
                    source_lines,
                    line_offsets,
                    operator=operator,
                    arg_index=sink_rule.arg_index,
                )
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
                        domain_skip_rules=domain_skip_rules,
                    )
                continue
            if sink_rule.kind != "unary_operand":
                continue

            operand_events = _collect_length_operand_events_lexical(source_lines, line_offsets)
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
                    domain_skip_rules=domain_skip_rules,
                )
            continue

        receiver_events = _collect_receiver_events_lexical(source_lines, line_offsets)
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
                domain_skip_rules=domain_skip_rules,
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
    domain_skip_rules: tuple[_CompiledDomainSkipRule, ...],
) -> None:
    expression = expression.strip()
    if not expression or _is_obviously_non_nil_literal(expression):
        return
    if _is_domain_skipped_expression(
        expression,
        sink_rule=sink_rule,
        domain_skip_rules=domain_skip_rules,
    ):
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


def _compile_domain_skip_rules(
    domain_knowledge: DomainKnowledgeConfig | None,
) -> tuple[_CompiledDomainSkipRule, ...]:
    if domain_knowledge is None:
        return ()
    compiled: list[_CompiledDomainSkipRule] = []
    for rule in domain_knowledge.rules:
        compiled_rule = _compile_domain_skip_rule(rule)
        if compiled_rule is not None:
            compiled.append(compiled_rule)
    return tuple(compiled)


def _compile_domain_skip_rule(rule: DomainKnowledgeRule) -> _CompiledDomainSkipRule | None:
    if rule.action != "skip_candidate":
        return None
    if not rule.assumed_non_nil:
        return None
    return _CompiledDomainSkipRule(
        id=rule.id,
        pattern=re.compile(rule.symbol_regex),
        applies_to_sinks=rule.applies_to_sinks,
    )


def _is_domain_skipped_expression(
    expression: str,
    *,
    sink_rule: SinkRule,
    domain_skip_rules: tuple[_CompiledDomainSkipRule, ...],
) -> bool:
    if not domain_skip_rules:
        return False

    sink_identifiers = {sink_rule.id, sink_rule.qualified_name}
    for rule in domain_skip_rules:
        if rule.applies_to_sinks and not sink_identifiers.intersection(rule.applies_to_sinks):
            continue
        for token in _domain_match_tokens(expression):
            if rule.pattern.fullmatch(token):
                return True
    return False


def _domain_match_tokens(expression: str) -> tuple[str, ...]:
    stripped = expression.strip()
    tokens: list[str] = []
    if stripped:
        tokens.append(stripped)
    root = _root_symbol(stripped)
    if root is not None and root not in tokens:
        tokens.append(root)
    return tuple(tokens)


def _root_symbol(expression: str) -> str | None:
    match = _ROOT_SYMBOL_RE.match(expression)
    if match is None:
        return None
    return match.group(1)


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
        masked_code = _mask_lua_strings(code)
        if target not in masked_code:
            continue
        search_from = 0
        while True:
            call_start = masked_code.find(target, search_from)
            if call_start < 0:
                break
            call_end = call_start + len(target)
            before_ok = call_start == 0 or not _is_identifier_char(masked_code[call_start - 1])
            after_ok = call_end >= len(masked_code) or not _is_identifier_char(masked_code[call_end])
            if not before_ok or not after_ok:
                search_from = call_end
                continue
            open_paren = call_end
            while open_paren < len(masked_code) and masked_code[open_paren].isspace():
                open_paren += 1
            if open_paren >= len(masked_code) or masked_code[open_paren] != "(":
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


def _collect_binary_operand_events_lexical(
    source_lines: list[str],
    line_offsets: tuple[int, ...],
    *,
    operator: str,
    arg_index: int,
) -> tuple[tuple[str, int, int, int], ...]:
    events: list[tuple[str, int, int, int]] = []
    for idx, raw_line in enumerate(source_lines, start=1):
        code = _strip_lua_comment(raw_line)
        masked_code = _mask_lua_strings(code)
        for operator_index in _operator_positions(masked_code, operator):
            if arg_index == 1:
                token = _extract_left_binary_token(code, operator_index)
            else:
                token = _extract_right_binary_token(
                    code,
                    operator_index + len(operator),
                )
            if token is None:
                continue
            expression, column = token
            offset = line_offsets[idx - 1] + (column - 1)
            events.append((expression, idx, column, offset))
    return tuple(events)


def _collect_length_operand_events_lexical(
    source_lines: list[str],
    line_offsets: tuple[int, ...],
) -> tuple[tuple[str, int, int, int], ...]:
    events: list[tuple[str, int, int, int]] = []
    for idx, raw_line in enumerate(source_lines, start=1):
        code = _strip_lua_comment(raw_line)
        masked_code = _mask_lua_strings(code)
        for match in _LEXICAL_LENGTH_RE.finditer(masked_code):
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
        masked_code = _mask_lua_strings(code)
        for match in _LEXICAL_RECEIVER_ACCESS_RE.finditer(masked_code):
            receiver = match.group(1).strip()
            delimiter = masked_code[match.end() - 1]
            if delimiter == "." and _is_dot_index_call_callee(masked_code, match.end()):
                continue
            if delimiter == "[" and _is_bracket_index_call_callee(masked_code, match.end()):
                continue
            column = match.start(1) + 1
            offset = line_offsets[idx - 1] + match.start(1)
            events.append((receiver, idx, column, offset))
    return tuple(events)


def _mask_lua_strings(code: str) -> str:
    chars = list(code)
    quote: str | None = None
    escape = False
    for index, char in enumerate(chars):
        if quote is None:
            if char in {"'", '"'}:
                quote = char
                chars[index] = " "
            continue
        chars[index] = " "
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == quote:
            quote = None
    return "".join(chars)


def _operator_positions(code: str, operator: str) -> tuple[int, ...]:
    positions: list[int] = []
    search_from = 0
    while True:
        index = code.find(operator, search_from)
        if index < 0:
            break
        if _is_valid_operator_occurrence(code, index, operator):
            positions.append(index)
        search_from = index + 1
    return tuple(positions)


def _is_valid_operator_occurrence(code: str, index: int, operator: str) -> bool:
    if operator == "<" and index + 1 < len(code) and code[index + 1] == "=":
        return False
    if operator == ">" and index + 1 < len(code) and code[index + 1] == "=":
        return False
    if operator == "..":
        prev_char = code[index - 1] if index > 0 else ""
        next_char = code[index + 2] if index + 2 < len(code) else ""
        if prev_char == "." or next_char == ".":
            return False
    return True


def _extract_left_binary_token(
    code: str,
    operator_index: int,
) -> tuple[str, int] | None:
    prefix_code = code[:operator_index]
    match = re.search(
        rf"(?P<token>{_LEXICAL_BINARY_TOKEN_RE.pattern})\s*$",
        prefix_code,
    )
    if match is None:
        return None
    token_start = match.start("token")
    token_end = match.end("token")
    token_text = prefix_code[token_start:token_end].strip()
    if not token_text:
        return None
    return token_text, token_start + 1


def _extract_right_binary_token(
    code: str,
    start_index: int,
) -> tuple[str, int] | None:
    suffix_code = code[start_index:]
    match = re.match(
        rf"\s*(?P<token>{_LEXICAL_BINARY_TOKEN_RE.pattern})",
        suffix_code,
    )
    if match is None:
        return None
    token_start = start_index + match.start("token")
    token_end = start_index + match.end("token")
    token_text = code[token_start:token_end].strip()
    if not token_text:
        return None
    return token_text, token_start + 1


def _is_dot_index_call_callee(masked_code: str, cursor: int) -> bool:
    while cursor < len(masked_code) and masked_code[cursor].isspace():
        cursor += 1
    name_start = cursor
    while cursor < len(masked_code) and _is_identifier_char(masked_code[cursor]):
        cursor += 1
    if cursor == name_start:
        return False
    while cursor < len(masked_code) and masked_code[cursor].isspace():
        cursor += 1
    return cursor < len(masked_code) and masked_code[cursor] in {"(", ":"}


def _is_bracket_index_call_callee(masked_code: str, cursor: int) -> bool:
    depth = 1
    quote: str | None = None
    escape = False
    while cursor < len(masked_code):
        char = masked_code[cursor]
        if quote is not None:
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
            cursor += 1
            continue
        if char == "[":
            depth += 1
            cursor += 1
            continue
        if char == "]":
            depth -= 1
            cursor += 1
            if depth == 0:
                break
            continue
        cursor += 1
    while cursor < len(masked_code) and masked_code[cursor].isspace():
        cursor += 1
    return cursor < len(masked_code) and masked_code[cursor] in {"(", ":"}


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
