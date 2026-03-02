from __future__ import annotations

import re
from pathlib import Path

from .models import CandidateCase, SinkRule
from .parser_backend import collect_call_sites, collect_receiver_accesses


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FUNCTION_NAME_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
)


def collect_candidates(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
) -> tuple[CandidateCase, ...]:
    """Collect nil-sensitive call sites using deterministic lightweight parsing."""

    path_text = str(file_path)
    candidates: list[CandidateCase] = []

    for sink_rule in sink_rules:
        if sink_rule.kind == "function_arg":
            for call_site in collect_call_sites(source, sink_rule.qualified_name):
                if sink_rule.arg_index < 1 or len(call_site.args) < sink_rule.arg_index:
                    continue

                expression = call_site.args[sink_rule.arg_index - 1].strip()
                line, column = call_site.line, call_site.column
                function_scope = _find_enclosing_function(source[: call_site.offset])
                symbol = expression if _IDENTIFIER_RE.match(expression) else expression
                case_id = f"{path_text}:{line}:{column}:{sink_rule.id}"

                candidates.append(
                    CandidateCase(
                        case_id=case_id,
                        file=path_text,
                        line=line,
                        column=column,
                        sink_rule_id=sink_rule.id,
                        sink_name=sink_rule.qualified_name,
                        arg_index=sink_rule.arg_index,
                        expression=expression,
                        symbol=symbol,
                        function_scope=function_scope,
                        static_state="unknown_static",
                    )
                )
            continue

        if sink_rule.kind != "receiver":
            continue

        for access in collect_receiver_accesses(source):
            expression = access.receiver
            line, column = access.line, access.column
            function_scope = _find_enclosing_function(source[: access.offset])
            symbol = expression if _IDENTIFIER_RE.match(expression) else expression
            case_id = f"{path_text}:{line}:{column}:{sink_rule.id}"

            candidates.append(
                CandidateCase(
                    case_id=case_id,
                    file=path_text,
                    line=line,
                    column=column,
                    sink_rule_id=sink_rule.id,
                    sink_name=sink_rule.qualified_name,
                    arg_index=sink_rule.arg_index,
                    expression=expression,
                    symbol=symbol,
                    function_scope=function_scope,
                    static_state="unknown_static",
                )
            )

    candidates.sort(key=lambda item: (item.line, item.column, item.sink_rule_id))
    return tuple(candidates)


def _find_enclosing_function(prefix: str) -> str:
    function_name = "main"
    for line in prefix.splitlines():
        match = _FUNCTION_NAME_RE.match(line)
        if match:
            function_name = match.group(1)
    return function_name
