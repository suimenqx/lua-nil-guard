from __future__ import annotations

from pathlib import Path, PurePosixPath
import re

from .models import MacroAuditResult, MacroFact, MacroIndex, MacroUnresolvedLine, PreprocessorConfig


_ASSIGNMENT_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*(.+?)\s*$"
)
_NUMBER_LITERAL_RE = re.compile(r"^-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_IDENT_OR_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_MAX_ALIAS_DEPTH = 8


def split_preprocessor_files(
    root: str | Path,
    lua_files: tuple[Path, ...],
    config: PreprocessorConfig,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Split discovered Lua files into review targets and preprocessor inputs."""

    root_path = Path(root)
    explicit = {item.replace("\\", "/") for item in config.preprocessor_files}
    globs = tuple(item.replace("\\", "/") for item in config.preprocessor_globs)
    review_files: list[Path] = []
    preprocessor_files: list[Path] = []

    for file_path in lua_files:
        relative = file_path.relative_to(root_path).as_posix()
        if relative in explicit or any(PurePosixPath(relative).match(pattern) for pattern in globs):
            preprocessor_files.append(file_path)
        else:
            review_files.append(file_path)

    return tuple(review_files), tuple(preprocessor_files)


def build_macro_audit(
    root: str | Path,
    preprocessor_files: tuple[Path, ...],
    *,
    source_loader,
) -> MacroAuditResult:
    """Parse all configured preprocessor files into an operator-facing audit result."""

    root_path = Path(root)
    facts: list[MacroFact] = []
    unresolved: list[MacroUnresolvedLine] = []
    files: list[str] = []
    for file_path in preprocessor_files:
        files.append(str(file_path))
        source = source_loader(file_path)
        parsed_facts, unresolved_lines = parse_macro_file(
            file_path,
            source,
            root=root_path,
        )
        facts.extend(parsed_facts)
        unresolved.extend(unresolved_lines)

    resolved_facts = resolve_macro_facts(tuple(facts))
    return MacroAuditResult(
        files=tuple(files),
        facts=resolved_facts,
        unresolved_lines=tuple(unresolved),
    )


def build_macro_index(
    root: str | Path,
    preprocessor_files: tuple[Path, ...],
    *,
    source_loader,
) -> MacroIndex:
    """Build a resolved macro index from configured preprocessor files."""

    audit = build_macro_audit(root, preprocessor_files, source_loader=source_loader)
    return MacroIndex(
        facts=audit.facts,
        unresolved_lines=audit.unresolved_lines,
    )


def parse_macro_file(
    file_path: str | Path,
    source: str,
    *,
    root: str | Path | None = None,
) -> tuple[tuple[MacroFact, ...], tuple[MacroUnresolvedLine, ...]]:
    """Parse one preprocessor dictionary file using a bounded line parser."""

    file_path = Path(file_path)
    root_path = Path(root) if root is not None else None
    display_path = (
        str(file_path.relative_to(root_path))
        if root_path is not None and file_path.is_absolute() and file_path.is_relative_to(root_path)
        else str(file_path)
    )
    facts: list[MacroFact] = []
    unresolved: list[MacroUnresolvedLine] = []

    for line_no, raw_line in enumerate(source.splitlines(), start=1):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        match = _ASSIGNMENT_RE.match(line)
        if match is None:
            unresolved.append(
                MacroUnresolvedLine(
                    file=display_path,
                    line=line_no,
                    content=raw_line,
                    reason="unsupported_assignment_syntax",
                )
            )
            continue

        key = match.group(1)
        rhs = match.group(2).strip()
        parsed = _parse_macro_value(rhs)
        if parsed is None:
            unresolved.append(
                MacroUnresolvedLine(
                    file=display_path,
                    line=line_no,
                    content=raw_line,
                    reason="unsupported_value_syntax",
                )
            )
            continue

        kind, value, alias_target = parsed
        resolved_kind = kind if kind != "alias" else None
        resolved_value = value if kind != "alias" else None
        facts.append(
            MacroFact(
                key=key,
                kind=kind,
                value=value,
                provably_non_nil=kind != "alias",
                file=display_path,
                line=line_no,
                resolved_kind=resolved_kind,
                resolved_value=resolved_value,
                alias_target=alias_target,
            )
        )

    return tuple(facts), tuple(unresolved)


def resolve_macro_facts(facts: tuple[MacroFact, ...]) -> tuple[MacroFact, ...]:
    """Resolve simple aliases while staying bounded and deterministic."""

    fact_by_key = {fact.key: fact for fact in facts}
    resolved: list[MacroFact] = []
    for fact in facts:
        resolved_kind, resolved_value, provably_non_nil = _resolve_fact_value(
            fact,
            fact_by_key,
            trail=(),
            depth=0,
        )
        resolved.append(
            MacroFact(
                key=fact.key,
                kind=fact.kind,
                value=fact.value,
                provably_non_nil=provably_non_nil,
                file=fact.file,
                line=fact.line,
                resolved_kind=resolved_kind,
                resolved_value=resolved_value,
                alias_target=fact.alias_target,
            )
        )
    return tuple(resolved)


def lookup_macro_fact(macro_index: MacroIndex | None, key: str) -> MacroFact | None:
    """Return the resolved macro fact for a normalized key, if present."""

    if macro_index is None:
        return None
    for fact in macro_index.facts:
        if fact.key == key:
            return fact
    return None


def _resolve_fact_value(
    fact: MacroFact,
    fact_by_key: dict[str, MacroFact],
    *,
    trail: tuple[str, ...],
    depth: int,
) -> tuple[str | None, str | None, bool]:
    if fact.kind != "alias":
        return fact.kind, fact.value, True
    if fact.alias_target is None:
        return None, None, False
    if depth >= _MAX_ALIAS_DEPTH:
        return None, None, False
    if fact.alias_target in trail:
        return None, None, False
    target = fact_by_key.get(fact.alias_target)
    if target is None:
        return None, None, False
    resolved_kind, resolved_value, provably_non_nil = _resolve_fact_value(
        target,
        fact_by_key,
        trail=trail + (fact.key,),
        depth=depth + 1,
    )
    if not provably_non_nil:
        return None, None, False
    return resolved_kind, resolved_value, True


def _parse_macro_value(value: str) -> tuple[str, str | None, str | None] | None:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return "string_literal", stripped[1:-1], None
    if _NUMBER_LITERAL_RE.match(stripped):
        return "number_literal", stripped, None
    if stripped in {"true", "false"}:
        return "boolean_literal", stripped, None
    if stripped == "{}":
        return "empty_table", stripped, None
    if _IDENT_OR_PATH_RE.match(stripped):
        return "alias", None, stripped
    return None


def _strip_comment(line: str) -> str:
    comment_index = line.find("--")
    if comment_index == -1:
        return line
    return line[:comment_index]
