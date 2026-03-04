from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
import sqlite3

from .models import (
    MacroAuditResult,
    MacroCacheStatus,
    MacroFact,
    MacroIndex,
    MacroUnresolvedLine,
    PreprocessorConfig,
)


_ASSIGNMENT_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*(.+?)\s*$"
)
_NUMBER_LITERAL_RE = re.compile(r"^-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_IDENT_OR_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_MAX_ALIAS_DEPTH = 8
_MACRO_CACHE_SCHEMA_VERSION = 1
_MACRO_CACHE_DIRNAME = ".lua-nil-guard-cache"
_MACRO_CACHE_FILENAME = "preprocessor-macro-cache.sqlite3"


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
    return _macro_index_from_audit(audit)


def macro_cache_path(root: str | Path) -> Path:
    """Return the repository-local compiled macro cache path."""

    root_path = Path(root)
    return root_path / _MACRO_CACHE_DIRNAME / _MACRO_CACHE_FILENAME


def inspect_macro_cache(
    root: str | Path,
    preprocessor_files: tuple[Path, ...],
) -> MacroCacheStatus:
    """Inspect compiled macro cache freshness without rebuilding it."""

    root_path = Path(root)
    cache_path = macro_cache_path(root_path)
    configured_files = _configured_file_labels(root_path, preprocessor_files)
    if not preprocessor_files:
        return MacroCacheStatus(
            path=str(cache_path),
            state="disabled",
            reason="no preprocessor files configured",
            configured_files=configured_files,
            file_count=0,
            parser_version=_MACRO_CACHE_SCHEMA_VERSION,
        )
    if not cache_path.is_file():
        return MacroCacheStatus(
            path=str(cache_path),
            state="missing",
            reason="compiled macro cache not found",
            configured_files=configured_files,
            file_count=len(configured_files),
            parser_version=_MACRO_CACHE_SCHEMA_VERSION,
        )
    try:
        connection = sqlite3.connect(cache_path)
    except sqlite3.Error as exc:
        return MacroCacheStatus(
            path=str(cache_path),
            state="invalid",
            reason=f"failed to open cache: {exc}",
            configured_files=configured_files,
            file_count=len(configured_files),
            parser_version=_MACRO_CACHE_SCHEMA_VERSION,
        )
    try:
        valid, reason, fact_count, unresolved_count = _validate_cache_connection(
            connection,
            root_path=root_path,
            preprocessor_files=preprocessor_files,
        )
        state = "fresh" if valid else "stale"
        return MacroCacheStatus(
            path=str(cache_path),
            state=state,
            reason=reason,
            configured_files=configured_files,
            file_count=len(configured_files),
            fact_count=fact_count,
            unresolved_count=unresolved_count,
            parser_version=_MACRO_CACHE_SCHEMA_VERSION,
        )
    finally:
        connection.close()


def build_macro_cache(
    root: str | Path,
    preprocessor_files: tuple[Path, ...],
    *,
    source_loader,
) -> tuple[MacroIndex, MacroCacheStatus]:
    """Build and persist compiled macro cache for the configured files."""

    root_path = Path(root)
    cache_path = macro_cache_path(root_path)
    configured_files = _configured_file_labels(root_path, preprocessor_files)
    if not preprocessor_files:
        return (
            MacroIndex(),
            MacroCacheStatus(
                path=str(cache_path),
                state="disabled",
                reason="no preprocessor files configured",
                configured_files=configured_files,
                file_count=0,
                parser_version=_MACRO_CACHE_SCHEMA_VERSION,
            ),
        )

    audit = build_macro_audit(root_path, preprocessor_files, source_loader=source_loader)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(cache_path)
    try:
        _write_cache(
            connection,
            root_path=root_path,
            preprocessor_files=preprocessor_files,
            audit=audit,
        )
    finally:
        connection.close()

    return (
        _macro_index_from_audit(audit),
        MacroCacheStatus(
            path=str(cache_path),
            state="rebuilt",
            reason="compiled macro cache rebuilt",
            configured_files=configured_files,
            file_count=len(configured_files),
            fact_count=len(audit.facts),
            unresolved_count=len(audit.unresolved_lines),
            parser_version=_MACRO_CACHE_SCHEMA_VERSION,
        ),
    )


def ensure_macro_index(
    root: str | Path,
    preprocessor_files: tuple[Path, ...],
    *,
    source_loader,
) -> tuple[MacroIndex, MacroCacheStatus]:
    """Load macro facts from cache when valid, otherwise rebuild them."""

    status = inspect_macro_cache(root, preprocessor_files)
    if status.state == "fresh":
        root_path = Path(root)
        cache_path = macro_cache_path(root_path)
        connection = sqlite3.connect(cache_path)
        return (
            MacroIndex(
                cache_db_path=str(cache_path),
                cache_connection=connection,
            ),
            status,
        )
    return build_macro_cache(root, preprocessor_files, source_loader=source_loader)


def load_macro_audit_from_cache(
    root: str | Path,
    macro_index: MacroIndex | None,
    *,
    files: tuple[Path, ...] = (),
) -> MacroAuditResult | None:
    """Materialize a full audit from a cache-backed macro index when needed."""

    if macro_index is None or macro_index.cache_connection is None:
        return None
    connection = macro_index.cache_connection
    facts = tuple(_fact_from_row(row) for row in connection.execute(_FACTS_SELECT_ALL_SQL))
    unresolved_lines = tuple(
        MacroUnresolvedLine(
            file=row[0],
            line=int(row[1]),
            content=row[2],
            reason=row[3],
        )
        for row in connection.execute(
            "SELECT file, line, content, reason FROM unresolved ORDER BY ordinal"
        )
    )
    file_labels = tuple(str(path) for path in files)
    return MacroAuditResult(
        files=file_labels,
        facts=facts,
        unresolved_lines=unresolved_lines,
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
    if not macro_index.fact_by_key and macro_index.facts:
        macro_index.fact_by_key.update(_build_fact_map(macro_index.facts))
    cached = macro_index.fact_by_key.get(key)
    if cached is not None:
        return cached
    if key in macro_index.missing_keys:
        return None
    if macro_index.cache_connection is not None:
        row = macro_index.cache_connection.execute(_FACTS_SELECT_ONE_SQL, (key,)).fetchone()
        if row is None:
            macro_index.missing_keys.add(key)
            return None
        fact = _fact_from_row(row)
        macro_index.fact_by_key[key] = fact
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


_FACTS_SELECT_ALL_SQL = """
SELECT key, kind, value, provably_non_nil, file, line, resolved_kind, resolved_value, alias_target
FROM facts
ORDER BY ordinal
"""
_FACTS_SELECT_ONE_SQL = """
SELECT key, kind, value, provably_non_nil, file, line, resolved_kind, resolved_value, alias_target
FROM facts
WHERE key = ?
ORDER BY ordinal
LIMIT 1
"""


def _macro_index_from_audit(audit: MacroAuditResult) -> MacroIndex:
    return MacroIndex(
        facts=audit.facts,
        unresolved_lines=audit.unresolved_lines,
        fact_by_key=_build_fact_map(audit.facts),
    )


def _build_fact_map(facts: tuple[MacroFact, ...]) -> dict[str, MacroFact]:
    mapping: dict[str, MacroFact] = {}
    for fact in facts:
        mapping.setdefault(fact.key, fact)
    return mapping


def _configured_file_labels(root: Path, preprocessor_files: tuple[Path, ...]) -> tuple[str, ...]:
    labels: list[str] = []
    for file_path in preprocessor_files:
        if file_path.is_absolute() and file_path.is_relative_to(root):
            labels.append(file_path.relative_to(root).as_posix())
        else:
            labels.append(str(file_path))
    return tuple(labels)


def _cache_signature(root_path: Path, preprocessor_files: tuple[Path, ...]) -> str:
    return json.dumps(_configured_file_labels(root_path, preprocessor_files), separators=(",", ":"))


def _ensure_cache_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS facts (
            ordinal INTEGER PRIMARY KEY,
            key TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT,
            provably_non_nil INTEGER NOT NULL,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            resolved_kind TEXT,
            resolved_value TEXT,
            alias_target TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_macro_facts_key ON facts(key);
        CREATE TABLE IF NOT EXISTS unresolved (
            ordinal INTEGER PRIMARY KEY,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            content TEXT NOT NULL,
            reason TEXT NOT NULL
        );
        """
    )


def _write_cache(
    connection: sqlite3.Connection,
    *,
    root_path: Path,
    preprocessor_files: tuple[Path, ...],
    audit: MacroAuditResult,
) -> None:
    _ensure_cache_schema(connection)
    connection.execute("DELETE FROM meta")
    connection.execute("DELETE FROM files")
    connection.execute("DELETE FROM facts")
    connection.execute("DELETE FROM unresolved")
    connection.executemany(
        "INSERT INTO meta(key, value) VALUES(?, ?)",
        (
            ("schema_version", str(_MACRO_CACHE_SCHEMA_VERSION)),
            ("config_signature", _cache_signature(root_path, preprocessor_files)),
        ),
    )
    connection.executemany(
        "INSERT INTO files(path, size, mtime_ns) VALUES(?, ?, ?)",
        tuple(
            (
                relative_path,
                int(file_path.stat().st_size),
                int(file_path.stat().st_mtime_ns),
            )
            for relative_path, file_path in zip(
                _configured_file_labels(root_path, preprocessor_files),
                preprocessor_files,
                strict=True,
            )
        ),
    )
    connection.executemany(
        """
        INSERT INTO facts(
            ordinal, key, kind, value, provably_non_nil, file, line,
            resolved_kind, resolved_value, alias_target
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(
            (
                ordinal,
                fact.key,
                fact.kind,
                fact.value,
                1 if fact.provably_non_nil else 0,
                fact.file,
                fact.line,
                fact.resolved_kind,
                fact.resolved_value,
                fact.alias_target,
            )
            for ordinal, fact in enumerate(audit.facts, start=1)
        ),
    )
    connection.executemany(
        "INSERT INTO unresolved(ordinal, file, line, content, reason) VALUES(?, ?, ?, ?, ?)",
        tuple(
            (
                ordinal,
                item.file,
                item.line,
                item.content,
                item.reason,
            )
            for ordinal, item in enumerate(audit.unresolved_lines, start=1)
        ),
    )
    connection.commit()


def _validate_cache_connection(
    connection: sqlite3.Connection,
    *,
    root_path: Path,
    preprocessor_files: tuple[Path, ...],
) -> tuple[bool, str, int, int]:
    try:
        meta = dict(connection.execute("SELECT key, value FROM meta"))
    except sqlite3.Error as exc:
        return False, f"failed to read cache metadata: {exc}", 0, 0
    schema_version = meta.get("schema_version")
    if schema_version != str(_MACRO_CACHE_SCHEMA_VERSION):
        return False, "cache schema version mismatch", 0, 0
    if meta.get("config_signature") != _cache_signature(root_path, preprocessor_files):
        return False, "preprocessor file set changed", 0, 0
    try:
        cached_files = {
            row[0]: (int(row[1]), int(row[2]))
            for row in connection.execute("SELECT path, size, mtime_ns FROM files")
        }
    except sqlite3.Error as exc:
        return False, f"failed to read cache file metadata: {exc}", 0, 0
    expected_files = _configured_file_labels(root_path, preprocessor_files)
    if set(cached_files) != set(expected_files):
        return False, "cached file list does not match current preprocessor files", 0, 0
    for relative_path, file_path in zip(expected_files, preprocessor_files, strict=True):
        try:
            stat = file_path.stat()
        except OSError as exc:
            return False, f"failed to stat {file_path}: {exc}", 0, 0
        cached = cached_files.get(relative_path)
        if cached is None:
            return False, f"missing cache metadata for {relative_path}", 0, 0
        if cached != (int(stat.st_size), int(stat.st_mtime_ns)):
            return False, f"preprocessor source changed: {relative_path}", 0, 0
    fact_count = int(connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0])
    unresolved_count = int(connection.execute("SELECT COUNT(*) FROM unresolved").fetchone()[0])
    return True, "compiled macro cache is fresh", fact_count, unresolved_count


def _fact_from_row(row: tuple[object, ...]) -> MacroFact:
    return MacroFact(
        key=str(row[0]),
        kind=str(row[1]),
        value=row[2] if row[2] is None else str(row[2]),
        provably_non_nil=bool(row[3]),
        file=str(row[4]),
        line=int(row[5]),
        resolved_kind=row[6] if row[6] is None else str(row[6]),
        resolved_value=row[7] if row[7] is None else str(row[7]),
        alias_target=row[8] if row[8] is None else str(row[8]),
    )
