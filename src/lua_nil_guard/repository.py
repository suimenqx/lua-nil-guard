from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path


IGNORED_DIR_NAMES = {".git", "__pycache__", ".pytest_cache"}
SUPPORTED_LUA_SOURCE_ENCODINGS = ("utf-8", "utf-8-sig", "gb18030")


class SourceEncodingError(ValueError):
    """Raised when a Lua source file cannot be decoded as UTF-8."""


@dataclass(frozen=True, slots=True)
class LuaSourceEncodingRecord:
    """Describe the detected encoding state for one Lua source file."""

    path: Path
    encoding: str | None
    convertible: bool
    needs_normalization: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class LuaSourceNormalizationResult:
    """Describe the outcome of one UTF-8 normalization attempt."""

    path: Path
    previous_encoding: str | None
    action: str
    reason: str | None = None


def discover_lua_files(root: str | Path) -> tuple[Path, ...]:
    """Recursively discover Lua source files under a repository root."""

    root_path = Path(root)
    files: list[Path] = []
    for path in root_path.rglob("*.lua"):
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    files.sort()
    return tuple(files)


def read_lua_source_text(path: str | Path) -> str:
    """Read a Lua source file as UTF-8 and raise a pathful error on decode failure."""

    file_path = Path(path)
    record, decoded_text = inspect_lua_source_encoding(file_path)
    if record.encoding == "utf-8":
        return decoded_text or ""

    if record.convertible:
        raise SourceEncodingError(
            "Lua source file is not valid UTF-8: "
            f"{file_path} (detected {record.encoding}). "
            "Run `lua-nil-guard normalize-encoding --write <repository>` "
            "or re-save this file as UTF-8 before running lua-nil-guard."
        )

    raise SourceEncodingError(
        f"Lua source file is not valid UTF-8: {file_path} ({record.reason}). "
        "Re-save this file as UTF-8 before running lua-nil-guard."
    )


def inspect_lua_source_encoding(path: str | Path) -> tuple[LuaSourceEncodingRecord, str | None]:
    """Inspect one Lua file and return a stable encoding verdict."""

    file_path = Path(path)
    raw_bytes = file_path.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        try:
            decoded = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            decoded = None
        else:
            if decoded.encode("utf-8-sig") == raw_bytes:
                return (
                    LuaSourceEncodingRecord(
                        path=file_path,
                        encoding="utf-8-sig",
                        convertible=True,
                        needs_normalization=True,
                    ),
                    decoded,
                )

    for encoding in SUPPORTED_LUA_SOURCE_ENCODINGS:
        if encoding == "utf-8-sig":
            continue
        try:
            decoded = raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
        try:
            if decoded.encode(encoding) != raw_bytes:
                continue
        except UnicodeEncodeError:
            continue
        return (
            LuaSourceEncodingRecord(
                path=file_path,
                encoding=encoding,
                convertible=True,
                needs_normalization=(encoding != "utf-8"),
            ),
            decoded,
        )

    return (
        LuaSourceEncodingRecord(
            path=file_path,
            encoding=None,
            convertible=False,
            needs_normalization=False,
            reason="could not decode with utf-8, utf-8-sig, or gb18030",
        ),
        None,
    )


def compute_file_fingerprint(path: str | Path) -> str:
    """Compute a SHA-256 content hash for a file."""

    file_path = Path(path)
    content = file_path.read_bytes()
    return hashlib.sha256(content).hexdigest()


# ---------------------------------------------------------------------------
# Dependency tracking schema
# ---------------------------------------------------------------------------

_FINGERPRINT_SCHEMA = """\
CREATE TABLE IF NOT EXISTS file_fingerprints (
    file_path TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    last_analyzed_run_id INTEGER
);
"""

_FACT_DEPS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS fact_dependencies (
    fact_id TEXT NOT NULL,
    fact_type TEXT NOT NULL,
    depends_on_file TEXT NOT NULL,
    depends_on_function TEXT,
    run_id INTEGER NOT NULL,
    PRIMARY KEY (fact_id, depends_on_file)
);
CREATE INDEX IF NOT EXISTS idx_fact_deps_file ON fact_dependencies(depends_on_file);
CREATE INDEX IF NOT EXISTS idx_fact_deps_run ON fact_dependencies(run_id);
"""


def ensure_dependency_schema(conn: sqlite3.Connection) -> None:
    """Create file_fingerprints and fact_dependencies tables if absent."""

    conn.executescript(_FINGERPRINT_SCHEMA)
    conn.executescript(_FACT_DEPS_SCHEMA)


def upsert_file_fingerprint(
    conn: sqlite3.Connection,
    file_path: str,
    content_hash: str,
    mtime_ns: int,
    run_id: int | None = None,
) -> None:
    """Insert or update a file fingerprint record."""

    conn.execute(
        "INSERT OR REPLACE INTO file_fingerprints (file_path, content_hash, mtime_ns, last_analyzed_run_id) "
        "VALUES (?, ?, ?, ?)",
        (file_path, content_hash, mtime_ns, run_id),
    )


def insert_fact_dependency(
    conn: sqlite3.Connection,
    fact_id: str,
    fact_type: str,
    depends_on_file: str,
    run_id: int,
    depends_on_function: str | None = None,
) -> None:
    """Record a single fact dependency edge."""

    conn.execute(
        "INSERT OR IGNORE INTO fact_dependencies "
        "(fact_id, fact_type, depends_on_file, depends_on_function, run_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (fact_id, fact_type, depends_on_file, depends_on_function, run_id),
    )


def audit_lua_source_encodings(root: str | Path) -> tuple[LuaSourceEncodingRecord, ...]:
    """Inspect all Lua files under a root directory for UTF-8 compliance."""

    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"Repository root not found: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Repository root is not a directory: {root_path}")

    records: list[LuaSourceEncodingRecord] = []
    for file_path in discover_lua_files(root_path):
        record, _ = inspect_lua_source_encoding(file_path)
        records.append(record)
    return tuple(records)


def normalize_lua_source_encodings(
    root: str | Path,
    *,
    write: bool = False,
) -> tuple[LuaSourceNormalizationResult, ...]:
    """Convert supported non-UTF-8 Lua files to UTF-8, or preview the changes."""

    results: list[LuaSourceNormalizationResult] = []
    for record in audit_lua_source_encodings(root):
        if record.encoding == "utf-8":
            results.append(
                LuaSourceNormalizationResult(
                    path=record.path,
                    previous_encoding="utf-8",
                    action="already_utf8",
                )
            )
            continue
        if not record.convertible or record.encoding is None:
            results.append(
                LuaSourceNormalizationResult(
                    path=record.path,
                    previous_encoding=None,
                    action="skipped",
                    reason=record.reason,
                )
            )
            continue

        _, decoded = inspect_lua_source_encoding(record.path)
        if decoded is None:
            results.append(
                LuaSourceNormalizationResult(
                    path=record.path,
                    previous_encoding=record.encoding,
                    action="skipped",
                    reason=record.reason or "unable to decode file",
                )
            )
            continue
        if write:
            record.path.write_bytes(decoded.encode("utf-8"))
            action = "converted"
        else:
            action = "would_convert"
        results.append(
            LuaSourceNormalizationResult(
                path=record.path,
                previous_encoding=record.encoding,
                action=action,
            )
        )
    return tuple(results)
