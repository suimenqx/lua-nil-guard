from __future__ import annotations

from collections import Counter
import difflib
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import sqlite3
from pathlib import Path
from typing import Callable

from .adjudication import attach_autofix_patch
from .agent_driver_models import AgentProviderSpec
from .agent_backend import AdjudicationBackend, CliAgentBackend, HeuristicAdjudicationBackend
from .collector import collect_candidates, top_level_phase_for_prefix
from .config_loader import (
    default_preprocessor_config,
    load_confidence_policy,
    load_function_contracts,
    load_preprocessor_config,
    load_sink_rules,
)
from .knowledge import (
    KnowledgeBase,
    contract_applies_in_function_scope,
    contract_applies_in_module,
    contract_applies_to_call,
    contract_applies_to_scope_kind,
    contract_applies_to_top_level_phase,
    contract_applies_to_sink,
    derive_facts_from_contracts,
    derive_facts_from_summaries,
    facts_for_subject,
)
from .models import (
    AdjudicationRecord,
    AutofixPatch,
    BenchmarkCacheComparison,
    BenchmarkCaseResult,
    BenchmarkSummary,
    CandidateAssessment,
    EvidencePacket,
    FunctionContract,
    ImprovementAnalytics,
    ImprovementProposal,
    MacroAuditResult,
    MacroCacheStatus,
    RepositorySnapshot,
    SinkRule,
    Verdict,
    with_candidate_state,
)
from .pipeline import build_evidence_packet, should_report
from .preprocessor import (
    build_macro_audit,
    build_macro_cache,
    ensure_macro_index,
    inspect_macro_cache,
    load_macro_audit_from_cache,
    split_preprocessor_files,
)
from .prompting import build_adjudication_prompt
from .repository import discover_lua_files, read_lua_source_text
from .summaries import (
    SummaryStore,
    detect_module_name,
    detect_required_module_line,
    required_module_symbol_map,
    summarize_source,
)
from .static_analysis import (
    analyze_candidate,
    collect_coalescing_return_helpers,
    collect_maybe_nil_return_helpers,
    collect_inline_guard_contracts,
    collect_transparent_return_wrappers,
)
from .verification import verify_verdict


_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*)\s*\(")
_CALL_EXPRESSION_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*)\s*\((.*)\)\s*$"
)
_INLINE_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*)\s*\("
)
_FUNCTION_BLOCK_RE = re.compile(
    r"\b(?:local\s+)?function(?:\s+[A-Za-z_][A-Za-z0-9_.:]*|\s*)\s*\("
)
_CONTROL_FLOW_START_RE = re.compile(r"^\s*(if|for|while)\b")
_LUA_KEYWORDS = frozenset(
    {
        "and",
        "break",
        "do",
        "elseif",
        "end",
        "for",
        "function",
        "if",
        "local",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "until",
        "while",
    }
)
_TRUNCATED_CONTEXT_MARKER = "  ... (truncated)"
_DEFAULT_RUN_DB_NAME = "review_runs.sqlite3"
_RUN_STORE_DIRNAME = ".lua_nil_guard"


@dataclass(frozen=True, slots=True)
class _RelatedEvidenceBudget:
    max_depth: int
    max_contexts: int
    max_context_lines: int
    max_summary_items: int


_FIRST_HOP_RELATED_EVIDENCE_BUDGET = _RelatedEvidenceBudget(
    max_depth=1,
    max_contexts=4,
    max_context_lines=48,
    max_summary_items=8,
)
_SECOND_HOP_RELATED_EVIDENCE_BUDGET = _RelatedEvidenceBudget(
    max_depth=2,
    max_contexts=6,
    max_context_lines=72,
    max_summary_items=12,
)


@dataclass(frozen=True, slots=True)
class _FunctionContextBlock:
    qualified_name: str
    file: str
    line: int
    evidence_score: int
    rendered: str
    callees: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RelatedEvidenceSelection:
    function_names: tuple[str, ...]
    summary_texts: tuple[str, ...]
    context_texts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReviewRunStatus:
    run_id: int
    repository_root: str
    status: str
    stage: str
    backend_name: str
    backend_model: str | None
    total_cases: int
    completed_cases: int
    failed_cases: int
    ast_exact_cases: int
    lexical_fallback_cases: int
    static_safe_cases: int
    static_unknown_cases: int
    llm_enqueued_cases: int
    llm_processed_cases: int
    llm_second_hop_cases: int
    safe_verified_cases: int
    risky_verified_cases: int
    unknown_reason_distribution: tuple[tuple[str, int], ...]
    created_at: str
    updated_at: str
    completed_at: str | None


def _resolve_preprocessor_files(root_path: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    all_lua_files = tuple(discover_lua_files(root_path))
    preprocessor_config_path = root_path / "config" / "preprocessor_files.json"
    preprocessor_config = (
        load_preprocessor_config(preprocessor_config_path)
        if preprocessor_config_path.is_file()
        else default_preprocessor_config()
    )
    return split_preprocessor_files(
        root_path,
        all_lua_files,
        preprocessor_config,
    )


def bootstrap_repository(root: str | Path) -> RepositorySnapshot:
    """Load the current repository's core review inputs."""

    root_path = Path(root)
    if root_path.suffix.lower() == ".lua" and not root_path.is_dir():
        raise ValueError(
            "Repository commands require a repository root directory, not a Lua file. "
            "Use scan-file, report-file, or report-file-json for a single Lua file."
        )
    if not root_path.exists():
        raise FileNotFoundError(f"Repository root not found: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Repository root is not a directory: {root_path}")

    sink_rules = tuple(load_sink_rules(root_path / "config" / "sink_rules.json"))
    confidence_policy = load_confidence_policy(root_path / "config" / "confidence_policy.json")
    contracts_path = root_path / "config" / "function_contracts.json"
    function_contracts = (
        tuple(load_function_contracts(contracts_path))
        if contracts_path.is_file()
        else ()
    )
    review_lua_files, preprocessor_files = _resolve_preprocessor_files(root_path)
    macro_index, macro_cache_status = ensure_macro_index(
        root_path,
        preprocessor_files,
        source_loader=read_lua_source_text,
    )

    return RepositorySnapshot(
        root=root_path,
        sink_rules=sink_rules,
        confidence_policy=confidence_policy,
        lua_files=review_lua_files,
        preprocessor_files=preprocessor_files,
        macro_index=macro_index,
        macro_cache_status=macro_cache_status,
        function_contracts=function_contracts,
    )


def macro_cache_status_for_repository(root: str | Path) -> MacroCacheStatus:
    """Inspect current macro cache state for a repository without rebuilding it."""

    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"Repository root not found: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Repository root is not a directory: {root_path}")
    _review_files, preprocessor_files = _resolve_preprocessor_files(root_path)
    return inspect_macro_cache(root_path, preprocessor_files)


def build_repository_macro_cache(root: str | Path) -> MacroCacheStatus:
    """Build or refresh the compiled macro cache for one repository."""

    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"Repository root not found: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Repository root is not a directory: {root_path}")
    _review_files, preprocessor_files = _resolve_preprocessor_files(root_path)
    _macro_index, status = build_macro_cache(
        root_path,
        preprocessor_files,
        source_loader=read_lua_source_text,
    )
    return status


def find_repository_root_for_file(file_path: str | Path) -> Path:
    """Resolve the nearest repository root for a Lua file by walking up to config/."""

    target = Path(file_path).resolve(strict=False)
    if target.suffix.lower() != ".lua":
        raise ValueError(f"single-file review requires a .lua file: {file_path}")
    if not target.is_file():
        raise FileNotFoundError(f"Lua file not found: {file_path}")

    for candidate_root in target.parents:
        config_dir = candidate_root / "config"
        if (
            (config_dir / "sink_rules.json").is_file()
            and (config_dir / "confidence_policy.json").is_file()
        ):
            return candidate_root

    raise ValueError(
        "Could not locate repository root for Lua file. "
        "Expected config/sink_rules.json and config/confidence_policy.json in this "
        f"directory or an ancestor: {file_path}"
    )


def review_run_db_path(root: str | Path) -> Path:
    """Return the default persistent run-store path for one repository."""

    root_path = Path(root).resolve(strict=False)
    return root_path / _RUN_STORE_DIRNAME / _DEFAULT_RUN_DB_NAME


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _serialize_run_verdict(verdict: Verdict) -> str:
    payload: dict[str, object] = {
        "case_id": verdict.case_id,
        "status": verdict.status,
        "confidence": verdict.confidence,
        "risk_path": list(verdict.risk_path),
        "safety_evidence": list(verdict.safety_evidence),
        "counterarguments_considered": list(verdict.counterarguments_considered),
        "suggested_fix": verdict.suggested_fix,
        "needs_human": verdict.needs_human,
    }
    if verdict.autofix_patch is not None:
        payload["autofix_patch"] = {
            "case_id": verdict.autofix_patch.case_id,
            "file": verdict.autofix_patch.file,
            "action": verdict.autofix_patch.action,
            "start_line": verdict.autofix_patch.start_line,
            "end_line": verdict.autofix_patch.end_line,
            "replacement": verdict.autofix_patch.replacement,
            "expected_original": verdict.autofix_patch.expected_original,
        }
    if verdict.verification_summary is not None:
        payload["verification_summary"] = {
            "mode": verdict.verification_summary.mode,
            "strongest_proof_kind": verdict.verification_summary.strongest_proof_kind,
            "strongest_proof_depth": verdict.verification_summary.strongest_proof_depth,
            "strongest_proof_summary": verdict.verification_summary.strongest_proof_summary,
            "verification_score": verdict.verification_summary.verification_score,
            "evidence": list(verdict.verification_summary.evidence),
        }
    return json.dumps(payload, sort_keys=True)


def _deserialize_run_verdict(payload: str) -> Verdict:
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("stored verdict payload must be a JSON object")
    autofix_payload = data.get("autofix_patch")
    autofix_patch = None
    if isinstance(autofix_payload, dict):
        autofix_patch = AutofixPatch(
            case_id=str(autofix_payload.get("case_id", "")),
            file=str(autofix_payload.get("file", "")),
            action=str(autofix_payload.get("action", "")),
            start_line=int(autofix_payload.get("start_line", 0)),
            end_line=int(autofix_payload.get("end_line", 0)),
            replacement=str(autofix_payload.get("replacement", "")),
            expected_original=str(autofix_payload.get("expected_original", "")),
        )

    verification_payload = data.get("verification_summary")
    verification_summary = None
    if isinstance(verification_payload, dict):
        from .models import VerificationSummary

        evidence = verification_payload.get("evidence", ())
        verification_summary = VerificationSummary(
            mode=str(verification_payload.get("mode", "")),
            strongest_proof_kind=(
                str(verification_payload["strongest_proof_kind"])
                if verification_payload.get("strongest_proof_kind") is not None
                else None
            ),
            strongest_proof_depth=(
                int(verification_payload["strongest_proof_depth"])
                if verification_payload.get("strongest_proof_depth") is not None
                else None
            ),
            strongest_proof_summary=(
                str(verification_payload["strongest_proof_summary"])
                if verification_payload.get("strongest_proof_summary") is not None
                else None
            ),
            verification_score=(
                int(verification_payload["verification_score"])
                if verification_payload.get("verification_score") is not None
                else None
            ),
            evidence=tuple(str(item) for item in evidence) if isinstance(evidence, list) else (),
        )

    return Verdict(
        case_id=str(data.get("case_id", "")),
        status=str(data.get("status", "uncertain")),
        confidence=str(data.get("confidence", "low")),
        risk_path=tuple(str(item) for item in data.get("risk_path", ()) if isinstance(item, str)),
        safety_evidence=tuple(
            str(item) for item in data.get("safety_evidence", ()) if isinstance(item, str)
        ),
        counterarguments_considered=tuple(
            str(item)
            for item in data.get("counterarguments_considered", ())
            if isinstance(item, str)
        ),
        suggested_fix=(
            str(data["suggested_fix"]) if data.get("suggested_fix") is not None else None
        ),
        needs_human=bool(data.get("needs_human", False)),
        autofix_patch=autofix_patch,
        verification_summary=verification_summary,
    )


class _ReviewRunStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve(strict=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def close(self) -> None:
        self._conn.close()

    def _initialize(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repository_root TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    backend_name TEXT NOT NULL,
                    backend_model TEXT,
                    total_cases INTEGER NOT NULL DEFAULT 0,
                    completed_cases INTEGER NOT NULL DEFAULT 0,
                    failed_cases INTEGER NOT NULL DEFAULT 0,
                    ast_exact_cases INTEGER NOT NULL DEFAULT 0,
                    lexical_fallback_cases INTEGER NOT NULL DEFAULT 0,
                    static_safe_cases INTEGER NOT NULL DEFAULT 0,
                    static_unknown_cases INTEGER NOT NULL DEFAULT 0,
                    llm_enqueued_cases INTEGER NOT NULL DEFAULT 0,
                    llm_processed_cases INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS case_tasks (
                    run_id INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    file TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    column INTEGER NOT NULL,
                    sink_rule_id TEXT NOT NULL,
                    static_state TEXT NOT NULL,
                    candidate_source TEXT NOT NULL DEFAULT 'ast_exact',
                    unknown_reason TEXT NOT NULL DEFAULT '',
                    origin_unknown_reason TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    verdict_status TEXT,
                    verdict_confidence TEXT,
                    verdict_payload TEXT,
                    llm_attempts INTEGER NOT NULL DEFAULT 0,
                    second_hop_used INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, case_id)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_tasks_run_status ON case_tasks(run_id, status)"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_tasks (
                    run_id INTEGER NOT NULL,
                    file TEXT NOT NULL,
                    total_cases INTEGER NOT NULL DEFAULT 0,
                    completed_cases INTEGER NOT NULL DEFAULT 0,
                    failed_cases INTEGER NOT NULL DEFAULT 0,
                    llm_enqueued_cases INTEGER NOT NULL DEFAULT 0,
                    llm_processed_cases INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, file)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adjudication_records (
                    run_id INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    adjudication_status TEXT NOT NULL,
                    adjudication_confidence TEXT NOT NULL,
                    adjudication_payload TEXT NOT NULL,
                    backend_name TEXT,
                    backend_model TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, case_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verdict_snapshots (
                    run_id INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    verdict_payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_tasks_run_status ON file_tasks(run_id, status)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdict_snapshots_run_case ON verdict_snapshots(run_id, case_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_adjudication_records_run_case ON adjudication_records(run_id, case_id)"
            )
        self._ensure_schema_migrations()

    def _ensure_schema_migrations(self) -> None:
        run_columns = {name for name, _type in self._table_columns("runs")}
        run_column_defaults: dict[str, tuple[str, str]] = {
            "ast_exact_cases": ("INTEGER", "0"),
            "lexical_fallback_cases": ("INTEGER", "0"),
            "static_safe_cases": ("INTEGER", "0"),
            "static_unknown_cases": ("INTEGER", "0"),
            "llm_enqueued_cases": ("INTEGER", "0"),
            "llm_processed_cases": ("INTEGER", "0"),
        }
        case_task_columns = {name for name, _type in self._table_columns("case_tasks")}
        with self._conn:
            for column_name, (column_type, default_value) in run_column_defaults.items():
                if column_name in run_columns:
                    continue
                self._conn.execute(
                    f"ALTER TABLE runs ADD COLUMN {column_name} {column_type} NOT NULL DEFAULT {default_value}"
                )
            if "candidate_source" not in case_task_columns:
                self._conn.execute(
                    "ALTER TABLE case_tasks ADD COLUMN candidate_source TEXT NOT NULL DEFAULT 'ast_exact'"
                )
            if "unknown_reason" not in case_task_columns:
                self._conn.execute(
                    "ALTER TABLE case_tasks ADD COLUMN unknown_reason TEXT NOT NULL DEFAULT ''"
                )
            if "origin_unknown_reason" not in case_task_columns:
                self._conn.execute(
                    "ALTER TABLE case_tasks ADD COLUMN origin_unknown_reason TEXT NOT NULL DEFAULT ''"
                )
            if "llm_attempts" not in case_task_columns:
                self._conn.execute(
                    "ALTER TABLE case_tasks ADD COLUMN llm_attempts INTEGER NOT NULL DEFAULT 0"
                )
            if "second_hop_used" not in case_task_columns:
                self._conn.execute(
                    "ALTER TABLE case_tasks ADD COLUMN second_hop_used INTEGER NOT NULL DEFAULT 0"
                )

    def _table_columns(self, table_name: str) -> tuple[tuple[str, str], ...]:
        rows = self._conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return tuple((str(row["name"]), str(row["type"])) for row in rows)

    def create_run(
        self,
        *,
        repository_root: str,
        backend_name: str,
        backend_model: str | None,
    ) -> int:
        now = _utc_now_iso()
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO runs (
                    repository_root,
                    status,
                    stage,
                    backend_name,
                    backend_model,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository_root,
                    "running",
                    "INIT",
                    backend_name,
                    backend_model,
                    now,
                    now,
                ),
            )
        return int(cursor.lastrowid)

    def latest_run_id(self, *, repository_root: str) -> int | None:
        row = self._conn.execute(
            "SELECT run_id FROM runs WHERE repository_root = ? ORDER BY run_id DESC LIMIT 1",
            (repository_root,),
        ).fetchone()
        if row is None:
            return None
        return int(row["run_id"])

    def update_stage(self, *, run_id: int, stage: str) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE runs SET stage = ?, updated_at = ?, status = ? WHERE run_id = ?",
                (stage, now, "running", run_id),
            )

    def ensure_case_tasks(self, *, run_id: int, assessments: tuple[CandidateAssessment, ...]) -> None:
        now = _utc_now_iso()
        per_file_totals: Counter[str] = Counter()
        per_file_llm_enqueued: Counter[str] = Counter()
        with self._conn:
            for assessment in assessments:
                per_file_totals[assessment.candidate.file] += 1
                if assessment.candidate.static_state == "unknown_static":
                    per_file_llm_enqueued[assessment.candidate.file] += 1
                self._conn.execute(
                    """
                    INSERT INTO case_tasks (
                        run_id,
                        case_id,
                        file,
                        line,
                        column,
                        sink_rule_id,
                        static_state,
                        candidate_source,
                        unknown_reason,
                        origin_unknown_reason,
                        llm_attempts,
                        second_hop_used,
                        status,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id, case_id) DO NOTHING
                    """,
                    (
                        run_id,
                        assessment.candidate.case_id,
                        assessment.candidate.file,
                        assessment.candidate.line,
                        assessment.candidate.column,
                        assessment.candidate.sink_rule_id,
                        assessment.candidate.static_state,
                        assessment.candidate.candidate_source,
                        (
                            assessment.static_analysis.unknown_reason
                            or assessment.static_analysis.origin_unknown_reason
                            or ""
                        ),
                        assessment.static_analysis.origin_unknown_reason or "",
                        0,
                        0,
                        "pending",
                        now,
                    ),
                )
            for file_path, total in per_file_totals.items():
                self._conn.execute(
                    """
                    INSERT INTO file_tasks (
                        run_id,
                        file,
                        total_cases,
                        llm_enqueued_cases,
                        status,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id, file) DO UPDATE SET
                        total_cases = excluded.total_cases,
                        llm_enqueued_cases = excluded.llm_enqueued_cases,
                        updated_at = excluded.updated_at
                    """,
                    (
                        run_id,
                        file_path,
                        total,
                        per_file_llm_enqueued[file_path],
                        "pending",
                        now,
                    ),
                )
            self._conn.execute(
                """
                UPDATE runs
                SET total_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ?
                ),
                ast_exact_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND candidate_source = 'ast_exact'
                ),
                lexical_fallback_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND candidate_source = 'lexical_fallback'
                ),
                static_safe_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND static_state = 'safe_static'
                ),
                static_unknown_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND static_state = 'unknown_static'
                ),
                llm_enqueued_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND static_state = 'unknown_static'
                ),
                updated_at = ?
                WHERE run_id = ?
                """,
                (run_id, run_id, run_id, run_id, run_id, run_id, now, run_id),
            )

    def mark_case_running(self, *, run_id: int, case_id: str) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE case_tasks
                SET status = ?, error_message = NULL, updated_at = ?
                WHERE run_id = ? AND case_id = ?
                """,
                ("running", now, run_id, case_id),
            )
            row = self._conn.execute(
                """
                SELECT file
                FROM case_tasks
                WHERE run_id = ? AND case_id = ?
                """,
                (run_id, case_id),
            ).fetchone()
            if row is not None:
                self._conn.execute(
                    """
                    UPDATE file_tasks
                    SET status = ?, updated_at = ?
                    WHERE run_id = ? AND file = ?
                    """,
                    ("running", now, run_id, str(row["file"])),
                )

    def mark_case_completed(
        self,
        *,
        run_id: int,
        verdict: Verdict,
        llm_attempts: int = 0,
        second_hop_used: bool = False,
    ) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE case_tasks
                SET status = ?,
                    verdict_status = ?,
                    verdict_confidence = ?,
                    verdict_payload = ?,
                    llm_attempts = ?,
                    second_hop_used = ?,
                    error_message = NULL,
                    updated_at = ?
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    "completed",
                    verdict.status,
                    verdict.confidence,
                    _serialize_run_verdict(verdict),
                    max(0, llm_attempts),
                    1 if second_hop_used else 0,
                    now,
                    run_id,
                    verdict.case_id,
                ),
            )
            case_row = self._conn.execute(
                """
                SELECT file, static_state
                FROM case_tasks
                WHERE run_id = ? AND case_id = ?
                """,
                (run_id, verdict.case_id),
            ).fetchone()
            if case_row is not None:
                file_path = str(case_row["file"])
                static_state = str(case_row["static_state"])
                self._refresh_file_task_progress(
                    run_id=run_id,
                    file_path=file_path,
                    now=now,
                )
                if static_state == "unknown_static":
                    self._conn.execute(
                        """
                        UPDATE runs
                        SET llm_processed_cases = (
                            SELECT COUNT(*)
                            FROM case_tasks
                            WHERE run_id = ? AND status = 'completed' AND static_state = 'unknown_static'
                        ),
                        updated_at = ?
                        WHERE run_id = ?
                        """,
                        (run_id, now, run_id),
                    )
            self._conn.execute(
                """
                UPDATE runs
                SET completed_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND status = 'completed'
                ),
                failed_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND status = 'failed'
                ),
                updated_at = ?
                WHERE run_id = ?
                """,
                (run_id, run_id, now, run_id),
            )
            self._conn.execute(
                """
                INSERT INTO verdict_snapshots (
                    run_id,
                    case_id,
                    stage,
                    verdict_payload,
                    created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    verdict.case_id,
                    "final",
                    _serialize_run_verdict(verdict),
                    now,
                ),
            )

    def mark_case_failed(self, *, run_id: int, case_id: str, message: str) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE case_tasks
                SET status = ?, error_message = ?, updated_at = ?
                WHERE run_id = ? AND case_id = ?
                """,
                ("failed", message, now, run_id, case_id),
            )
            case_row = self._conn.execute(
                """
                SELECT file
                FROM case_tasks
                WHERE run_id = ? AND case_id = ?
                """,
                (run_id, case_id),
            ).fetchone()
            if case_row is not None:
                self._refresh_file_task_progress(
                    run_id=run_id,
                    file_path=str(case_row["file"]),
                    now=now,
                )
            self._conn.execute(
                """
                UPDATE runs
                SET failed_cases = (
                    SELECT COUNT(*)
                    FROM case_tasks
                    WHERE run_id = ? AND status = 'failed'
                ),
                updated_at = ?
                WHERE run_id = ?
                """,
                (run_id, now, run_id),
            )

    def record_adjudication(
        self,
        *,
        run_id: int,
        case_id: str,
        verdict: Verdict,
        backend_name: str | None,
        backend_model: str | None,
    ) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO adjudication_records (
                    run_id,
                    case_id,
                    adjudication_status,
                    adjudication_confidence,
                    adjudication_payload,
                    backend_name,
                    backend_model,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, case_id) DO UPDATE SET
                    adjudication_status = excluded.adjudication_status,
                    adjudication_confidence = excluded.adjudication_confidence,
                    adjudication_payload = excluded.adjudication_payload,
                    backend_name = excluded.backend_name,
                    backend_model = excluded.backend_model,
                    created_at = excluded.created_at
                """,
                (
                    run_id,
                    case_id,
                    verdict.status,
                    verdict.confidence,
                    _serialize_run_verdict(verdict),
                    backend_name,
                    backend_model,
                    now,
                ),
            )

    def load_run_verdicts_ordered(self, *, run_id: int) -> tuple[Verdict, ...]:
        rows = self._conn.execute(
            """
            SELECT case_id, verdict_payload
            FROM case_tasks
            WHERE run_id = ? AND status = 'completed' AND verdict_payload IS NOT NULL
            ORDER BY file ASC, line ASC, column ASC, case_id ASC
            """,
            (run_id,),
        ).fetchall()
        verdicts: list[Verdict] = []
        for row in rows:
            payload = row["verdict_payload"]
            if not isinstance(payload, str):
                continue
            try:
                verdicts.append(_deserialize_run_verdict(payload))
            except (ValueError, json.JSONDecodeError):
                continue
        return tuple(verdicts)

    def _refresh_file_task_progress(self, *, run_id: int, file_path: str, now: str) -> None:
        row = self._conn.execute(
            """
            SELECT COUNT(*) AS total_cases,
                   SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_cases,
                   SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_cases,
                   SUM(
                       CASE WHEN status = 'completed' AND static_state = 'unknown_static'
                       THEN 1 ELSE 0 END
                   ) AS llm_processed_cases,
                   SUM(
                       CASE WHEN static_state = 'unknown_static'
                       THEN 1 ELSE 0 END
                   ) AS llm_enqueued_cases
            FROM case_tasks
            WHERE run_id = ? AND file = ?
            """,
            (run_id, file_path),
        ).fetchone()
        if row is None:
            return
        total_cases = int(row["total_cases"] or 0)
        completed_cases = int(row["completed_cases"] or 0)
        failed_cases = int(row["failed_cases"] or 0)
        llm_processed_cases = int(row["llm_processed_cases"] or 0)
        llm_enqueued_cases = int(row["llm_enqueued_cases"] or 0)
        if completed_cases + failed_cases >= total_cases:
            status = "completed"
        elif completed_cases > 0 or failed_cases > 0:
            status = "running"
        else:
            status = "pending"
        self._conn.execute(
            """
            UPDATE file_tasks
            SET completed_cases = ?,
                failed_cases = ?,
                llm_processed_cases = ?,
                llm_enqueued_cases = ?,
                status = ?,
                updated_at = ?
            WHERE run_id = ? AND file = ?
            """,
            (
                completed_cases,
                failed_cases,
                llm_processed_cases,
                llm_enqueued_cases,
                status,
                now,
                run_id,
                file_path,
            ),
        )

    def is_case_completed(self, *, run_id: int, case_id: str) -> bool:
        row = self._conn.execute(
            """
            SELECT status
            FROM case_tasks
            WHERE run_id = ? AND case_id = ?
            """,
            (run_id, case_id),
        ).fetchone()
        if row is None:
            return False
        return str(row["status"]) == "completed"

    def load_completed_verdicts(self, *, run_id: int) -> dict[str, Verdict]:
        rows = self._conn.execute(
            """
            SELECT case_id, verdict_payload
            FROM case_tasks
            WHERE run_id = ? AND status = 'completed' AND verdict_payload IS NOT NULL
            """,
            (run_id,),
        ).fetchall()
        verdicts: dict[str, Verdict] = {}
        for row in rows:
            payload = row["verdict_payload"]
            if not isinstance(payload, str):
                continue
            try:
                verdicts[str(row["case_id"])] = _deserialize_run_verdict(payload)
            except (ValueError, json.JSONDecodeError):
                continue
        return verdicts

    def mark_run_completed(self, *, run_id: int) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE runs
                SET status = ?,
                    stage = ?,
                    completed_cases = (
                        SELECT COUNT(*)
                        FROM case_tasks
                        WHERE run_id = ? AND status = 'completed'
                    ),
                    failed_cases = (
                        SELECT COUNT(*)
                        FROM case_tasks
                        WHERE run_id = ? AND status = 'failed'
                    ),
                    llm_processed_cases = (
                        SELECT COUNT(*)
                        FROM case_tasks
                        WHERE run_id = ? AND status = 'completed' AND static_state = 'unknown_static'
                    ),
                    updated_at = ?,
                    completed_at = ?
                WHERE run_id = ?
                """,
                ("completed", "FINALIZE", run_id, run_id, run_id, now, now, run_id),
            )

    def mark_run_failed(self, *, run_id: int) -> None:
        now = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?",
                ("failed", now, run_id),
            )

    def _load_unknown_reason_distribution(self, *, run_id: int) -> tuple[tuple[str, int], ...]:
        rows = self._conn.execute(
            """
            SELECT unknown_reason, COUNT(*) AS reason_count
            FROM case_tasks
            WHERE run_id = ?
              AND static_state = 'unknown_static'
              AND TRIM(unknown_reason) <> ''
            GROUP BY unknown_reason
            ORDER BY reason_count DESC, unknown_reason ASC
            """,
            (run_id,),
        ).fetchall()
        return tuple((str(row["unknown_reason"]), int(row["reason_count"])) for row in rows)

    def _load_case_stage_metrics(self, *, run_id: int) -> tuple[int, int, int]:
        row = self._conn.execute(
            """
            SELECT
                SUM(CASE WHEN second_hop_used = 1 THEN 1 ELSE 0 END) AS llm_second_hop_cases,
                SUM(CASE WHEN verdict_status = 'safe_verified' THEN 1 ELSE 0 END) AS safe_verified_cases,
                SUM(CASE WHEN verdict_status = 'risky_verified' THEN 1 ELSE 0 END) AS risky_verified_cases
            FROM case_tasks
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            return (0, 0, 0)
        return (
            int(row["llm_second_hop_cases"] or 0),
            int(row["safe_verified_cases"] or 0),
            int(row["risky_verified_cases"] or 0),
        )

    def load_run_status(self, *, run_id: int) -> ReviewRunStatus | None:
        row = self._conn.execute(
            """
            SELECT run_id,
                   repository_root,
                   status,
                   stage,
                   backend_name,
                   backend_model,
                   total_cases,
                   completed_cases,
                   failed_cases,
                   ast_exact_cases,
                   lexical_fallback_cases,
                   static_safe_cases,
                   static_unknown_cases,
                   llm_enqueued_cases,
                   llm_processed_cases,
                   created_at,
                   updated_at,
                   completed_at
            FROM runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        llm_second_hop_cases, safe_verified_cases, risky_verified_cases = (
            self._load_case_stage_metrics(run_id=run_id)
        )
        unknown_reason_distribution = self._load_unknown_reason_distribution(run_id=run_id)
        return ReviewRunStatus(
            run_id=int(row["run_id"]),
            repository_root=str(row["repository_root"]),
            status=str(row["status"]),
            stage=str(row["stage"]),
            backend_name=str(row["backend_name"]),
            backend_model=(str(row["backend_model"]) if row["backend_model"] is not None else None),
            total_cases=int(row["total_cases"]),
            completed_cases=int(row["completed_cases"]),
            failed_cases=int(row["failed_cases"]),
            ast_exact_cases=int(row["ast_exact_cases"]),
            lexical_fallback_cases=int(row["lexical_fallback_cases"]),
            static_safe_cases=int(row["static_safe_cases"]),
            static_unknown_cases=int(row["static_unknown_cases"]),
            llm_enqueued_cases=int(row["llm_enqueued_cases"]),
            llm_processed_cases=int(row["llm_processed_cases"]),
            llm_second_hop_cases=llm_second_hop_cases,
            safe_verified_cases=safe_verified_cases,
            risky_verified_cases=risky_verified_cases,
            unknown_reason_distribution=unknown_reason_distribution,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            completed_at=(str(row["completed_at"]) if row["completed_at"] is not None else None),
        )


def review_source(
    file_path: str | Path,
    source: str,
    sink_rules: tuple[SinkRule, ...],
    *,
    function_contracts: tuple[object, ...] = (),
    transparent_return_wrappers: dict[str, tuple[tuple[int, int], ...]] | None = None,
    maybe_nil_return_helpers: dict[str, tuple[tuple[int, int], ...]] | None = None,
    coalescing_return_helpers: dict[str, tuple[tuple[int, int, int], ...]] | None = None,
    inline_guard_contracts: tuple[object, ...] | None = None,
    macro_index=None,
) -> tuple[CandidateAssessment, ...]:
    """Collect candidates from one source file and attach local static analysis."""

    effective_transparent_return_wrappers = (
        dict(transparent_return_wrappers)
        if transparent_return_wrappers is not None
        else {}
    )
    effective_transparent_return_wrappers.update(
        collect_transparent_return_wrappers((source,), allow_local=True)
    )
    effective_inline_guard_contracts = (
        tuple(inline_guard_contracts)
        if inline_guard_contracts is not None
        else ()
    )
    effective_inline_guard_contracts = (
        effective_inline_guard_contracts
        + collect_inline_guard_contracts((source,), allow_local=True)
    )
    effective_maybe_nil_return_helpers = (
        dict(maybe_nil_return_helpers)
        if maybe_nil_return_helpers is not None
        else {}
    )
    effective_coalescing_return_helpers = (
        dict(coalescing_return_helpers)
        if coalescing_return_helpers is not None
        else {}
    )
    effective_maybe_nil_return_helpers.update(
        collect_maybe_nil_return_helpers(summarize_source(file_path, source))
    )
    effective_coalescing_return_helpers.update(
        collect_coalescing_return_helpers(summarize_source(file_path, source))
    )
    effective_required_module_symbol_map = required_module_symbol_map(source)
    assessments: list[CandidateAssessment] = []
    for candidate in collect_candidates(file_path, source, sink_rules):
        static_analysis = analyze_candidate(
            source,
            candidate,
            function_contracts=tuple(function_contracts),
            transparent_return_wrappers=effective_transparent_return_wrappers,
            maybe_nil_return_helpers=effective_maybe_nil_return_helpers,
            coalescing_return_helpers=effective_coalescing_return_helpers,
            inline_guard_contracts=effective_inline_guard_contracts,
            macro_index=macro_index,
            required_module_symbol_map=effective_required_module_symbol_map,
        )
        assessments.append(
            CandidateAssessment(
                candidate=with_candidate_state(candidate, static_analysis.state),
                static_analysis=static_analysis,
            )
        )
    return tuple(assessments)


def review_repository(snapshot: RepositorySnapshot) -> tuple[CandidateAssessment, ...]:
    """Run the current static first-pass review across all discovered Lua files."""

    transparent_return_wrappers = _collect_snapshot_transparent_return_wrappers(snapshot)
    inline_guard_contracts = _collect_snapshot_inline_guard_contracts(snapshot)
    maybe_nil_return_helpers = _collect_snapshot_maybe_nil_return_helpers(snapshot)
    coalescing_return_helpers = _collect_snapshot_coalescing_return_helpers(snapshot)
    assessments: list[CandidateAssessment] = []
    for file_path in snapshot.lua_files:
        source = read_lua_source_text(file_path)
        assessments.extend(
            review_source(
                file_path,
                source,
                snapshot.sink_rules,
                function_contracts=snapshot.function_contracts,
                transparent_return_wrappers=transparent_return_wrappers,
                maybe_nil_return_helpers=maybe_nil_return_helpers,
                coalescing_return_helpers=coalescing_return_helpers,
                inline_guard_contracts=inline_guard_contracts,
                macro_index=snapshot.macro_index,
            )
        )
    return tuple(assessments)


def review_repository_file(
    snapshot: RepositorySnapshot,
    file_path: str | Path,
) -> tuple[CandidateAssessment, ...]:
    """Run the current static first-pass review for one Lua file in a repository snapshot."""

    resolved_file = _resolve_snapshot_lua_file(snapshot, file_path)
    source = read_lua_source_text(resolved_file)
    transparent_return_wrappers = _collect_snapshot_transparent_return_wrappers(snapshot)
    inline_guard_contracts = _collect_snapshot_inline_guard_contracts(snapshot)
    maybe_nil_return_helpers = _collect_snapshot_maybe_nil_return_helpers(snapshot)
    coalescing_return_helpers = _collect_snapshot_coalescing_return_helpers(snapshot)
    return review_source(
        resolved_file,
        source,
        snapshot.sink_rules,
        function_contracts=snapshot.function_contracts,
        transparent_return_wrappers=transparent_return_wrappers,
        maybe_nil_return_helpers=maybe_nil_return_helpers,
        coalescing_return_helpers=coalescing_return_helpers,
        inline_guard_contracts=inline_guard_contracts,
        macro_index=snapshot.macro_index,
    )


def macro_audit_repository(snapshot: RepositorySnapshot) -> MacroAuditResult:
    """Return operator-facing macro dictionary ingestion details for a snapshot."""

    cached_audit = load_macro_audit_from_cache(
        snapshot.root,
        snapshot.macro_index,
        files=snapshot.preprocessor_files,
    )
    if cached_audit is not None:
        return cached_audit
    if snapshot.macro_index is not None:
        return MacroAuditResult(
            files=tuple(str(path) for path in snapshot.preprocessor_files),
            facts=snapshot.macro_index.facts,
            unresolved_lines=snapshot.macro_index.unresolved_lines,
        )
    return build_macro_audit(
        snapshot.root,
        snapshot.preprocessor_files,
        source_loader=read_lua_source_text,
    )


def prepare_evidence_packet(
    assessment: CandidateAssessment,
    source: str,
    *,
    related_functions: tuple[str, ...] = (),
    function_summaries: tuple[str, ...] = (),
    knowledge_facts: tuple[str, ...] = (),
    related_function_contexts: tuple[str, ...] = (),
    context_radius: int = 2,
) -> EvidencePacket:
    """Convert a locally analyzed candidate into an agent-ready evidence packet."""

    lines = source.splitlines()
    start = max(0, assessment.candidate.line - 1 - context_radius)
    end = min(len(lines), assessment.candidate.line + context_radius)
    local_context = "\n".join(lines[start:end])

    return build_evidence_packet(
        candidate=assessment.candidate,
        local_context=local_context,
        related_functions=related_functions,
        function_summaries=function_summaries,
        knowledge_facts=knowledge_facts,
        origin_candidates=assessment.static_analysis.origin_candidates,
        origin_usage_modes=assessment.static_analysis.origin_usage_modes,
        origin_return_slots=assessment.static_analysis.origin_return_slots,
        analysis_mode=assessment.static_analysis.analysis_mode,
        unknown_reason=assessment.static_analysis.unknown_reason,
        origin_analysis_mode=assessment.static_analysis.origin_analysis_mode,
        origin_unknown_reason=assessment.static_analysis.origin_unknown_reason,
        observed_guards=assessment.static_analysis.observed_guards,
        related_function_contexts=related_function_contexts,
        static_proofs=assessment.static_analysis.proofs,
        static_risk_signals=assessment.static_analysis.risk_signals,
    )


def run_repository_review(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
    only_unknown_for_agent: bool = True,
) -> tuple[Verdict, ...]:
    """Run the current end-to-end local review pipeline across a repository."""

    assessments = review_repository(snapshot)
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    adjudication_backend = backend or HeuristicAdjudicationBackend()

    return _run_review_from_assessments(
        snapshot,
        assessments,
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
        only_unknown_for_agent=only_unknown_for_agent,
    )


def run_repository_review_job(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
    run_db_path: str | Path | None = None,
    run_id: int | None = None,
) -> tuple[ReviewRunStatus, tuple[Verdict, ...]]:
    """Run one persistent review job and return run status with ordered verdicts."""

    adjudication_backend = backend or HeuristicAdjudicationBackend()
    db_path = (
        Path(run_db_path).resolve(strict=False)
        if run_db_path is not None
        else review_run_db_path(snapshot.root)
    )
    store = _ReviewRunStore(db_path)
    effective_run_id: int | None = run_id
    repository_key = str(Path(snapshot.root).resolve(strict=False))
    try:
        backend_name = _backend_name(adjudication_backend)
        backend_model = _backend_optional_string(adjudication_backend, "model")
        if effective_run_id is None:
            effective_run_id = store.create_run(
                repository_root=repository_key,
                backend_name=backend_name,
                backend_model=backend_model,
            )
        status = store.load_run_status(run_id=effective_run_id)
        if status is None:
            raise ValueError(f"Run id not found: {effective_run_id}")

        store.update_stage(run_id=effective_run_id, stage="STATIC")
        assessments = review_repository(snapshot)
        store.ensure_case_tasks(run_id=effective_run_id, assessments=assessments)
        existing_verdicts = store.load_completed_verdicts(run_id=effective_run_id)

        summaries = _collect_repository_summaries(snapshot)
        summary_text_by_name = _build_summary_text_index(summaries)
        function_context_by_name = _build_function_context_index(snapshot, summaries)
        file_module_by_path = _build_file_module_index(snapshot)
        facts = _load_knowledge_facts(snapshot, knowledge_path)

        store.update_stage(run_id=effective_run_id, stage="QUEUE")
        store.update_stage(run_id=effective_run_id, stage="LLM")
        verdicts = _run_review_from_assessments(
            snapshot,
            assessments,
            adjudication_backend=adjudication_backend,
            summary_text_by_name=summary_text_by_name,
            function_context_by_name=function_context_by_name,
            file_module_by_path=file_module_by_path,
            facts=facts,
            run_store=store,
            run_id=effective_run_id,
            only_unknown_for_agent=True,
            existing_verdicts=existing_verdicts,
        )
        store.update_stage(run_id=effective_run_id, stage="VERIFY")
        store.mark_run_completed(run_id=effective_run_id)
        final_status = store.load_run_status(run_id=effective_run_id)
        if final_status is None:
            raise ValueError(f"Run id not found after completion: {effective_run_id}")
        return final_status, verdicts
    except Exception:
        if effective_run_id is not None:
            store.mark_run_failed(run_id=effective_run_id)
        raise
    finally:
        store.close()


def repository_review_run_status(
    root: str | Path,
    *,
    run_db_path: str | Path | None = None,
    run_id: int | None = None,
) -> ReviewRunStatus:
    """Load persisted status for the latest or specified review run."""

    root_path = Path(root).resolve(strict=False)
    db_path = (
        Path(run_db_path).resolve(strict=False)
        if run_db_path is not None
        else review_run_db_path(root_path)
    )
    store = _ReviewRunStore(db_path)
    try:
        effective_run_id = run_id
        if effective_run_id is None:
            effective_run_id = store.latest_run_id(repository_root=str(root_path))
            if effective_run_id is None:
                raise ValueError(f"No review runs found for repository: {root_path}")
        status = store.load_run_status(run_id=effective_run_id)
        if status is None:
            raise ValueError(f"Run id not found: {effective_run_id}")
        return status
    finally:
        store.close()


def repository_review_run_verdicts(
    root: str | Path,
    *,
    run_db_path: str | Path | None = None,
    run_id: int | None = None,
) -> tuple[ReviewRunStatus, tuple[Verdict, ...]]:
    """Load persisted verdicts for the latest or specified run."""

    root_path = Path(root).resolve(strict=False)
    db_path = (
        Path(run_db_path).resolve(strict=False)
        if run_db_path is not None
        else review_run_db_path(root_path)
    )
    store = _ReviewRunStore(db_path)
    try:
        effective_run_id = run_id
        if effective_run_id is None:
            effective_run_id = store.latest_run_id(repository_root=str(root_path))
            if effective_run_id is None:
                raise ValueError(f"No review runs found for repository: {root_path}")
        status = store.load_run_status(run_id=effective_run_id)
        if status is None:
            raise ValueError(f"Run id not found: {effective_run_id}")
        verdicts = store.load_run_verdicts_ordered(run_id=effective_run_id)
        return status, verdicts
    finally:
        store.close()


def run_file_review(
    snapshot: RepositorySnapshot,
    file_path: str | Path,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
    only_unknown_for_agent: bool = True,
) -> tuple[Verdict, ...]:
    """Run the current end-to-end review pipeline for one Lua file with repository context."""

    assessments = review_repository_file(snapshot, file_path)
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    adjudication_backend = backend or HeuristicAdjudicationBackend()

    return _run_review_from_assessments(
        snapshot,
        assessments,
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
        only_unknown_for_agent=only_unknown_for_agent,
    )


def benchmark_repository_review(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> BenchmarkSummary:
    """Run a labeled semantic benchmark over provable_* Lua review fixtures."""

    assessments = review_repository(snapshot)
    labeled_assessments = tuple(
        (assessment, _expected_benchmark_label(assessment.candidate.file))
        for assessment in assessments
        if _expected_benchmark_label(assessment.candidate.file) is not None
    )
    if not labeled_assessments:
        raise ValueError(
            "benchmark requires labeled files named provable_risky_*, "
            "provable_safe_* or provable_uncertain_*"
        )

    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = (
        _load_knowledge_facts(snapshot, knowledge_path)
        if knowledge_path is not None
        else _merge_knowledge_facts(
            derive_facts_from_summaries(summaries),
            derive_facts_from_contracts(snapshot.function_contracts),
        )
    )
    adjudication_backend = backend or HeuristicAdjudicationBackend()
    verdicts = _run_review_from_assessments(
        snapshot,
        tuple(assessment for assessment, _ in labeled_assessments),
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
    )
    verdict_by_case_id = {verdict.case_id: verdict for verdict in verdicts}

    cases: list[BenchmarkCaseResult] = []
    for assessment, expected in labeled_assessments:
        verdict = verdict_by_case_id[assessment.candidate.case_id]
        actual = _normalize_benchmark_status(verdict.status)
        backend_failure_reason = _extract_backend_failure_reason(verdict)
        cases.append(
            BenchmarkCaseResult(
                case_id=assessment.candidate.case_id,
                file=assessment.candidate.file,
                expected_status=expected,
                actual_status=actual,
                matches_expectation=actual == expected,
                backend_failure_reason=backend_failure_reason,
            )
        )

    expected_risky = sum(1 for case in cases if case.expected_status == "risky")
    expected_safe = sum(1 for case in cases if case.expected_status == "safe")
    expected_uncertain = sum(1 for case in cases if case.expected_status == "uncertain")
    actual_risky = sum(1 for case in cases if case.actual_status == "risky")
    actual_safe = sum(1 for case in cases if case.actual_status == "safe")
    actual_uncertain = sum(1 for case in cases if case.actual_status == "uncertain")
    ast_primary_cases = sum(
        1
        for assessment, _ in labeled_assessments
        if assessment.static_analysis.analysis_mode == "ast_primary"
    )
    ast_fallback_to_legacy_cases = sum(
        1
        for assessment, _ in labeled_assessments
        if assessment.static_analysis.analysis_mode == "ast_fallback_to_legacy"
    )
    legacy_only_cases = sum(
        1
        for assessment, _ in labeled_assessments
        if assessment.static_analysis.analysis_mode == "legacy_only"
    )
    backend_cache_hits = _backend_metric(adjudication_backend, "cache_hits")
    backend_cache_misses = _backend_metric(adjudication_backend, "cache_misses")
    backend_calls = _backend_metric(adjudication_backend, "backend_call_count")
    backend_total_seconds = _backend_float_metric(adjudication_backend, "backend_total_seconds")
    backend_warmup_calls = _backend_metric(adjudication_backend, "backend_warmup_call_count")
    backend_warmup_total_seconds = _backend_float_metric(
        adjudication_backend,
        "backend_warmup_total_seconds",
    )
    backend_average_seconds = 0.0
    if backend_calls:
        backend_average_seconds = backend_total_seconds / backend_calls
    backend_review_calls = max(0, backend_calls - backend_warmup_calls)
    backend_review_total_seconds = max(0.0, backend_total_seconds - backend_warmup_total_seconds)
    backend_review_average_seconds = 0.0
    if backend_review_calls:
        backend_review_average_seconds = backend_review_total_seconds / backend_review_calls
    backend_name = _backend_name(adjudication_backend)
    backend_model = _backend_optional_string(adjudication_backend, "model")
    backend_executable = _backend_optional_string(adjudication_backend, "executable")

    return BenchmarkSummary(
        total_cases=len(cases),
        exact_matches=sum(1 for case in cases if case.matches_expectation),
        expected_risky=expected_risky,
        expected_safe=expected_safe,
        expected_uncertain=expected_uncertain,
        actual_risky=actual_risky,
        actual_safe=actual_safe,
        actual_uncertain=actual_uncertain,
        false_positive_risks=sum(
            1 for case in cases if case.actual_status == "risky" and case.expected_status != "risky"
        ),
        missed_risks=sum(
            1 for case in cases if case.expected_status == "risky" and case.actual_status != "risky"
        ),
        unresolved_cases=sum(
            1
            for case in cases
            if case.actual_status == "uncertain" and case.expected_status in {"risky", "safe"}
        ),
        backend_fallbacks=sum(1 for case in cases if case.backend_failure_reason is not None),
        backend_timeouts=sum(
            1
            for case in cases
            if case.backend_failure_reason is not None
            and "timed out" in case.backend_failure_reason.lower()
        ),
        backend_cache_hits=backend_cache_hits,
        backend_cache_misses=backend_cache_misses,
        backend_calls=backend_calls,
        backend_total_seconds=backend_total_seconds,
        backend_average_seconds=backend_average_seconds,
        backend_name=backend_name,
        backend_model=backend_model,
        backend_executable=backend_executable,
        cases=tuple(cases),
        backend_warmup_calls=backend_warmup_calls,
        backend_warmup_total_seconds=backend_warmup_total_seconds,
        backend_review_calls=backend_review_calls,
        backend_review_total_seconds=backend_review_total_seconds,
        backend_review_average_seconds=backend_review_average_seconds,
        ast_primary_cases=ast_primary_cases,
        ast_fallback_to_legacy_cases=ast_fallback_to_legacy_cases,
        legacy_only_cases=legacy_only_cases,
    )


def benchmark_cache_compare(
    snapshot: RepositorySnapshot,
    *,
    backend_factory: Callable[[], AdjudicationBackend],
    cache_path: str | Path,
    knowledge_path: str | Path | None = None,
) -> BenchmarkCacheComparison:
    """Run benchmark twice to compare cold-start and warm-cache backend behavior."""

    cleared_entries = clear_backend_cache(cache_path)
    cold_backend = backend_factory()
    cold = benchmark_repository_review(
        snapshot,
        backend=cold_backend,
        knowledge_path=knowledge_path,
    )
    warm_backend = backend_factory()
    warm = benchmark_repository_review(
        snapshot,
        backend=warm_backend,
        knowledge_path=knowledge_path,
    )
    return BenchmarkCacheComparison(
        cache_path=str(Path(cache_path)),
        cache_cleared_entries=cleared_entries,
        cold=cold,
        warm=warm,
    )


def _run_review_from_assessments(
    snapshot: RepositorySnapshot,
    assessments: tuple[CandidateAssessment, ...],
    *,
    adjudication_backend: AdjudicationBackend,
    summary_text_by_name: dict[str, tuple[str, ...]],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    file_module_by_path: dict[str, str | None],
    facts: tuple[object, ...],
    run_store: _ReviewRunStore | None = None,
    run_id: int | None = None,
    only_unknown_for_agent: bool = False,
    existing_verdicts: dict[str, Verdict] | None = None,
) -> tuple[Verdict, ...]:
    if run_store is not None and run_id is None:
        raise ValueError("run_id is required when run_store is provided")
    sink_rule_by_id = {rule.id: rule for rule in snapshot.sink_rules}
    assessments_by_file: dict[str, list[CandidateAssessment]] = {}
    for assessment in assessments:
        assessments_by_file.setdefault(assessment.candidate.file, []).append(assessment)

    verdict_cache = dict(existing_verdicts or {})
    backend_name = _backend_name(adjudication_backend) if run_store is not None else None
    backend_model = (
        _backend_optional_string(adjudication_backend, "model")
        if run_store is not None
        else None
    )
    verdicts: list[Verdict] = []
    for file_path in snapshot.lua_files:
        source = read_lua_source_text(file_path)
        for assessment in assessments_by_file.get(str(file_path), ()):
            case_id = assessment.candidate.case_id
            cached_verdict = verdict_cache.get(case_id)
            if cached_verdict is not None:
                verdicts.append(cached_verdict)
                continue
            if run_store is not None and run_id is not None:
                run_store.mark_case_running(
                    run_id=run_id,
                    case_id=case_id,
                )
            llm_attempts = 0
            second_hop_used = False
            related_evidence = _build_related_evidence(
                assessment,
                summary_text_by_name=summary_text_by_name,
                function_context_by_name=function_context_by_name,
                file_module_by_path=file_module_by_path,
                budget=_FIRST_HOP_RELATED_EVIDENCE_BUDGET,
            )
            knowledge_facts = _knowledge_facts_for_assessment(
                assessment,
                related_evidence.function_names,
                facts,
                function_contracts=snapshot.function_contracts,
                current_module=file_module_by_path.get(_normalize_path_key(assessment.candidate.file)),
                source=source,
            )
            packet = prepare_evidence_packet(
                assessment,
                source,
                related_functions=related_evidence.function_names,
                function_summaries=related_evidence.summary_texts,
                knowledge_facts=knowledge_facts,
                related_function_contexts=related_evidence.context_texts,
            )
            try:
                if only_unknown_for_agent and assessment.static_analysis.state != "unknown_static":
                    seeded_verdict = _static_only_seed_verdict(assessment)
                    final_verdict = verify_verdict(seeded_verdict, packet)
                else:
                    adjudication = adjudication_backend.adjudicate(
                        packet,
                        sink_rule_by_id[assessment.candidate.sink_rule_id],
                    )
                    llm_attempts += 1
                    verdict = attach_autofix_patch(
                        adjudication.judge,
                        packet,
                        sink_rule_by_id[assessment.candidate.sink_rule_id],
                    )
                    if run_store is not None and run_id is not None:
                        run_store.record_adjudication(
                            run_id=run_id,
                            case_id=case_id,
                            verdict=verdict,
                            backend_name=backend_name,
                            backend_model=backend_model,
                        )
                    final_verdict = verify_verdict(verdict, packet)
                    if (
                        assessment.static_analysis.state == "unknown_static"
                        and _should_retry_with_expanded_evidence(
                            adjudication_backend,
                            adjudication,
                            final_verdict,
                        )
                    ):
                        expanded_related_evidence = _build_related_evidence(
                            assessment,
                            summary_text_by_name=summary_text_by_name,
                            function_context_by_name=function_context_by_name,
                            file_module_by_path=file_module_by_path,
                            budget=_SECOND_HOP_RELATED_EVIDENCE_BUDGET,
                        )
                        if expanded_related_evidence != related_evidence:
                            second_hop_used = True
                            expanded_packet = prepare_evidence_packet(
                                assessment,
                                source,
                                related_functions=expanded_related_evidence.function_names,
                                function_summaries=expanded_related_evidence.summary_texts,
                                knowledge_facts=_knowledge_facts_for_assessment(
                                    assessment,
                                    expanded_related_evidence.function_names,
                                    facts,
                                    function_contracts=snapshot.function_contracts,
                                    current_module=file_module_by_path.get(
                                        _normalize_path_key(assessment.candidate.file)
                                    ),
                                    source=source,
                                ),
                                related_function_contexts=expanded_related_evidence.context_texts,
                            )
                            expanded_adjudication = adjudication_backend.adjudicate(
                                expanded_packet,
                                sink_rule_by_id[assessment.candidate.sink_rule_id],
                            )
                            llm_attempts += 1
                            expanded_verdict = attach_autofix_patch(
                                expanded_adjudication.judge,
                                expanded_packet,
                                sink_rule_by_id[assessment.candidate.sink_rule_id],
                            )
                            if run_store is not None and run_id is not None:
                                run_store.record_adjudication(
                                    run_id=run_id,
                                    case_id=case_id,
                                    verdict=expanded_verdict,
                                    backend_name=backend_name,
                                    backend_model=backend_model,
                                )
                            final_verdict = verify_verdict(expanded_verdict, expanded_packet)
            except Exception as exc:
                if run_store is not None and run_id is not None:
                    run_store.mark_case_failed(
                        run_id=run_id,
                        case_id=case_id,
                        message=str(exc),
                    )
                raise

            if run_store is not None and run_id is not None:
                run_store.mark_case_completed(
                    run_id=run_id,
                    verdict=final_verdict,
                    llm_attempts=llm_attempts,
                    second_hop_used=second_hop_used,
                )
            verdict_cache[case_id] = final_verdict
            verdicts.append(final_verdict)
    return tuple(verdicts)


def _static_only_seed_verdict(assessment: CandidateAssessment) -> Verdict:
    state = assessment.static_analysis.state
    case_id = assessment.candidate.case_id
    if state == "safe_static":
        safety_evidence = (
            assessment.static_analysis.observed_guards
            or tuple(proof.summary for proof in assessment.static_analysis.proofs)
        )
        return Verdict(
            case_id=case_id,
            status="safe",
            confidence="medium",
            risk_path=(),
            safety_evidence=safety_evidence,
            counterarguments_considered=("static-only evaluation path",),
            suggested_fix=None,
            needs_human=False,
        )
    return Verdict(
        case_id=case_id,
        status="uncertain",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        counterarguments_considered=("static-only evaluation path",),
        suggested_fix=None,
        needs_human=False,
    )


def refresh_summary_cache(
    snapshot: RepositorySnapshot,
    *,
    summary_path: str | Path | None = None,
) -> tuple[object, ...]:
    """Rebuild and persist the repository function summary cache."""

    summaries = _collect_repository_summaries(snapshot)
    path = Path(summary_path) if summary_path is not None else snapshot.root / "data" / "function_summaries.json"
    SummaryStore(path).save(summaries)
    return summaries


def refresh_knowledge_base(
    snapshot: RepositorySnapshot,
    *,
    knowledge_path: str | Path | None = None,
) -> tuple[object, ...]:
    """Rebuild and persist repository knowledge facts derived from summaries."""

    summaries = _collect_repository_summaries(snapshot)
    facts = _merge_knowledge_facts(
        derive_facts_from_summaries(summaries),
        derive_facts_from_contracts(snapshot.function_contracts),
    )
    path = Path(knowledge_path) if knowledge_path is not None else snapshot.root / "data" / "knowledge.json"
    KnowledgeBase(path).save(facts)
    return facts


def draft_function_contracts(
    snapshot: RepositorySnapshot,
) -> tuple[FunctionContract, ...]:
    """Generate review-only contract drafts inferred from current AST-safe helpers."""

    source_texts = tuple(read_lua_source_text(file_path) for file_path in snapshot.lua_files)
    existing_names = {contract.qualified_name for contract in snapshot.function_contracts}
    drafts: list[FunctionContract] = []
    seen: set[str] = set()

    for contract in collect_inline_guard_contracts(source_texts, allow_local=False):
        if contract.qualified_name in existing_names or contract.qualified_name in seen:
            continue
        drafts.append(
            FunctionContract(
                qualified_name=contract.qualified_name,
                returns_non_nil=False,
                ensures_non_nil_args=contract.ensures_non_nil_args,
                notes="draft:ast_inlined_guard_helper",
            )
        )
        seen.add(contract.qualified_name)

    for qualified_name, mapping in collect_transparent_return_wrappers(
        source_texts,
        allow_local=False,
    ).items():
        if qualified_name in existing_names or qualified_name in seen:
            continue
        draft = _draft_contract_from_wrapper_mapping(qualified_name, mapping)
        if draft is None:
            continue
        drafts.append(draft)
        seen.add(qualified_name)

    drafts.sort(key=lambda contract: contract.qualified_name)
    return tuple(drafts)


def draft_review_improvements(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> tuple[ImprovementProposal, ...]:
    """Generate draft-only follow-up proposals from unresolved or medium-confidence reviews."""

    assessments = review_repository(snapshot)
    if not assessments:
        return ()

    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    adjudication_backend = backend or HeuristicAdjudicationBackend()
    verdicts = _run_review_from_assessments(
        snapshot,
        assessments,
        adjudication_backend=adjudication_backend,
        summary_text_by_name=summary_text_by_name,
        function_context_by_name=function_context_by_name,
        file_module_by_path=file_module_by_path,
        facts=facts,
    )
    verdict_by_case_id = {verdict.case_id: verdict for verdict in verdicts}
    draft_contract_by_name = {
        contract.qualified_name: contract for contract in draft_function_contracts(snapshot)
    }
    recognized_helpers = _recognized_helper_names(snapshot)
    local_recognized_helpers = _local_recognized_helper_names(snapshot)

    proposals: list[ImprovementProposal] = []
    seen: set[tuple[str, str, str]] = set()
    known_draft_names = frozenset(draft_contract_by_name)

    for assessment in assessments:
        verdict = verdict_by_case_id[assessment.candidate.case_id]
        if verdict.status != "uncertain" and verdict.confidence != "medium":
            continue

        evidence = assessment.static_analysis.origin_candidates or (assessment.candidate.expression,)
        unknown_reason = (
            assessment.static_analysis.unknown_reason
            or assessment.static_analysis.origin_unknown_reason
        )
        if unknown_reason is not None:
            key = ("ast_pattern", assessment.candidate.case_id, unknown_reason)
            if key not in seen:
                proposals.append(
                    ImprovementProposal(
                        kind="ast_pattern",
                        case_id=assessment.candidate.case_id,
                        file=assessment.candidate.file,
                        status=verdict.status,
                        confidence=verdict.confidence,
                        reason=(
                            f"structured fallback `{unknown_reason}` blocked a conclusive proof; "
                            "consider adding a bounded AST pattern"
                        ),
                        suggested_pattern=unknown_reason,
                        evidence=evidence,
                    )
                )
                seen.add(key)

        current_module = file_module_by_path.get(_normalize_path_key(assessment.candidate.file))
        known_helper_names = recognized_helpers | local_recognized_helpers.get(
            assessment.candidate.file,
            frozenset(),
        )
        related_names = _related_functions_from_assessment(
            assessment,
            current_module=current_module,
            known_function_names=known_draft_names | known_helper_names,
        )
        for function_name in related_names:
            if function_name in draft_contract_by_name:
                key = ("function_contract", assessment.candidate.case_id, function_name)
                if key in seen:
                    continue
                proposals.append(
                    ImprovementProposal(
                        kind="function_contract",
                        case_id=assessment.candidate.case_id,
                        file=assessment.candidate.file,
                        status=verdict.status,
                        confidence=verdict.confidence,
                        reason=(
                            f"unresolved case references `{function_name}`; "
                            "review the inferred contract draft before promoting it"
                        ),
                        suggested_contract=draft_contract_by_name[function_name],
                        evidence=evidence,
                    )
                )
                seen.add(key)
                continue

            if function_name in known_helper_names:
                continue
            key = ("wrapper_recognizer", assessment.candidate.case_id, function_name)
            if key in seen:
                continue
            proposals.append(
                ImprovementProposal(
                    kind="wrapper_recognizer",
                    case_id=assessment.candidate.case_id,
                    file=assessment.candidate.file,
                    status=verdict.status,
                    confidence=verdict.confidence,
                    reason=(
                        f"`{function_name}` participates in an unresolved call chain; "
                        "consider adding a bounded wrapper/helper recognizer"
                    ),
                    suggested_pattern=function_name,
                    evidence=evidence,
                )
            )
            seen.add(key)

    proposals.sort(key=lambda proposal: (proposal.file, proposal.case_id, proposal.kind, proposal.reason))
    return tuple(proposals)


def summarize_improvement_proposals(
    proposals: tuple[ImprovementProposal, ...],
) -> ImprovementAnalytics:
    """Aggregate proposal counts into a stable analytics summary."""

    kind_counts = Counter(proposal.kind for proposal in proposals)
    reason_counts = Counter(proposal.suggested_pattern or proposal.reason for proposal in proposals)
    unresolved_kind_counts = Counter(
        proposal.kind for proposal in proposals if proposal.status == "uncertain"
    )
    medium_reportable_kind_counts = Counter(
        proposal.kind
        for proposal in proposals
        if proposal.status.startswith("risky") and proposal.confidence == "medium"
    )
    pattern_counts = Counter(
        proposal.suggested_pattern
        for proposal in proposals
        if proposal.suggested_pattern
    )
    contract_counts = Counter(
        proposal.suggested_contract.qualified_name
        for proposal in proposals
        if proposal.suggested_contract is not None
    )

    def _ordered(counter: Counter[str]) -> tuple[tuple[str, int], ...]:
        return tuple(
            sorted(
                counter.items(),
                key=lambda item: (-item[1], item[0]),
            )
        )

    return ImprovementAnalytics(
        total_proposals=len(proposals),
        unique_cases=len({proposal.case_id for proposal in proposals}),
        unresolved_proposals=sum(1 for proposal in proposals if proposal.status == "uncertain"),
        medium_reportable_proposals=sum(
            1
            for proposal in proposals
            if proposal.status.startswith("risky") and proposal.confidence == "medium"
        ),
        by_kind=_ordered(kind_counts),
        by_reason=_ordered(reason_counts),
        by_pattern=_ordered(pattern_counts),
        by_contract=_ordered(contract_counts),
        unresolved_by_kind=_ordered(unresolved_kind_counts),
        medium_reportable_by_kind=_ordered(medium_reportable_kind_counts),
    )


def analyze_review_improvements(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
) -> ImprovementAnalytics:
    """Run review-improvement draft generation and return aggregate analytics."""

    proposals = draft_review_improvements(
        snapshot,
        backend=backend,
        knowledge_path=knowledge_path,
    )
    return summarize_improvement_proposals(proposals)


def export_adjudication_tasks(
    snapshot: RepositorySnapshot,
    *,
    knowledge_path: str | Path | None = None,
    output_path: str | Path | None = None,
    skill_path: str | Path | None = None,
    strict_skill: bool = True,
) -> tuple[dict[str, object], ...]:
    """Export agent-ready prompt tasks for all collected candidates."""

    sink_rule_by_id = {rule.id: rule for rule in snapshot.sink_rules}
    summaries = _collect_repository_summaries(snapshot)
    summary_text_by_name = _build_summary_text_index(summaries)
    function_context_by_name = _build_function_context_index(snapshot, summaries)
    file_module_by_path = _build_file_module_index(snapshot)
    facts = _load_knowledge_facts(snapshot, knowledge_path)
    transparent_return_wrappers = _collect_snapshot_transparent_return_wrappers(snapshot)
    inline_guard_contracts = _collect_snapshot_inline_guard_contracts(snapshot)
    tasks: list[dict[str, object]] = []

    for file_path in snapshot.lua_files:
        source = read_lua_source_text(file_path)
        for assessment in review_source(
            file_path,
            source,
            snapshot.sink_rules,
            function_contracts=snapshot.function_contracts,
            transparent_return_wrappers=transparent_return_wrappers,
            inline_guard_contracts=inline_guard_contracts,
        ):
            related_evidence = _build_related_evidence(
                assessment,
                summary_text_by_name=summary_text_by_name,
                function_context_by_name=function_context_by_name,
                file_module_by_path=file_module_by_path,
                budget=_FIRST_HOP_RELATED_EVIDENCE_BUDGET,
            )
            knowledge_facts = tuple(
                _knowledge_facts_for_assessment(
                    assessment,
                    related_evidence.function_names,
                    facts,
                    function_contracts=snapshot.function_contracts,
                    current_module=file_module_by_path.get(_normalize_path_key(assessment.candidate.file)),
                    source=source,
                )
            )
            packet = prepare_evidence_packet(
                assessment,
                source,
                related_functions=related_evidence.function_names,
                function_summaries=related_evidence.summary_texts,
                knowledge_facts=knowledge_facts,
                related_function_contexts=related_evidence.context_texts,
            )
            sink_rule = sink_rule_by_id[assessment.candidate.sink_rule_id]
            tasks.append(
                {
                    "case_id": assessment.candidate.case_id,
                    "sink_rule_id": sink_rule.id,
                    "file": assessment.candidate.file,
                    "line": assessment.candidate.line,
                    "function_scope": assessment.candidate.function_scope,
                    "prompt": build_adjudication_prompt(
                        packet=packet,
                        sink_rule=sink_rule,
                        skill_path=skill_path,
                        strict_skill=strict_skill,
                    ),
                }
            )

    task_tuple = tuple(tasks)
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(task_tuple, indent=2, sort_keys=True), encoding="utf-8")
    return task_tuple


def export_autofix_patches(
    snapshot: RepositorySnapshot,
    *,
    backend: AdjudicationBackend | None = None,
    knowledge_path: str | Path | None = None,
    output_path: str | Path | None = None,
    audit_mode: bool = False,
) -> tuple[AutofixPatch, ...]:
    """Export machine-applicable autofix patches for current reportable findings."""

    verdicts = run_repository_review(
        snapshot,
        backend=backend,
        knowledge_path=knowledge_path,
    )
    patches = tuple(
        verdict.autofix_patch
        for verdict in verdicts
        if verdict.autofix_patch is not None
        and should_report(verdict, snapshot.confidence_policy, audit_mode=audit_mode)
    )
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps([_serialize_autofix_patch(patch) for patch in patches], indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return patches


def clear_backend_cache(cache_path: str | Path) -> int:
    """Remove a persisted backend cache file and return the removed entry count."""

    path = Path(cache_path)
    if not path.exists():
        return 0

    removed_entries = 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        removed_entries = len(payload)

    path.unlink()
    return removed_entries


def apply_autofix_manifest(
    manifest_path: str | Path,
    *,
    dry_run: bool = False,
    case_ids: tuple[str, ...] = (),
    file_paths: tuple[str | Path, ...] = (),
) -> tuple[tuple[AutofixPatch, ...], tuple[str, ...]]:
    """Apply an exported autofix manifest with per-file conflict checks."""

    patches = _filter_autofix_patches(
        _load_autofix_manifest(manifest_path),
        case_ids=case_ids,
        file_paths=file_paths,
    )
    grouped: dict[Path, list[AutofixPatch]] = {}
    for patch in patches:
        grouped.setdefault(Path(patch.file), []).append(patch)

    applied: list[AutofixPatch] = []
    conflicts: list[str] = []

    for file_path, file_patches in grouped.items():
        file_applied, file_conflicts = _apply_autofix_group(
            file_path,
            tuple(file_patches),
            dry_run=dry_run,
        )
        applied.extend(file_applied)
        conflicts.extend(file_conflicts)

    return tuple(applied), tuple(conflicts)


def export_autofix_unified_diff(
    manifest_path: str | Path,
    *,
    output_path: str | Path | None = None,
    case_ids: tuple[str, ...] = (),
    file_paths: tuple[str | Path, ...] = (),
) -> tuple[str, tuple[str, ...]]:
    """Render a unified diff from an exported autofix manifest."""

    patches = _filter_autofix_patches(
        _load_autofix_manifest(manifest_path),
        case_ids=case_ids,
        file_paths=file_paths,
    )
    grouped: dict[Path, list[AutofixPatch]] = {}
    for patch in patches:
        grouped.setdefault(Path(patch.file), []).append(patch)

    diffs: list[str] = []
    conflicts: list[str] = []

    for file_path, file_patches in grouped.items():
        original_text, updated_text, _, file_conflicts = _simulate_autofix_group(
            file_path,
            tuple(file_patches),
        )
        if file_conflicts:
            conflicts.extend(file_conflicts)
            continue
        if original_text == updated_text:
            continue
        diff_text = _build_unified_diff(file_path, original_text, updated_text)
        if diff_text:
            diffs.append(diff_text)

    if conflicts:
        return "", tuple(conflicts)

    rendered = "\n".join(diffs).rstrip()
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"{rendered}\n" if rendered else "", encoding="utf-8")
    return rendered, ()


def _collect_repository_summaries(snapshot: RepositorySnapshot) -> tuple[object, ...]:
    summaries: list[object] = []
    for file_path in snapshot.lua_files:
        source = read_lua_source_text(file_path)
        summaries.extend(summarize_source(file_path, source))
    return tuple(summaries)


def _collect_snapshot_transparent_return_wrappers(
    snapshot: RepositorySnapshot,
) -> dict[str, tuple[tuple[int, int], ...]]:
    return collect_transparent_return_wrappers(
        tuple(read_lua_source_text(file_path) for file_path in snapshot.lua_files),
        allow_local=False,
    )


def _collect_snapshot_inline_guard_contracts(
    snapshot: RepositorySnapshot,
) -> tuple[object, ...]:
    return collect_inline_guard_contracts(
        tuple(read_lua_source_text(file_path) for file_path in snapshot.lua_files),
        allow_local=False,
    )


def _collect_snapshot_maybe_nil_return_helpers(
    snapshot: RepositorySnapshot,
) -> dict[str, tuple[tuple[int, int], ...]]:
    return collect_maybe_nil_return_helpers(_collect_repository_summaries(snapshot))


def _collect_snapshot_coalescing_return_helpers(
    snapshot: RepositorySnapshot,
) -> dict[str, tuple[tuple[int, int, int], ...]]:
    return collect_coalescing_return_helpers(_collect_repository_summaries(snapshot))


def _recognized_helper_names(snapshot: RepositorySnapshot) -> frozenset[str]:
    helper_names = set(_collect_snapshot_transparent_return_wrappers(snapshot))
    helper_names.update(
        contract.qualified_name for contract in _collect_snapshot_inline_guard_contracts(snapshot)
    )
    return frozenset(helper_names)


def _local_recognized_helper_names(
    snapshot: RepositorySnapshot,
) -> dict[str, frozenset[str]]:
    helper_names_by_file: dict[str, frozenset[str]] = {}
    for file_path in snapshot.lua_files:
        source = read_lua_source_text(file_path)
        helper_names = set(collect_transparent_return_wrappers((source,), allow_local=True))
        helper_names.update(
            contract.qualified_name
            for contract in collect_inline_guard_contracts((source,), allow_local=True)
        )
        helper_names_by_file[str(file_path)] = frozenset(helper_names)
    return helper_names_by_file


def _draft_contract_from_wrapper_mapping(
    qualified_name: str,
    mapping: tuple[tuple[int, int], ...],
) -> FunctionContract | None:
    first_slot = next((arg_index for slot, arg_index in mapping if slot == 1), None)
    if first_slot is None:
        return None
    if first_slot == 0:
        return FunctionContract(
            qualified_name=qualified_name,
            returns_non_nil=True,
            notes="draft:ast_defaulting_wrapper",
        )
    if first_slot < 1:
        return None
    return FunctionContract(
        qualified_name=qualified_name,
        returns_non_nil=False,
        returns_non_nil_from_args=(first_slot,),
        returns_non_nil_from_args_by_return_slot=((1, (first_slot,)),),
        notes="draft:ast_wrapper_passthrough",
    )


def _load_autofix_manifest(manifest_path: str | Path) -> tuple[AutofixPatch, ...]:
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("autofix manifest must be a JSON array")
    return tuple(_deserialize_autofix_patch(item) for item in payload)


def _deserialize_autofix_patch(payload: object) -> AutofixPatch:
    if not isinstance(payload, dict):
        raise ValueError("autofix manifest entries must be JSON objects")

    required_string_keys = ("case_id", "file", "action", "replacement")
    for key in required_string_keys:
        value = payload.get(key)
        if not isinstance(value, str):
            raise ValueError(f"autofix patch field {key} must be a string")

    start_line = payload.get("start_line")
    end_line = payload.get("end_line")
    if not isinstance(start_line, int) or not isinstance(end_line, int):
        raise ValueError("autofix patch start_line and end_line must be integers")

    expected_original = payload.get("expected_original", "")
    if not isinstance(expected_original, str):
        raise ValueError("autofix patch expected_original must be a string")

    return AutofixPatch(
        case_id=payload["case_id"],
        file=payload["file"],
        action=payload["action"],
        start_line=start_line,
        end_line=end_line,
        replacement=payload["replacement"],
        expected_original=expected_original,
    )


def _filter_autofix_patches(
    patches: tuple[AutofixPatch, ...],
    *,
    case_ids: tuple[str, ...] = (),
    file_paths: tuple[str | Path, ...] = (),
) -> tuple[AutofixPatch, ...]:
    case_filter = set(case_ids)
    file_filter = {_normalize_path_key(file_path) for file_path in file_paths}
    filtered: list[AutofixPatch] = []

    for patch in patches:
        if case_filter and patch.case_id not in case_filter:
            continue
        if file_filter and _normalize_path_key(patch.file) not in file_filter:
            continue
        filtered.append(patch)
    return tuple(filtered)


def _apply_autofix_group(
    file_path: Path,
    patches: tuple[AutofixPatch, ...],
    *,
    dry_run: bool = False,
) -> tuple[tuple[AutofixPatch, ...], tuple[str, ...]]:
    original_text, updated_text, applied, conflicts = _simulate_autofix_group(file_path, patches)
    if conflicts:
        return (), conflicts

    if dry_run:
        return applied, ()

    file_path.write_text(updated_text, encoding="utf-8")
    return applied, ()


def _build_summary_text_index(summaries: tuple[object, ...]) -> dict[str, tuple[str, ...]]:
    index: dict[str, list[str]] = {}
    for summary in summaries:
        text = (
            f"{summary.qualified_name} params={summary.params} "
            f"guards={list(summary.guards)} returns={list(summary.returns)}"
        )
        index.setdefault(summary.qualified_name, []).append(text)
    return {key: tuple(value) for key, value in index.items()}


def _build_function_context_index(
    snapshot: RepositorySnapshot,
    summaries: tuple[object, ...],
) -> dict[str, tuple[_FunctionContextBlock, ...]]:
    path_lookup = {str(path): path for path in snapshot.lua_files}
    source_lookup: dict[str, str] = {}
    index: dict[str, list[_FunctionContextBlock]] = {}
    known_function_names = {
        summary.qualified_name
        for summary in summaries
        if isinstance(getattr(summary, "qualified_name", None), str)
    }

    for summary in summaries:
        path_key = str(summary.file)
        file_path = path_lookup.get(path_key, Path(path_key))
        if path_key not in source_lookup:
            try:
                source_lookup[path_key] = read_lua_source_text(file_path)
            except OSError:
                continue
        snippet, callees = _extract_function_context_snippet(
            source_lookup[path_key],
            summary.line,
            summary.module_name,
            known_function_names,
        )
        if not snippet:
            continue
        rendered = "\n".join(
            [
                f"{summary.qualified_name} @ {summary.file}:{summary.line}",
                snippet,
            ]
        )
        index.setdefault(summary.qualified_name, []).append(
            _FunctionContextBlock(
                qualified_name=summary.qualified_name,
                file=str(summary.file),
                line=summary.line,
                evidence_score=_summary_evidence_score(summary),
                rendered=rendered,
                callees=callees,
            )
        )

    return {key: tuple(value) for key, value in index.items()}


def _extract_function_context_snippet(
    source: str,
    start_line: int,
    module_name: str | None,
    known_function_names: set[str],
) -> tuple[str, tuple[str, ...]]:
    lines = source.splitlines()
    start_index = max(0, start_line - 1)
    if start_index >= len(lines):
        return "", ()

    snippet_lines = [lines[start_index]]
    callee_names: list[str] = []
    depth = 1
    index = start_index + 1

    while index < len(lines):
        line = lines[index]
        snippet_lines.append(line)
        callee_names.extend(
            _call_names_from_line(
                line,
                default_module=module_name,
                known_function_names=known_function_names,
            )
        )
        depth += _opened_block_count(line)
        depth -= _closed_block_count(line)
        if depth <= 0:
            break
        index += 1

    while snippet_lines and not snippet_lines[-1].strip():
        snippet_lines.pop()
    return "\n".join(snippet_lines), tuple(dict.fromkeys(callee_names))


def _summary_evidence_score(summary: object) -> int:
    score = 0
    guards = getattr(summary, "guards", ())
    returns = getattr(summary, "returns", ())
    if isinstance(guards, tuple) and guards:
        score += 2
    if isinstance(returns, tuple) and returns:
        score += 1
    return score


def _build_related_evidence(
    assessment: CandidateAssessment,
    *,
    summary_text_by_name: dict[str, tuple[str, ...]],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    file_module_by_path: dict[str, str | None],
    budget: _RelatedEvidenceBudget = _FIRST_HOP_RELATED_EVIDENCE_BUDGET,
) -> _RelatedEvidenceSelection:
    current_file_key = _normalize_path_key(assessment.candidate.file)
    known_function_names = frozenset(
        set(summary_text_by_name) | set(function_context_by_name)
    )
    direct_related_functions = _related_functions_from_assessment(
        assessment,
        current_module=file_module_by_path.get(current_file_key),
        known_function_names=known_function_names,
    )
    ordered_functions, depth_by_function = _expand_related_functions(
        direct_related_functions,
        function_context_by_name,
        max_depth=budget.max_depth,
    )
    selected_contexts = _select_related_function_contexts(
        ordered_functions,
        depth_by_function=depth_by_function,
        function_context_by_name=function_context_by_name,
        current_file=assessment.candidate.file,
        max_contexts=budget.max_contexts,
        max_context_lines=budget.max_context_lines,
    )

    function_names: list[str] = list(direct_related_functions)
    for qualified_name, _ in selected_contexts:
        if qualified_name not in function_names:
            function_names.append(qualified_name)
    for qualified_name in ordered_functions:
        if qualified_name in function_names:
            continue
        if summary_text_by_name.get(qualified_name):
            function_names.append(qualified_name)

    summary_texts = _select_function_summaries(
        tuple(function_names),
        summary_text_by_name=summary_text_by_name,
        max_items=budget.max_summary_items,
    )
    context_texts = tuple(rendered for _, rendered in selected_contexts)

    return _RelatedEvidenceSelection(
        function_names=tuple(function_names),
        summary_texts=summary_texts,
        context_texts=context_texts,
    )


def _knowledge_facts_for_assessment(
    assessment: CandidateAssessment,
    related_functions: tuple[str, ...],
    facts: tuple[object, ...],
    *,
    function_contracts: tuple[object, ...] = (),
    current_module: str | None = None,
    source: str | None = None,
) -> tuple[object, ...]:
    current_top_level_phase = _top_level_phase_for_assessment(assessment, source)
    current_scope_kind = _scope_kind_for_function_scope(assessment.candidate.function_scope)
    applicable_contracts = tuple(
        contract
        for contract in function_contracts
        if contract_applies_in_module(contract, current_module)
        and contract_applies_in_function_scope(
            contract,
            assessment.candidate.function_scope,
        )
        and contract_applies_to_top_level_phase(contract, current_top_level_phase)
        and contract_applies_to_scope_kind(
            contract,
            current_scope_kind,
        )
        and contract_applies_to_sink(
            contract,
            current_sink_rule_id=assessment.candidate.sink_rule_id,
            current_sink_name=assessment.candidate.sink_name,
        )
    )
    fact_texts = list(
        fact
        for subject in related_functions + (assessment.candidate.function_scope,)
        for fact in facts_for_subject(facts, subject)
    )
    call_contexts_by_function = _contract_calls_from_assessment(
        assessment,
        current_module=current_module,
        known_function_names=frozenset(contract.qualified_name for contract in applicable_contracts),
    )
    scoped_contract_statements = [
        fact.statement
        for fact in derive_facts_from_contracts(
            applicable_contracts,
            current_module=current_module,
            current_function_scope=assessment.candidate.function_scope,
            current_top_level_phase=current_top_level_phase,
            current_scope_kind=current_scope_kind,
            current_sink_rule_id=assessment.candidate.sink_rule_id,
            current_sink_name=assessment.candidate.sink_name,
        )
        if fact.subject in related_functions
    ]
    for contract in applicable_contracts:
        if not contract.returns_non_nil:
            continue
        if contract.qualified_name not in related_functions:
            continue
        if not (
            contract.applies_to_call_roles
            or contract.applies_to_usage_modes
            or contract.applies_to_return_slots
            or contract.applies_with_arg_count
            or contract.required_literal_args
            or contract.required_arg_shapes
            or contract.required_arg_roots
            or contract.required_arg_prefixes
            or contract.required_arg_access_paths
        ):
            continue
        call_contexts = call_contexts_by_function.get(contract.qualified_name, ())
        if not any(
            contract_applies_to_call(
                contract,
                arg_count=len(args),
                arg_values=args,
                call_role=call_role,
                usage_mode=usage_mode,
                return_slot=return_slot,
            )
            for args, call_role, usage_mode, return_slot in call_contexts
        ):
            continue
        scoped_contract_statements.append(
            f"{contract.qualified_name} returns non-nil value"
        )
    for fact in scoped_contract_statements:
        fact_texts.append(fact)
    return tuple(dict.fromkeys(fact_texts))


def _should_retry_with_expanded_evidence(
    backend: AdjudicationBackend,
    adjudication: AdjudicationRecord,
    verdict: Verdict,
) -> bool:
    if verdict.status != "uncertain":
        return False
    if not _supports_expanded_evidence_retry(backend):
        return False
    return "expand_context" in {
        adjudication.prosecutor.recommended_next_action,
        adjudication.defender.recommended_next_action,
    }


def _supports_expanded_evidence_retry(backend: AdjudicationBackend) -> bool:
    if isinstance(backend, CliAgentBackend):
        explicit_setting = getattr(backend, "expanded_evidence_retry", None)
        if isinstance(explicit_setting, bool):
            return explicit_setting
        max_attempts = getattr(backend, "max_attempts", 1)
        return isinstance(max_attempts, int) and max_attempts == 1
    return bool(getattr(backend, "supports_expanded_evidence_retry", False))


def _select_function_summaries(
    function_names: tuple[str, ...],
    *,
    summary_text_by_name: dict[str, tuple[str, ...]],
    max_items: int,
) -> tuple[str, ...]:
    selected: list[str] = []
    for function_name in function_names:
        for summary_text in summary_text_by_name.get(function_name, ()):
            if len(selected) >= max_items:
                return tuple(selected)
            selected.append(summary_text)
    return tuple(selected)


def _select_related_function_contexts(
    ordered_functions: tuple[str, ...],
    *,
    depth_by_function: dict[str, int],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    current_file: str,
    max_contexts: int,
    max_context_lines: int,
) -> tuple[tuple[str, str], ...]:
    candidates: list[_FunctionContextBlock] = []
    current_file_key = _normalize_path_key(current_file)
    function_order = {name: index for index, name in enumerate(ordered_functions)}

    for function_name in ordered_functions:
        candidates.extend(function_context_by_name.get(function_name, ()))

    candidates.sort(
        key=lambda block: (
            depth_by_function.get(block.qualified_name, max(function_order.values(), default=0) + 1),
            0 if _normalize_path_key(block.file) == current_file_key else 1,
            -block.evidence_score,
            function_order.get(block.qualified_name, len(function_order)),
            block.line,
            block.file,
        )
    )

    selected: list[tuple[str, str]] = []
    seen_contexts: set[str] = set()
    used_lines = 0

    for block in candidates:
        if len(selected) >= max_contexts:
            break
        if block.rendered in seen_contexts:
            continue

        remaining_lines = max_context_lines - used_lines
        if remaining_lines <= 0:
            break

        rendered = block.rendered
        block_line_count = len(rendered.splitlines())
        if block_line_count > remaining_lines:
            if remaining_lines < 3:
                break
            rendered = _truncate_context_text(rendered, remaining_lines)

        selected.append((block.qualified_name, rendered))
        seen_contexts.add(block.rendered)
        used_lines += len(rendered.splitlines())

    return tuple(selected)


def _truncate_context_text(rendered: str, max_lines: int) -> str:
    lines = rendered.splitlines()
    if len(lines) <= max_lines:
        return rendered
    if max_lines <= 1:
        return lines[0]
    truncated = lines[: max_lines - 1]
    truncated.append(_TRUNCATED_CONTEXT_MARKER)
    return "\n".join(truncated)


def _call_names_from_line(
    line: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, ...]:
    code = _strip_lua_comment(line)
    if not code.strip():
        return ()
    if detect_required_module_line(code) is not None:
        return ()
    if re.match(r"^\s*(?:local\s+)?function\b", code):
        return ()
    names = []
    for match in _INLINE_CALL_RE.finditer(code):
        raw_name = match.group(1)
        short_name = raw_name.rsplit(".", 1)[-1].rsplit(":", 1)[-1]
        if short_name in _LUA_KEYWORDS:
            continue
        if raw_name == "require":
            continue
        names.append(
            _resolve_related_name(
                raw_name,
                default_module=default_module,
                known_function_names=known_function_names,
            )
        )
    return tuple(dict.fromkeys(names))


def _opened_block_count(line: str) -> int:
    code = _strip_lua_comment(line).strip()
    if not code:
        return 0

    count = 0
    if _FUNCTION_BLOCK_RE.search(code):
        count += len(_FUNCTION_BLOCK_RE.findall(code))

    control_match = _CONTROL_FLOW_START_RE.match(code)
    if control_match is not None:
        keyword = control_match.group(1)
        if keyword == "if" and re.search(r"\bthen\b", code):
            count += 1
        elif keyword in {"for", "while"} and re.search(r"\bdo\b", code):
            count += 1
    elif code == "do":
        count += 1

    if re.match(r"^\s*repeat\b", code):
        count += 1

    return count


def _closed_block_count(line: str) -> int:
    code = _strip_lua_comment(line)
    if not code.strip():
        return 0
    return len(re.findall(r"\bend\b", code)) + len(re.findall(r"\buntil\b", code))


def _strip_lua_comment(line: str) -> str:
    return line.partition("--")[0]


def _load_knowledge_facts(
    snapshot: RepositorySnapshot,
    knowledge_path: str | Path | None,
) -> tuple[object, ...]:
    path = Path(knowledge_path) if knowledge_path is not None else snapshot.root / "data" / "knowledge.json"
    return KnowledgeBase(path).load()


def _merge_knowledge_facts(*fact_groups: tuple[object, ...]) -> tuple[object, ...]:
    merged: list[object] = []
    seen: set[tuple[object, object, object]] = set()

    for group in fact_groups:
        for fact in group:
            key = (
                getattr(fact, "key", None),
                getattr(fact, "subject", None),
                getattr(fact, "statement", None),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(fact)
    return tuple(merged)


def _expected_benchmark_label(file_path: str) -> str | None:
    name = Path(file_path).name
    if name.startswith("provable_risky_"):
        return "risky"
    if name.startswith("provable_safe_"):
        return "safe"
    if name.startswith("provable_uncertain_"):
        return "uncertain"
    return None


def _normalize_benchmark_status(status: str) -> str:
    if status in {"risky", "risky_verified"}:
        return "risky"
    if status in {"safe", "safe_verified"}:
        return "safe"
    return "uncertain"


def _extract_backend_failure_reason(verdict: Verdict) -> str | None:
    if verdict.status != "uncertain":
        return None
    for item in verdict.counterarguments_considered:
        if item.startswith("CLI backend command"):
            return item
    return None


def _backend_metric(backend: object, name: str) -> int:
    value = getattr(backend, name, 0)
    if isinstance(value, int) and value >= 0:
        return value
    return 0


def _backend_float_metric(backend: object, name: str) -> float:
    value = getattr(backend, name, 0.0)
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return 0.0


def _backend_name(backend: object) -> str:
    provider_spec = getattr(backend, "provider_spec", None)
    if isinstance(provider_spec, AgentProviderSpec):
        return provider_spec.name
    name = backend.__class__.__name__
    if name == "HeuristicAdjudicationBackend":
        return "heuristic"
    if name == "CodexCliBackend":
        return "codex"
    if name == "CodeAgentCliBackend":
        return "codeagent"
    return name


def _backend_optional_string(backend: object, name: str) -> str | None:
    value = getattr(backend, name, None)
    if isinstance(value, str):
        return value
    return None


def _serialize_autofix_patch(patch: AutofixPatch) -> dict[str, object]:
    return {
        "case_id": patch.case_id,
        "file": patch.file,
        "action": patch.action,
        "start_line": patch.start_line,
        "end_line": patch.end_line,
        "replacement": patch.replacement,
        "expected_original": patch.expected_original,
    }


def _simulate_autofix_group(
    file_path: Path,
    patches: tuple[AutofixPatch, ...],
) -> tuple[str, str, tuple[AutofixPatch, ...], tuple[str, ...]]:
    if not file_path.exists():
        conflicts = tuple(f"{patch.case_id}: target file not found: {file_path}" for patch in patches)
        return "", "", (), conflicts

    original_text = read_lua_source_text(file_path)
    trailing_newline = original_text.endswith("\n")
    trial_lines = original_text.splitlines()
    applied: list[AutofixPatch] = []
    conflicts: list[str] = []

    ordered = sorted(patches, key=lambda patch: (patch.start_line, patch.end_line), reverse=True)
    for patch in ordered:
        conflict = _validate_autofix_patch(trial_lines, patch)
        if conflict is not None:
            conflicts.append(f"{patch.case_id}: {conflict}")
            continue
        _apply_autofix_patch_to_lines(trial_lines, patch)
        applied.append(patch)

    if conflicts:
        return original_text, original_text, (), tuple(conflicts)

    updated_text = _render_text_from_lines(trial_lines, trailing_newline=trailing_newline)
    return original_text, updated_text, tuple(applied), ()


def _build_unified_diff(file_path: Path, original_text: str, updated_text: str) -> str:
    original_lines = original_text.splitlines()
    updated_lines = updated_text.splitlines()
    diff_lines = list(
        difflib.unified_diff(
            original_lines,
            updated_lines,
            fromfile=str(file_path),
            tofile=str(file_path),
            lineterm="",
        )
    )
    return "\n".join(diff_lines)


def _normalize_path_key(path: str | Path) -> str:
    return str(Path(path).resolve(strict=False))


def _resolve_snapshot_lua_file(snapshot: RepositorySnapshot, file_path: str | Path) -> Path:
    target_key = _normalize_path_key(file_path)
    for candidate in snapshot.lua_files:
        if _normalize_path_key(candidate) == target_key:
            return candidate
    raise ValueError(f"File is not a discovered Lua source in repository: {file_path}")


def _render_text_from_lines(lines: list[str], *, trailing_newline: bool) -> str:
    rendered = "\n".join(lines)
    if trailing_newline:
        return f"{rendered}\n"
    return rendered


def _validate_autofix_patch(lines: list[str], patch: AutofixPatch) -> str | None:
    if patch.start_line < 1 or patch.end_line < patch.start_line:
        return "invalid patch line range"
    if patch.action not in {"insert_before", "replace_range"}:
        return f"unsupported patch action: {patch.action}"
    if not patch.expected_original:
        return "patch is missing expected_original"

    start_index = patch.start_line - 1
    end_index = patch.end_line

    if patch.action == "insert_before":
        if start_index >= len(lines):
            return "anchor line is out of range"
        current = lines[start_index]
        if current != patch.expected_original:
            return "anchor line no longer matches expected_original"
        return None

    if end_index > len(lines):
        return "replace range is out of range"
    current = "\n".join(lines[start_index:end_index])
    if current != patch.expected_original:
        return "replace range no longer matches expected_original"
    return None


def _apply_autofix_patch_to_lines(lines: list[str], patch: AutofixPatch) -> None:
    start_index = patch.start_line - 1
    replacement_lines = patch.replacement.splitlines()

    if patch.action == "insert_before":
        lines[start_index:start_index] = replacement_lines
        return

    end_index = patch.end_line
    lines[start_index:end_index] = replacement_lines


def _expand_related_functions(
    related_functions: tuple[str, ...],
    function_context_by_name: dict[str, tuple[_FunctionContextBlock, ...]],
    *,
    max_depth: int,
) -> tuple[tuple[str, ...], dict[str, int]]:
    ordered: list[str] = []
    depth_by_function: dict[str, int] = {}
    queue = [(function_name, 0) for function_name in tuple(dict.fromkeys(related_functions))]

    while queue:
        function_name, depth = queue.pop(0)
        if function_name in depth_by_function:
            continue
        depth_by_function[function_name] = depth
        ordered.append(function_name)
        if depth >= max_depth:
            continue
        for context in function_context_by_name.get(function_name, ()):
            for callee in context.callees:
                if callee in depth_by_function or callee not in function_context_by_name:
                    continue
                queue.append((callee, depth + 1))

    return tuple(ordered), depth_by_function


def _related_functions_from_assessment(
    assessment: CandidateAssessment,
    *,
    current_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, ...]:
    related: list[str] = []
    for origin in assessment.static_analysis.origin_candidates:
        resolved = _call_name_from_expression(
            origin,
            default_module=current_module,
            known_function_names=known_function_names,
        )
        if resolved is not None:
            related.append(resolved)
    return tuple(dict.fromkeys(related))


def _call_name_from_expression(
    expression: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> str | None:
    match = _CALL_RE.match(expression)
    if match is None:
        return None
    return _resolve_related_name(
        match.group(1),
        default_module=default_module,
        known_function_names=known_function_names,
    )


def _contract_calls_from_assessment(
    assessment: CandidateAssessment,
    *,
    current_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> dict[str, tuple[tuple[tuple[str, ...], str, str | None, int | None], ...]]:
    call_args: dict[str, list[tuple[tuple[str, ...], str, str | None, int | None]]] = {}
    usage_modes = assessment.static_analysis.origin_usage_modes
    return_slots = assessment.static_analysis.origin_return_slots
    for index, origin in enumerate(assessment.static_analysis.origin_candidates):
        parsed = _parse_call_expression(
            origin,
            default_module=current_module,
            known_function_names=known_function_names,
        )
        if parsed is None:
            continue
        function_name, args = parsed
        usage_mode = usage_modes[index] if index < len(usage_modes) else _usage_mode_for_origin(
            assessment,
            origin,
        )
        return_slot = (
            return_slots[index]
            if index < len(return_slots)
            else _return_slot_for_origin(assessment, origin)
        )
        call_args.setdefault(function_name, []).append(
            (args, _call_role_for_origin(assessment, origin), usage_mode, return_slot)
        )
    return {key: tuple(value) for key, value in call_args.items()}


def _parse_call_expression(
    expression: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, tuple[str, ...]] | None:
    match = _CALL_EXPRESSION_RE.match(_strip_lua_comment(expression).strip())
    if match is None:
        return None
    return (
        _resolve_related_name(
            match.group(1),
            default_module=default_module,
            known_function_names=known_function_names,
        ),
        tuple(_split_top_level_values(match.group(2))),
    )


def _resolve_related_name(
    raw_name: str,
    *,
    default_module: str | None = None,
    known_function_names: frozenset[str] | set[str] = frozenset(),
) -> str:
    normalized = raw_name.strip().replace(":", ".")
    if "." in normalized:
        return normalized
    if default_module:
        module_qualified = f"{default_module}.{normalized}"
        if module_qualified in known_function_names:
            return module_qualified
    if normalized in known_function_names:
        return normalized
    return normalized


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


def _strip_lua_comment(line: str) -> str:
    return line.partition("--")[0]


def _call_role_for_origin(assessment: CandidateAssessment, origin: str) -> str:
    if origin == assessment.candidate.expression:
        return "sink_expression"
    return "assignment_origin"


def _usage_mode_for_origin(assessment: CandidateAssessment, origin: str) -> str:
    if origin == assessment.candidate.expression:
        return "direct_sink"
    return "single_assignment"


def _return_slot_for_origin(assessment: CandidateAssessment, origin: str) -> int:
    if origin == assessment.candidate.expression:
        return 1
    return 1


def _scope_kind_for_function_scope(function_scope: str | None) -> str | None:
    if function_scope is None:
        return None
    return "top_level" if function_scope == "main" else "function_body"


def _top_level_phase_for_assessment(
    assessment: CandidateAssessment,
    source: str | None,
) -> str | None:
    if source is None or assessment.candidate.function_scope != "main":
        return None
    prefix = "\n".join(source.splitlines()[: max(0, assessment.candidate.line - 1)])
    return top_level_phase_for_prefix(prefix)


def _build_file_module_index(snapshot: RepositorySnapshot) -> dict[str, str | None]:
    index: dict[str, str | None] = {}
    for file_path in snapshot.lua_files:
        try:
            source = read_lua_source_text(file_path)
        except OSError:
            continue
        index[_normalize_path_key(file_path)] = detect_module_name(source)
    return index
