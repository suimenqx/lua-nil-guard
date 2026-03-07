from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Callable, Protocol

from .agent_driver_manifest import (
    CODEAGENT_PROVIDER_SPEC,
    CLAUDE_PROVIDER_SPEC,
    CODEX_PROVIDER_SPEC,
    get_builtin_agent_provider_spec,
    load_agent_provider_spec_manifest_file,
)
from .agent_driver_models import AgentProviderSpec
from .agent_protocols import (
    SchemaFileCliProtocol,
    StdoutEnvelopeCliProtocol,
    StdoutStructuredCliProtocol,
    get_cli_protocol_builder,
)
from .adjudication import adjudicate_packet
from .models import AdjudicationRecord, EvidencePacket, RoleOpinion, SinglePassJudgment, SinkRule, Verdict
from .prompting import build_adjudication_prompt


class AdjudicationBackend(Protocol):
    """Protocol for pluggable adjudication backends."""

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        """Return prosecutor/defender/judge output for one evidence packet."""


class BackendError(RuntimeError):
    """Raised when an external adjudication backend returns invalid output."""


AdjudicationBackendFactory = Callable[..., AdjudicationBackend]
DEFAULT_GEMINI_BACKEND_MODEL = "gemini-3.1-pro-preview"


class HeuristicAdjudicationBackend:
    """Default local backend for v3 single-pass adjudication."""

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        record = adjudicate_packet(packet, sink_rule)
        if record.judge.status != "risky":
            return record
        if _has_local_risk_proof(packet):
            return record

        origins = _tuple_field(packet, "origin_candidates")
        prosecutor = RoleOpinion(
            role="prosecutor",
            status="uncertain",
            confidence="low",
            risk_path=origins,
            safety_evidence=(),
            missing_evidence=("origin may be nil, but no code-proven nil path exists",),
            recommended_next_action="expand_context",
            suggested_fix=None,
        )
        defender = RoleOpinion(
            role=record.defender.role,
            status="uncertain",
            confidence="low",
            risk_path=record.defender.risk_path,
            safety_evidence=record.defender.safety_evidence,
            missing_evidence=("no explicit guard or trusted non-nil contract found",),
            recommended_next_action="expand_context",
            suggested_fix=None,
        )
        judge = Verdict(
            case_id=packet.case_id,
            status="uncertain",
            confidence="medium",
            risk_path=origins,
            safety_evidence=(),
            counterarguments_considered=("insufficient local proof either way",),
            suggested_fix=None,
            needs_human=True,
        )
        return AdjudicationRecord(
            prosecutor=prosecutor,
            defender=defender,
            judge=judge,
        )


class SinglePassHeuristicBackend:
    """Backward-compatible alias for the v3 heuristic backend."""

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        return HeuristicAdjudicationBackend().adjudicate(packet, sink_rule)


def _resolve_expanded_evidence_retry_mode(mode: str) -> bool | None:
    if mode == "on":
        return True
    if mode == "off":
        return False
    return None


class CliAgentBackend:
    """Base class for CLI-backed adjudication providers."""

    def __init__(
        self,
        *,
        runner=None,
        workdir: str | Path | None = None,
        skill_path: str | Path | None = None,
        strict_skill: bool = True,
        timeout_seconds: float | None = None,
        max_attempts: int = 1,
        expanded_evidence_retry: bool | None = None,
        fallback_to_uncertain_on_error: bool = False,
        cache_path: str | Path | None = None,
    ) -> None:
        self.runner = runner or _default_runner
        self._uses_default_runner = runner is None
        self.workdir = Path(workdir).resolve() if workdir is not None else None
        self.skill_path = Path(skill_path).resolve() if skill_path is not None else None
        self.strict_skill = strict_skill
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)
        self.expanded_evidence_retry = expanded_evidence_retry
        self.fallback_to_uncertain_on_error = fallback_to_uncertain_on_error
        self.cache_path = Path(cache_path).resolve() if cache_path is not None else None
        self.cache_hits = 0
        self.cache_misses = 0
        self.backend_call_count = 0
        self.backend_total_seconds = 0.0
        self.backend_warmup_call_count = 0
        self.backend_warmup_total_seconds = 0.0

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        prompt = self.build_prompt(packet=packet, sink_rule=sink_rule)
        cached = self._load_cached_record(prompt=prompt, case_id=packet.case_id)
        if cached is not None:
            self.cache_hits += 1
            return cached
        if self.cache_path is not None:
            self.cache_misses += 1
        return self._adjudicate_with_retries(
            lambda: self._adjudicate_once(packet, sink_rule, prompt),
            packet=packet,
        )

    def _adjudicate_once(
        self,
        packet: EvidencePacket,
        sink_rule: SinkRule,
        prompt: str,
    ) -> AdjudicationRecord:
        temp_dir_root = str(self.workdir) if self.workdir is not None else None
        with tempfile.TemporaryDirectory(
            prefix="lua_nil_guard_",
            dir=temp_dir_root,
        ) as temp_dir:
            temp_path = Path(temp_dir)
            schema_path = temp_path / "adjudication_record.schema.json"
            output_path = temp_path / "result.json"
            schema_path.write_text(
                json.dumps(self.output_schema(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
            command = self.build_command(
                schema_path=schema_path,
                output_path=output_path,
                cwd=self.workdir,
            )
            self._run_command(command, stdin_text=prompt)
            if not output_path.exists():
                raise BackendError("CLI backend did not write an output file")
            raw = output_path.read_text(encoding="utf-8")
        record = self.parse_response(raw, case_id=packet.case_id)
        self._store_cached_record(prompt=prompt, record=record)
        return record

    def _adjudicate_with_retries(
        self,
        operation,
        *,
        packet: EvidencePacket,
    ) -> AdjudicationRecord:
        last_error: BackendError | None = None
        for _ in range(self.max_attempts):
            try:
                return operation()
            except BackendError as exc:
                last_error = exc

        if self.fallback_to_uncertain_on_error:
            return _backend_failure_fallback(packet, str(last_error or "CLI backend failed"))
        if last_error is not None:
            raise last_error
        raise BackendError("CLI backend failed without a captured error")

    def _run_command(
        self,
        command: tuple[str, ...],
        *,
        stdin_text: str,
    ) -> str:
        self.backend_call_count += 1
        started = time.perf_counter()
        try:
            if self._uses_default_runner:
                return _default_runner(
                    command,
                    stdin_text=stdin_text,
                    cwd=self.workdir,
                    timeout_seconds=self.timeout_seconds,
                )
            return self.runner(command, stdin_text=stdin_text, cwd=self.workdir)
        finally:
            self.backend_total_seconds += max(0.0, time.perf_counter() - started)

    def build_prompt(self, *, packet: EvidencePacket, sink_rule: SinkRule) -> str:
        """Render the adjudication prompt consumed by the CLI provider."""

        return "\n".join(
            [
                build_adjudication_prompt(
                    packet=packet,
                    sink_rule=sink_rule,
                    skill_path=self.skill_path,
                    strict_skill=self.strict_skill,
                ),
                "",
                "Return a single JSON object with this exact top-level shape:",
                "{",
                '  "prosecutor": {...},',
                '  "defender": {...},',
                '  "judge": {...}',
                "}",
                "",
                "The prosecutor and defender objects must contain:",
                "- role",
                "- status",
                "- confidence",
                "- risk_path",
                "- safety_evidence",
                "- missing_evidence",
                "- recommended_next_action",
                "- suggested_fix",
                "",
                "The judge object must contain:",
                "- status",
                "- confidence",
                "- risk_path",
                "- safety_evidence",
                "- counterarguments_considered",
                "- suggested_fix",
                "- needs_human",
                "",
                "If your runtime supports repository access, prefer read-only evidence collection and cite concrete file:line evidence.",
                "If no repository access is available, use only the prompt payload as admissible evidence.",
                "",
                "Output JSON only. Do not include markdown fences or extra text.",
            ]
        )

    def build_command(
        self,
        *,
        schema_path: Path,
        output_path: Path,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        """Return the concrete CLI command for this provider."""

        raise NotImplementedError

    def output_schema(self) -> dict[str, object]:
        """Return a JSON schema that constrains the provider output."""

        role_object = {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "role",
                "status",
                "confidence",
                "risk_path",
                "safety_evidence",
                "missing_evidence",
                "recommended_next_action",
                "suggested_fix",
            ],
            "properties": {
                "role": {"type": "string"},
                "status": {"type": "string"},
                "confidence": {"type": "string"},
                "risk_path": {"type": "array", "items": {"type": "string"}},
                "safety_evidence": {"type": "array", "items": {"type": "string"}},
                "missing_evidence": {"type": "array", "items": {"type": "string"}},
                "recommended_next_action": {"type": "string"},
                "suggested_fix": {"type": ["string", "null"]},
            },
        }
        judge_object = {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "status",
                "confidence",
                "risk_path",
                "safety_evidence",
                "counterarguments_considered",
                "suggested_fix",
                "needs_human",
            ],
            "properties": {
                "status": {"type": "string"},
                "confidence": {"type": "string"},
                "risk_path": {"type": "array", "items": {"type": "string"}},
                "safety_evidence": {"type": "array", "items": {"type": "string"}},
                "counterarguments_considered": {"type": "array", "items": {"type": "string"}},
                "suggested_fix": {"type": ["string", "null"]},
                "needs_human": {"type": "boolean"},
            },
        }
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["prosecutor", "defender", "judge"],
            "properties": {
                "prosecutor": role_object,
                "defender": role_object,
                "judge": judge_object,
            },
        }

    def parse_response(self, raw: str, *, case_id: str) -> AdjudicationRecord:
        """Parse a provider JSON response into internal dataclasses."""

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BackendError("Invalid CLI backend JSON output") from exc
        if not isinstance(payload, dict):
            raise BackendError("CLI backend output must be a JSON object")

        try:
            prosecutor = _parse_role_opinion(payload["prosecutor"])
            defender = _parse_role_opinion(payload["defender"])
            judge = _parse_judge_verdict(payload["judge"], case_id=case_id)
        except (KeyError, TypeError, ValueError) as exc:
            raise BackendError(f"CLI backend output did not match expected schema: {exc}") from exc

        return AdjudicationRecord(
            prosecutor=prosecutor,
            defender=defender,
            judge=judge,
        )

    def _cache_identity(self) -> dict[str, object]:
        return {"backend": self.__class__.__name__}

    def _cache_key(self, *, prompt: str) -> str:
        payload = json.dumps(
            {
                "identity": self._cache_identity(),
                "prompt": prompt,
                "schema": self.output_schema(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _load_cached_record(self, *, prompt: str, case_id: str) -> AdjudicationRecord | None:
        if self.cache_path is None or not self.cache_path.exists():
            return None
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        cached = payload.get(self._cache_key(prompt=prompt))
        if not isinstance(cached, dict):
            return None
        return self.parse_response(json.dumps(cached), case_id=case_id)

    def _store_cached_record(self, *, prompt: str, record: AdjudicationRecord) -> None:
        if self.cache_path is None:
            return
        payload: dict[str, object] = {}
        if self.cache_path.exists():
            try:
                existing = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = {}
            if isinstance(existing, dict):
                payload.update(existing)
        payload[self._cache_key(prompt=prompt)] = _serialize_record(record)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.cache_path.parent / f"{self.cache_path.name}.tmp"
        temp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temp_path.replace(self.cache_path)


class CodexCliBackend(CliAgentBackend):
    """CLI backend implementation for the Codex CLI."""

    def __init__(
        self,
        *,
        runner=None,
        workdir: str | Path | None = None,
        skill_path: str | Path | None = None,
        strict_skill: bool = True,
        model: str | None = None,
        sandbox: str = "read-only",
        executable: str | None = None,
        timeout_seconds: float | None = None,
        max_attempts: int | None = None,
        expanded_evidence_retry: bool | None = None,
        fallback_to_uncertain_on_error: bool | None = None,
        config_overrides: tuple[str, ...] = (),
        cache_path: str | Path | None = None,
        provider_spec: AgentProviderSpec | None = None,
    ) -> None:
        self.provider_spec = provider_spec or CODEX_PROVIDER_SPEC
        self.cli_protocol = get_cli_protocol_builder(self.provider_spec.protocol)
        resolved_timeout = (
            self.provider_spec.default_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        resolved_attempts = (
            self.provider_spec.default_max_attempts if max_attempts is None else max_attempts
        )
        resolved_expanded_evidence_retry = (
            _resolve_expanded_evidence_retry_mode(
                self.provider_spec.default_expanded_evidence_retry_mode
            )
            if expanded_evidence_retry is None
            else expanded_evidence_retry
        )
        resolved_fallback = (
            self.provider_spec.default_fallback_to_uncertain_on_error
            if fallback_to_uncertain_on_error is None
            else fallback_to_uncertain_on_error
        )
        super().__init__(
            runner=runner,
            workdir=workdir,
            skill_path=skill_path,
            strict_skill=strict_skill,
            timeout_seconds=resolved_timeout,
            max_attempts=resolved_attempts,
            expanded_evidence_retry=resolved_expanded_evidence_retry,
            fallback_to_uncertain_on_error=resolved_fallback,
            cache_path=cache_path,
        )
        self.model = model
        self.sandbox = sandbox
        self.executable = executable or self.provider_spec.default_executable
        self.config_overrides = config_overrides

    def _cache_identity(self) -> dict[str, object]:
        return {
            "backend": self.provider_spec.name,
            "model": self.model,
            "sandbox": self.sandbox,
            "executable": self.executable,
            "config_overrides": self.config_overrides,
            "protocol": self.provider_spec.protocol,
        }

    def build_command(
        self,
        *,
        schema_path: Path,
        output_path: Path,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        protocol = self.cli_protocol
        if not isinstance(protocol, SchemaFileCliProtocol):
            raise BackendError(
                f"Provider {self.provider_spec.name} requires schema_file_cli, got {self.provider_spec.protocol}"
            )
        return protocol.build_command(
            executable=self.executable,
            base_args=(
                "exec",
                "--skip-git-repo-check",
                "--sandbox",
                self.sandbox,
                "--color",
                "never",
            ),
            config_overrides=self.config_overrides,
            schema_path=schema_path,
            output_path=output_path,
            schema_flag="--output-schema",
            output_flag="-o",
            cwd=cwd,
            cwd_flag="-C",
            model=self.model,
            model_flag="-m",
            stdin_sentinel="-",
        )


class ClaudeCliBackend(CliAgentBackend):
    """CLI backend for a Claude binary that emits structured JSON on stdout."""

    def __init__(
        self,
        *,
        runner=None,
        workdir: str | Path | None = None,
        skill_path: str | Path | None = None,
        strict_skill: bool = True,
        model: str | None = None,
        executable: str | None = None,
        timeout_seconds: float | None = None,
        max_attempts: int | None = None,
        expanded_evidence_retry: bool | None = None,
        fallback_to_uncertain_on_error: bool | None = None,
        config_overrides: tuple[str, ...] = (),
        cache_path: str | Path | None = None,
        provider_spec: AgentProviderSpec | None = None,
        warmup_enabled: bool | None = None,
    ) -> None:
        self.provider_spec = provider_spec or CLAUDE_PROVIDER_SPEC
        self.cli_protocol = get_cli_protocol_builder(self.provider_spec.protocol)
        resolved_timeout = (
            self.provider_spec.default_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        resolved_attempts = (
            self.provider_spec.default_max_attempts if max_attempts is None else max_attempts
        )
        resolved_expanded_evidence_retry = (
            _resolve_expanded_evidence_retry_mode(
                self.provider_spec.default_expanded_evidence_retry_mode
            )
            if expanded_evidence_retry is None
            else expanded_evidence_retry
        )
        resolved_fallback = (
            self.provider_spec.default_fallback_to_uncertain_on_error
            if fallback_to_uncertain_on_error is None
            else fallback_to_uncertain_on_error
        )
        super().__init__(
            runner=runner,
            workdir=workdir,
            skill_path=skill_path,
            strict_skill=strict_skill,
            timeout_seconds=resolved_timeout,
            max_attempts=resolved_attempts,
            expanded_evidence_retry=resolved_expanded_evidence_retry,
            fallback_to_uncertain_on_error=resolved_fallback,
            cache_path=cache_path,
        )
        self.model = model
        self.executable = executable or self.provider_spec.default_executable
        self.config_overrides = config_overrides
        self.warmup_enabled = (runner is None) if warmup_enabled is None else warmup_enabled
        self._warmup_attempted = False

    def _cache_identity(self) -> dict[str, object]:
        return {
            "backend": self.provider_spec.name,
            "model": self.model,
            "executable": self.executable,
            "config_overrides": self.config_overrides,
            "protocol": self.provider_spec.protocol,
        }

    def build_prompt(self, *, packet: EvidencePacket, sink_rule: SinkRule) -> str:
        return "\n".join(
            [
                build_adjudication_prompt(
                    packet=packet,
                    sink_rule=sink_rule,
                    skill_path=self.skill_path,
                    strict_skill=self.strict_skill,
                ),
                "",
                "Return a single JSON object with exactly three top-level keys: prosecutor, defender and judge.",
                "The prosecutor and defender objects must each contain:",
                "- role",
                "- status",
                "- confidence",
                "- risk_path",
                "- safety_evidence",
                "- missing_evidence",
                "- recommended_next_action",
                "- suggested_fix",
                "The judge object must contain:",
                "- status",
                "- confidence",
                "- risk_path",
                "- safety_evidence",
                "- counterarguments_considered",
                "- suggested_fix",
                "- needs_human",
                "If your runtime supports repository access, prefer read-only evidence collection and cite concrete file:line evidence.",
                "If no repository access is available, use only the prompt payload as admissible evidence.",
                "Do not include markdown fences or explanatory prose.",
            ]
        )

    def _adjudicate_once(
        self,
        packet: EvidencePacket,
        sink_rule: SinkRule,
        prompt: str,
    ) -> AdjudicationRecord:
        self._ensure_warmup()
        command = self.build_prompt_command(prompt=prompt)
        raw = self._run_command(command, stdin_text="")
        if not isinstance(raw, str) or not raw.strip():
            raise BackendError("Claude backend did not return structured JSON on stdout")
        record = self.parse_wrapped_response(raw, case_id=packet.case_id)
        self._store_cached_record(prompt=prompt, record=record)
        return record

    def build_command(
        self,
        *,
        schema_path: Path,
        output_path: Path,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        raise NotImplementedError("ClaudeCliBackend builds commands from the prompt directly")

    def build_prompt_command(
        self,
        *,
        prompt: str,
    ) -> tuple[str, ...]:
        if self.config_overrides:
            raise BackendError("Claude backend does not support config overrides")
        protocol = self.cli_protocol
        if not isinstance(protocol, StdoutStructuredCliProtocol):
            raise BackendError(
                f"Provider {self.provider_spec.name} requires stdout_structured_cli, got {self.provider_spec.protocol}"
            )
        return protocol.build_command(
            executable=self.executable,
            base_args=(
                "--output-format",
                "json",
                "--permission-mode",
                "dontAsk",
                "--tools",
                "",
                "--no-session-persistence",
            ),
            model=self.model,
            model_flag="--model",
            schema=None,
            schema_flag=None,
            print_flag="-p",
            prompt=prompt,
        )

    def build_warmup_command(self) -> tuple[str, ...]:
        protocol = self.cli_protocol
        if not isinstance(protocol, StdoutStructuredCliProtocol):
            raise BackendError(
                f"Provider {self.provider_spec.name} requires stdout_structured_cli, got {self.provider_spec.protocol}"
            )
        return protocol.build_command(
            executable=self.executable,
            base_args=(
                "--output-format",
                "json",
                "--permission-mode",
                "dontAsk",
                "--tools",
                "",
                "--no-session-persistence",
            ),
            model=self.model,
            model_flag="--model",
            schema=None,
            schema_flag=None,
            print_flag="-p",
            prompt='Return exactly this JSON object and nothing else: {"ok": true}',
        )

    def _ensure_warmup(self) -> None:
        if not self.warmup_enabled or self._warmup_attempted:
            return
        self._warmup_attempted = True
        command = self.build_warmup_command()
        self.backend_call_count += 1
        self.backend_warmup_call_count += 1
        started = time.perf_counter()
        try:
            if self._uses_default_runner:
                warmup_timeout = self.timeout_seconds
                if warmup_timeout is None:
                    warmup_timeout = 12.0
                else:
                    warmup_timeout = min(warmup_timeout, 12.0)
                _default_runner(
                    command,
                    stdin_text="",
                    cwd=self.workdir,
                    timeout_seconds=warmup_timeout,
                )
            else:
                self.runner(command, stdin_text="", cwd=self.workdir)
        except Exception:
            # Warm-up is a best-effort latency stabilizer and must not block the real review path.
            return
        finally:
            elapsed = max(0.0, time.perf_counter() - started)
            self.backend_total_seconds += elapsed
            self.backend_warmup_total_seconds += elapsed

    def parse_wrapped_response(self, raw: str, *, case_id: str) -> AdjudicationRecord:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BackendError("Invalid Claude structured JSON envelope") from exc
        if not isinstance(payload, dict):
            raise BackendError("Claude structured JSON envelope must be an object")

        if {"prosecutor", "defender", "judge"}.issubset(payload.keys()):
            return self.parse_response(raw, case_id=case_id)

        structured = payload.get("structured_output")
        if isinstance(structured, dict):
            return self.parse_response(json.dumps(structured), case_id=case_id)
        if isinstance(structured, str):
            return self.parse_response(_strip_markdown_fences(structured), case_id=case_id)
        result = payload.get("result")
        if isinstance(result, str):
            return self.parse_response(_strip_markdown_fences(result), case_id=case_id)
        raise BackendError(
            "Claude JSON envelope must contain structured_output or result text"
        )


class CodeAgentCliBackend(CliAgentBackend):
    """CLI backend for Gemini-compatible binaries that use headless JSON output."""

    def __init__(
        self,
        *,
        runner=None,
        workdir: str | Path | None = None,
        skill_path: str | Path | None = None,
        strict_skill: bool = True,
        model: str | None = None,
        executable: str | None = None,
        timeout_seconds: float | None = None,
        max_attempts: int | None = None,
        expanded_evidence_retry: bool | None = None,
        fallback_to_uncertain_on_error: bool | None = None,
        config_overrides: tuple[str, ...] = (),
        cache_path: str | Path | None = None,
        provider_spec: AgentProviderSpec | None = None,
    ) -> None:
        self.provider_spec = provider_spec or CODEAGENT_PROVIDER_SPEC
        self.cli_protocol = get_cli_protocol_builder(self.provider_spec.protocol)
        resolved_timeout = (
            self.provider_spec.default_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        resolved_attempts = (
            self.provider_spec.default_max_attempts if max_attempts is None else max_attempts
        )
        resolved_expanded_evidence_retry = (
            _resolve_expanded_evidence_retry_mode(
                self.provider_spec.default_expanded_evidence_retry_mode
            )
            if expanded_evidence_retry is None
            else expanded_evidence_retry
        )
        resolved_fallback = (
            self.provider_spec.default_fallback_to_uncertain_on_error
            if fallback_to_uncertain_on_error is None
            else fallback_to_uncertain_on_error
        )
        super().__init__(
            runner=runner,
            workdir=workdir,
            skill_path=skill_path,
            strict_skill=strict_skill,
            timeout_seconds=resolved_timeout,
            max_attempts=resolved_attempts,
            expanded_evidence_retry=resolved_expanded_evidence_retry,
            fallback_to_uncertain_on_error=resolved_fallback,
            cache_path=cache_path,
        )
        self.model = model
        self.executable = executable or self.provider_spec.default_executable
        self.config_overrides = config_overrides

    def _cache_identity(self) -> dict[str, object]:
        return {
            "backend": self.provider_spec.name,
            "model": self.model,
            "executable": self.executable,
            "config_overrides": self.config_overrides,
            "protocol": self.provider_spec.protocol,
        }

    def _adjudicate_once(
        self,
        packet: EvidencePacket,
        sink_rule: SinkRule,
        prompt: str,
    ) -> AdjudicationRecord:
        command = self.build_prompt_command(prompt=prompt, cwd=self.workdir)
        raw = self._run_command(command, stdin_text="")
        if not isinstance(raw, str) or not raw.strip():
            raise BackendError(
                f"{self.provider_spec.name} backend did not return headless JSON on stdout"
            )
        record = self.parse_wrapped_response(raw, case_id=packet.case_id)
        self._store_cached_record(prompt=prompt, record=record)
        return record

    def build_command(
        self,
        *,
        schema_path: Path,
        output_path: Path,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        raise NotImplementedError("CodeAgentCliBackend builds commands from the prompt directly")

    def build_prompt_command(
        self,
        *,
        prompt: str,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        del cwd
        if self.config_overrides and not self.provider_spec.capabilities.supports_config_overrides:
            raise BackendError(
                f"{self.provider_spec.name} backend does not support config overrides"
            )
        protocol = self.cli_protocol
        if not isinstance(protocol, StdoutEnvelopeCliProtocol):
            raise BackendError(
                f"Provider {self.provider_spec.name} requires stdout_envelope_cli, got {self.provider_spec.protocol}"
            )
        prompt_flag = None
        if Path(self.executable).name == "gemini":
            prompt_flag = "--prompt"
        return protocol.build_command(
            executable=self.executable,
            base_args=("--output-format", "json"),
            config_overrides=self.config_overrides,
            model=self.model,
            model_flag="-m",
            prompt=prompt,
            prompt_flag=prompt_flag,
        )

    def parse_wrapped_response(self, raw: str, *, case_id: str) -> AdjudicationRecord:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BackendError(
                f"Invalid {self.provider_spec.name} headless JSON envelope"
            ) from exc
        if not isinstance(payload, dict):
            raise BackendError(
                f"{self.provider_spec.name} headless JSON envelope must be an object"
            )

        if {"prosecutor", "defender", "judge"}.issubset(payload.keys()):
            return self.parse_response(raw, case_id=case_id)

        response = payload.get("response")
        if not isinstance(response, str):
            raise BackendError(
                f"{self.provider_spec.name} headless JSON envelope must contain a string response field"
            )

        return self.parse_response(_strip_markdown_fences(response), case_id=case_id)


_ADJUDICATION_BACKEND_FACTORIES: dict[str, AdjudicationBackendFactory] = {}


def register_adjudication_backend(
    name: str,
    factory: AdjudicationBackendFactory,
    *,
    replace: bool = False,
) -> None:
    """Register a backend factory under a normalized name."""

    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("Backend name must not be empty")
    if normalized in _ADJUDICATION_BACKEND_FACTORIES and not replace:
        raise ValueError(f"Adjudication backend already registered: {name}")
    _ADJUDICATION_BACKEND_FACTORIES[normalized] = factory


def unregister_adjudication_backend(name: str) -> None:
    """Remove a previously registered backend factory."""

    normalized = name.strip().lower()
    if normalized not in _ADJUDICATION_BACKEND_FACTORIES:
        raise ValueError(f"Unknown adjudication backend: {name}")
    del _ADJUDICATION_BACKEND_FACTORIES[normalized]


def get_adjudication_backend_factory(name: str) -> AdjudicationBackendFactory:
    """Return the registered factory for a backend name."""

    normalized = name.strip().lower()
    if normalized not in _ADJUDICATION_BACKEND_FACTORIES:
        raise ValueError(f"Unknown adjudication backend: {name}")
    return _ADJUDICATION_BACKEND_FACTORIES[normalized]


def _build_heuristic_backend(**_kwargs) -> AdjudicationBackend:
    return HeuristicAdjudicationBackend()


def build_manifest_backed_backend_factory(provider_name: str) -> AdjudicationBackendFactory:
    """Build a generic backend factory from a provider manifest and protocol mapping."""

    provider_spec = get_builtin_agent_provider_spec(provider_name)
    return build_provider_spec_backed_backend_factory(provider_spec)


def build_provider_spec_backed_backend_factory(
    provider_spec: AgentProviderSpec,
) -> AdjudicationBackendFactory:
    """Build a generic backend factory from an explicit provider spec."""

    backend_type = get_cli_protocol_backend(provider_spec.protocol)

    def factory(
        *,
        workdir: str | Path | None = None,
        model: str | None = None,
        skill_path: str | Path | None = None,
        strict_skill: bool = True,
        executable: str | None = None,
        timeout_seconds: float | None = None,
        max_attempts: int | None = None,
        expanded_evidence_retry: bool | None = None,
        cache_path: str | Path | None = None,
        config_overrides: tuple[str, ...] = (),
        runner=None,
    ) -> AdjudicationBackend:
        return _instantiate_manifest_backed_backend(
            backend_type=backend_type,
            provider_spec=provider_spec,
            workdir=workdir,
            model=model,
            skill_path=skill_path,
            strict_skill=strict_skill,
            executable=executable,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
            expanded_evidence_retry=expanded_evidence_retry,
            cache_path=cache_path,
            config_overrides=config_overrides,
            runner=runner,
        )

    return factory


def register_manifest_backed_adjudication_backend(
    manifest_path: str | Path,
    *,
    replace: bool = False,
) -> AgentProviderSpec:
    """Load a provider manifest file and register a matching backend factory."""

    provider_spec = load_agent_provider_spec_manifest_file(manifest_path)
    register_adjudication_backend(
        provider_spec.name,
        build_provider_spec_backed_backend_factory(provider_spec),
        replace=replace,
    )
    return provider_spec


def _instantiate_manifest_backed_backend(
    *,
    backend_type: type[CliAgentBackend],
    provider_spec: AgentProviderSpec,
    workdir: str | Path | None = None,
    model: str | None = None,
    skill_path: str | Path | None = None,
    strict_skill: bool = True,
    executable: str | None = None,
    timeout_seconds: float | None = None,
    max_attempts: int | None = None,
    expanded_evidence_retry: bool | None = None,
    cache_path: str | Path | None = None,
    config_overrides: tuple[str, ...] = (),
    runner=None,
) -> AdjudicationBackend:
    if model is not None and not provider_spec.capabilities.supports_model_override:
        raise ValueError(f"Provider {provider_spec.name} does not support model overrides")
    if config_overrides and not provider_spec.capabilities.supports_config_overrides:
        raise ValueError(f"Provider {provider_spec.name} does not support backend config overrides")
    resolved_model = model
    if resolved_model is None and provider_spec.name == "gemini":
        resolved_model = DEFAULT_GEMINI_BACKEND_MODEL
    options: dict[str, object] = {}
    if timeout_seconds is not None:
        options["timeout_seconds"] = timeout_seconds
    if max_attempts is not None:
        options["max_attempts"] = max_attempts
    if expanded_evidence_retry is not None:
        options["expanded_evidence_retry"] = expanded_evidence_retry
    if cache_path is not None:
        options["cache_path"] = cache_path
    if config_overrides:
        options["config_overrides"] = config_overrides
    return backend_type(
        runner=runner,
        workdir=workdir,
        model=resolved_model,
        skill_path=skill_path,
        strict_skill=strict_skill,
        executable=executable or provider_spec.default_executable,
        provider_spec=provider_spec,
        **options,
    )


def create_adjudication_backend(
    name: str,
    *,
    workdir: str | Path | None = None,
    model: str | None = None,
    skill_path: str | Path | None = None,
    strict_skill: bool = True,
    executable: str | None = None,
    timeout_seconds: float | None = None,
    max_attempts: int | None = None,
    expanded_evidence_retry: bool | None = None,
    cache_path: str | Path | None = None,
    config_overrides: tuple[str, ...] = (),
    runner=None,
) -> AdjudicationBackend:
    """Create a named adjudication backend."""

    factory = get_adjudication_backend_factory(name)
    options: dict[str, object] = {
        "workdir": workdir,
        "model": model,
        "skill_path": skill_path,
        "strict_skill": strict_skill,
        "executable": executable,
        "timeout_seconds": timeout_seconds,
        "max_attempts": max_attempts,
        "cache_path": cache_path,
        "config_overrides": config_overrides,
        "runner": runner,
    }
    if expanded_evidence_retry is not None:
        options["expanded_evidence_retry"] = expanded_evidence_retry
    return factory(**options)


def _default_runner(
    command: tuple[str, ...],
    *,
    stdin_text: str,
    cwd: Path | None,
    timeout_seconds: float | None = None,
) -> str:
    try:
        result = subprocess.run(
            command,
            input=stdin_text,
            text=True,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        if timeout_seconds is None:
            raise BackendError("CLI backend command timed out") from exc
        raise BackendError(
            f"CLI backend command timed out after {timeout_seconds:g}s"
        ) from exc
    if result.returncode != 0:
        raise BackendError(
            f"CLI backend command failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


def _tuple_field(packet: EvidencePacket, key: str) -> tuple[str, ...]:
    value = packet.static_reasoning.get(key, ())
    if isinstance(value, tuple):
        return value
    return ()


def _has_local_risk_proof(packet: EvidencePacket) -> bool:
    if packet.static_risk_signals:
        return True
    origins = _tuple_field(packet, "origin_candidates")
    if any(origin.strip() == "nil" for origin in origins):
        return True
    return " and nil or " in packet.local_context


def _backend_failure_fallback(packet: EvidencePacket, reason: str) -> AdjudicationRecord:
    origins = _tuple_field(packet, "origin_candidates")
    prosecutor = RoleOpinion(
        role="prosecutor",
        status="uncertain",
        confidence="low",
        risk_path=origins,
        safety_evidence=(),
        missing_evidence=(reason,),
        recommended_next_action="expand_context",
        suggested_fix=None,
    )
    defender = RoleOpinion(
        role="defender",
        status="uncertain",
        confidence="low",
        risk_path=(),
        safety_evidence=(),
        missing_evidence=(reason,),
        recommended_next_action="expand_context",
        suggested_fix=None,
    )
    judge = Verdict(
        case_id=packet.case_id,
        status="uncertain",
        confidence="low",
        risk_path=origins,
        safety_evidence=(),
        counterarguments_considered=(reason,),
        suggested_fix=None,
        needs_human=True,
    )
    return AdjudicationRecord(
        prosecutor=prosecutor,
        defender=defender,
        judge=judge,
    )


def _serialize_record(record: AdjudicationRecord) -> dict[str, object]:
    return {
        "prosecutor": _serialize_role(record.prosecutor),
        "defender": _serialize_role(record.defender),
        "judge": {
            "status": record.judge.status,
            "confidence": record.judge.confidence,
            "risk_path": list(record.judge.risk_path),
            "safety_evidence": list(record.judge.safety_evidence),
            "counterarguments_considered": list(record.judge.counterarguments_considered),
            "suggested_fix": record.judge.suggested_fix,
            "needs_human": record.judge.needs_human,
        },
    }


def _serialize_role(role: RoleOpinion) -> dict[str, object]:
    return {
        "role": role.role,
        "status": role.status,
        "confidence": role.confidence,
        "risk_path": list(role.risk_path),
        "safety_evidence": list(role.safety_evidence),
        "missing_evidence": list(role.missing_evidence),
        "recommended_next_action": role.recommended_next_action,
        "suggested_fix": role.suggested_fix,
    }


def _parse_role_opinion(payload: object) -> RoleOpinion:
    if not isinstance(payload, dict):
        raise TypeError("role opinion must be an object")
    return RoleOpinion(
        role=_require_string(payload, "role"),
        status=_require_string(payload, "status"),
        confidence=_require_string(payload, "confidence"),
        risk_path=_require_string_tuple(payload, "risk_path"),
        safety_evidence=_require_string_tuple(payload, "safety_evidence"),
        missing_evidence=_require_string_tuple(payload, "missing_evidence"),
        recommended_next_action=_require_string(payload, "recommended_next_action"),
        suggested_fix=_optional_string(payload, "suggested_fix"),
    )


def _parse_judge_verdict(payload: object, *, case_id: str) -> Verdict:
    if not isinstance(payload, dict):
        raise TypeError("judge verdict must be an object")
    return Verdict(
        case_id=case_id,
        status=_require_string(payload, "status"),
        confidence=_require_string(payload, "confidence"),
        risk_path=_require_string_tuple(payload, "risk_path"),
        safety_evidence=_require_string_tuple(payload, "safety_evidence"),
        counterarguments_considered=_require_string_tuple(payload, "counterarguments_considered"),
        suggested_fix=_optional_string(payload, "suggested_fix"),
        needs_human=_require_bool(payload, "needs_human"),
    )


def _require_string(payload: dict[str, object], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _optional_string(payload: dict[str, object], key: str) -> str | None:
    value = payload[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string or null")
    return value


def _require_bool(payload: dict[str, object], key: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise TypeError(f"{key} must be a boolean")
    return value


def _require_string_tuple(payload: dict[str, object], key: str) -> tuple[str, ...]:
    value = payload[key]
    if value is None:
        return ()
    if isinstance(value, str):
        if not value:
            return ()
        return (value,)
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise TypeError(f"{key} must be a string array")


def _strip_markdown_fences(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if len(lines) < 3:
        return stripped
    if not lines[0].startswith("```"):
        return stripped
    if not lines[-1].startswith("```"):
        return stripped
    return "\n".join(lines[1:-1]).strip()


_CLI_PROTOCOL_BACKEND_TYPES: dict[str, type[CliAgentBackend]] = {}


def register_cli_protocol_backend(
    protocol_name: str,
    backend_type: type[CliAgentBackend],
    *,
    replace: bool = False,
) -> None:
    """Register the default backend implementation for a CLI protocol."""

    normalized = protocol_name.strip().lower()
    if not normalized:
        raise ValueError("Protocol name must not be empty")
    if normalized in _CLI_PROTOCOL_BACKEND_TYPES and not replace:
        raise ValueError(f"CLI protocol backend already registered: {protocol_name}")
    _CLI_PROTOCOL_BACKEND_TYPES[normalized] = backend_type


def get_cli_protocol_backend(protocol_name: str) -> type[CliAgentBackend]:
    """Return the default backend implementation for a CLI protocol."""

    normalized = protocol_name.strip().lower()
    if normalized not in _CLI_PROTOCOL_BACKEND_TYPES:
        raise ValueError(f"Unknown CLI protocol backend: {protocol_name}")
    return _CLI_PROTOCOL_BACKEND_TYPES[normalized]


def unregister_cli_protocol_backend(protocol_name: str) -> None:
    """Remove a previously registered CLI protocol backend mapping."""

    normalized = protocol_name.strip().lower()
    if normalized not in _CLI_PROTOCOL_BACKEND_TYPES:
        raise ValueError(f"Unknown CLI protocol backend: {protocol_name}")
    del _CLI_PROTOCOL_BACKEND_TYPES[normalized]


register_adjudication_backend("heuristic", _build_heuristic_backend)
register_cli_protocol_backend(CODEX_PROVIDER_SPEC.protocol, CodexCliBackend)
register_cli_protocol_backend(CLAUDE_PROVIDER_SPEC.protocol, ClaudeCliBackend)
register_cli_protocol_backend(CODEAGENT_PROVIDER_SPEC.protocol, CodeAgentCliBackend)
register_adjudication_backend("codex", build_manifest_backed_backend_factory("codex"))
register_adjudication_backend("claude", build_manifest_backed_backend_factory("claude"))
register_adjudication_backend("gemini", build_manifest_backed_backend_factory("gemini"))
register_adjudication_backend("codeagent", build_manifest_backed_backend_factory("codeagent"))
