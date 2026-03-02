from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
from typing import Protocol

from .adjudication import adjudicate_packet
from .models import AdjudicationRecord, EvidencePacket, RoleOpinion, SinkRule, Verdict
from .prompting import build_adjudication_prompt


class AdjudicationBackend(Protocol):
    """Protocol for pluggable adjudication backends."""

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        """Return prosecutor/defender/judge output for one evidence packet."""


class BackendError(RuntimeError):
    """Raised when an external adjudication backend returns invalid output."""


class HeuristicAdjudicationBackend:
    """Default local backend used when no external agent is configured."""

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
        defender = replace(
            record.defender,
            status="uncertain",
            confidence="low",
            missing_evidence=("no explicit guard or trusted non-nil contract found",),
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
        fallback_to_uncertain_on_error: bool = False,
    ) -> None:
        self.runner = runner or _default_runner
        self._uses_default_runner = runner is None
        self.workdir = Path(workdir).resolve() if workdir is not None else None
        self.skill_path = Path(skill_path).resolve() if skill_path is not None else None
        self.strict_skill = strict_skill
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)
        self.fallback_to_uncertain_on_error = fallback_to_uncertain_on_error

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        return self._adjudicate_with_retries(
            lambda: self._adjudicate_once(packet, sink_rule),
            packet=packet,
        )

    def _adjudicate_once(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        prompt = self.build_prompt(packet=packet, sink_rule=sink_rule)
        temp_dir_root = str(self.workdir) if self.workdir is not None else None
        with tempfile.TemporaryDirectory(
            prefix="lua_nil_review_agent_",
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
        return self.parse_response(raw, case_id=packet.case_id)

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
        if self._uses_default_runner:
            return _default_runner(
                command,
                stdin_text=stdin_text,
                cwd=self.workdir,
                timeout_seconds=self.timeout_seconds,
            )
        return self.runner(command, stdin_text=stdin_text, cwd=self.workdir)

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
                "Do not execute shell commands, open files, or inspect the repository.",
                "Use only the prompt payload as admissible evidence.",
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
        executable: str = "codex",
        timeout_seconds: float | None = 45.0,
        max_attempts: int = 2,
        fallback_to_uncertain_on_error: bool = True,
    ) -> None:
        super().__init__(
            runner=runner,
            workdir=workdir,
            skill_path=skill_path,
            strict_skill=strict_skill,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
            fallback_to_uncertain_on_error=fallback_to_uncertain_on_error,
        )
        self.model = model
        self.sandbox = sandbox
        self.executable = executable

    def build_command(
        self,
        *,
        schema_path: Path,
        output_path: Path,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        command: list[str] = [
            self.executable,
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            self.sandbox,
            "--color",
            "never",
            "--output-schema",
            str(schema_path),
            "-o",
            str(output_path),
        ]
        if cwd is not None:
            command.extend(["-C", str(cwd)])
        if self.model is not None:
            command.extend(["-m", self.model])
        command.append("-")
        return tuple(command)


class CodeAgentCliBackend(CliAgentBackend):
    """CLI backend for a codeagent binary that uses headless JSON output."""

    def __init__(
        self,
        *,
        runner=None,
        workdir: str | Path | None = None,
        skill_path: str | Path | None = None,
        strict_skill: bool = True,
        model: str | None = None,
        executable: str = "codeagent",
        timeout_seconds: float | None = None,
        max_attempts: int = 1,
    ) -> None:
        super().__init__(
            runner=runner,
            workdir=workdir,
            skill_path=skill_path,
            strict_skill=strict_skill,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
        )
        self.model = model
        self.executable = executable

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        return self._adjudicate_with_retries(
            lambda: self._adjudicate_once(packet, sink_rule),
            packet=packet,
        )

    def _adjudicate_once(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        prompt = self.build_prompt(packet=packet, sink_rule=sink_rule)
        command = self.build_prompt_command(prompt=prompt, cwd=self.workdir)
        raw = self._run_command(command, stdin_text="")
        if not isinstance(raw, str) or not raw.strip():
            raise BackendError("CodeAgent backend did not return headless JSON on stdout")
        return self.parse_wrapped_response(raw, case_id=packet.case_id)

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
        command: list[str] = [
            self.executable,
            "--output-format",
            "json",
        ]
        if self.model is not None:
            command.extend(["-m", self.model])
        command.extend(["-p", prompt])
        return tuple(command)

    def parse_wrapped_response(self, raw: str, *, case_id: str) -> AdjudicationRecord:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BackendError("Invalid CodeAgent headless JSON envelope") from exc
        if not isinstance(payload, dict):
            raise BackendError("CodeAgent headless JSON envelope must be an object")

        if {"prosecutor", "defender", "judge"}.issubset(payload.keys()):
            return self.parse_response(raw, case_id=case_id)

        response = payload.get("response")
        if not isinstance(response, str):
            raise BackendError("CodeAgent headless JSON envelope must contain a string response field")

        return self.parse_response(_strip_markdown_fences(response), case_id=case_id)


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
    runner=None,
) -> AdjudicationBackend:
    """Create a named adjudication backend."""

    normalized = name.strip().lower()
    if normalized == "heuristic":
        return HeuristicAdjudicationBackend()
    if normalized == "codex":
        options: dict[str, object] = {}
        if timeout_seconds is not None:
            options["timeout_seconds"] = timeout_seconds
        if max_attempts is not None:
            options["max_attempts"] = max_attempts
        return CodexCliBackend(
            runner=runner,
            workdir=workdir,
            model=model,
            skill_path=skill_path,
            strict_skill=strict_skill,
            executable=executable or "codex",
            **options,
        )
    if normalized == "codeagent":
        options = {}
        if timeout_seconds is not None:
            options["timeout_seconds"] = timeout_seconds
        if max_attempts is not None:
            options["max_attempts"] = max_attempts
        return CodeAgentCliBackend(
            runner=runner,
            workdir=workdir,
            model=model,
            skill_path=skill_path,
            strict_skill=strict_skill,
            executable=executable or "codeagent",
            **options,
        )
    raise ValueError(f"Unknown adjudication backend: {name}")


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


def _has_local_risk_proof(packet: EvidencePacket) -> bool:
    origins = _tuple_field(packet, "origin_candidates")
    if any(origin.strip() == "nil" for origin in origins):
        return True
    return " and nil or " in packet.local_context


def _tuple_field(packet: EvidencePacket, key: str) -> tuple[str, ...]:
    value = packet.static_reasoning.get(key, ())
    if isinstance(value, tuple):
        return value
    return ()


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
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TypeError(f"{key} must be a string array")
    return tuple(value)


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
