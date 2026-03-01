from __future__ import annotations

import json
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
        return adjudicate_packet(packet, sink_rule)


class CliAgentBackend:
    """Base class for CLI-backed adjudication providers."""

    def __init__(
        self,
        *,
        runner=None,
        workdir: str | Path | None = None,
    ) -> None:
        self.runner = runner or _default_runner
        self.workdir = Path(workdir) if workdir is not None else None

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        prompt = self.build_prompt(packet=packet, sink_rule=sink_rule)
        with tempfile.TemporaryDirectory(prefix="lua_nil_review_agent_") as temp_dir:
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
            self.runner(command, stdin_text=prompt, cwd=self.workdir)
            if not output_path.exists():
                raise BackendError("CLI backend did not write an output file")
            raw = output_path.read_text(encoding="utf-8")
        return self.parse_response(raw, case_id=packet.case_id)

    def build_prompt(self, *, packet: EvidencePacket, sink_rule: SinkRule) -> str:
        """Render the adjudication prompt consumed by the CLI provider."""

        return "\n".join(
            [
                build_adjudication_prompt(packet=packet, sink_rule=sink_rule),
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
        model: str | None = None,
        sandbox: str = "read-only",
        executable: str = "codex",
    ) -> None:
        super().__init__(runner=runner, workdir=workdir)
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
        model: str | None = None,
        executable: str = "codeagent",
    ) -> None:
        super().__init__(runner=runner, workdir=workdir)
        self.model = model
        self.executable = executable

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        prompt = self.build_prompt(packet=packet, sink_rule=sink_rule)
        command = self.build_prompt_command(prompt=prompt, cwd=self.workdir)
        raw = self.runner(command, stdin_text="", cwd=self.workdir)
        if not isinstance(raw, str) or not raw.strip():
            raise BackendError("CodeAgent CLI backend did not return JSON on stdout")
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
            raise BackendError("Invalid CodeAgent JSON envelope") from exc
        if not isinstance(payload, dict):
            raise BackendError("CodeAgent JSON envelope must be an object")

        if {"prosecutor", "defender", "judge"}.issubset(payload.keys()):
            return self.parse_response(raw, case_id=case_id)

        response = payload.get("response")
        if not isinstance(response, str):
            raise BackendError("CodeAgent JSON envelope must contain a string response field")

        return self.parse_response(_strip_markdown_fences(response), case_id=case_id)


def create_adjudication_backend(
    name: str,
    *,
    workdir: str | Path | None = None,
    model: str | None = None,
    runner=None,
) -> AdjudicationBackend:
    """Create a named adjudication backend."""

    normalized = name.strip().lower()
    if normalized == "heuristic":
        return HeuristicAdjudicationBackend()
    if normalized == "codex":
        return CodexCliBackend(runner=runner, workdir=workdir, model=model)
    if normalized == "codeagent":
        return CodeAgentCliBackend(runner=runner, workdir=workdir, model=model)
    raise ValueError(f"Unknown adjudication backend: {name}")


def _default_runner(
    command: tuple[str, ...],
    *,
    stdin_text: str,
    cwd: Path | None,
) -> str:
    result = subprocess.run(
        command,
        input=stdin_text,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise BackendError(
            f"CLI backend command failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


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
