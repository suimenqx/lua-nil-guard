from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_guard.agent_driver_manifest import (
    CODEAGENT_PROVIDER_SPEC,
    CLAUDE_PROVIDER_SPEC,
    CODEX_PROVIDER_SPEC,
    GEMINI_PROVIDER_SPEC,
    get_builtin_agent_provider_spec,
)
from lua_nil_guard.agent_backend import (
    DEFAULT_GEMINI_BACKEND_MODEL,
    BackendError,
    build_manifest_backed_backend_factory,
    build_provider_spec_backed_backend_factory,
    CliAgentBackend,
    ClaudeCliBackend,
    CodeAgentCliBackend,
    CodexCliBackend,
    create_adjudication_backend,
    get_cli_protocol_backend,
    get_adjudication_backend_factory,
    register_cli_protocol_backend,
    register_adjudication_backend,
    register_manifest_backed_adjudication_backend,
    unregister_adjudication_backend,
    unregister_cli_protocol_backend,
)
from lua_nil_guard.models import EvidencePacket, EvidenceTarget, SinkRule


class DemoCliBackend(CliAgentBackend):
    def build_command(
        self,
        *,
        schema_path: Path,
        output_path: Path,
        cwd: Path | None,
    ) -> tuple[str, ...]:
        return (
            "demo-cli",
            "--schema",
            str(schema_path),
            "-o",
            str(output_path),
        )


class _TraceCollector:
    def __init__(self) -> None:
        self.started: list[dict[str, object]] = []
        self.finished: list[dict[str, object]] = []
        self.failed: list[dict[str, object]] = []

    def on_call_started(
        self,
        *,
        case_id: str,
        attempt_no: int,
        stage: str,
        payload: dict[str, object],
    ) -> None:
        self.started.append(
            {
                "case_id": case_id,
                "attempt_no": attempt_no,
                "stage": stage,
                "payload": payload,
            }
        )

    def on_call_finished(
        self,
        *,
        case_id: str,
        attempt_no: int,
        stage: str,
        payload: dict[str, object],
    ) -> None:
        self.finished.append(
            {
                "case_id": case_id,
                "attempt_no": attempt_no,
                "stage": stage,
                "payload": payload,
            }
        )

    def on_call_failed(
        self,
        *,
        case_id: str,
        attempt_no: int,
        stage: str,
        payload: dict[str, object],
    ) -> None:
        self.failed.append(
            {
                "case_id": case_id,
                "attempt_no": attempt_no,
                "stage": stage,
                "payload": payload,
            }
        )


def test_cli_agent_backend_uses_custom_skill_path(tmp_path: Path) -> None:
    skill_path = _write_minimal_skill(tmp_path / "custom-skill.md", name="custom-adjudicator")
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        captured["stdin_text"] = stdin_text
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["custom skill"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["custom skill"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = DemoCliBackend(runner=fake_runner, skill_path=skill_path)
    backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert "Adjudication policy: custom-adjudicator" in str(captured["stdin_text"])


def test_cli_agent_backend_parses_structured_json_response(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        captured["command"] = command
        captured["stdin_text"] = stdin_text
        captured["cwd"] = cwd
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "risky",
                        "confidence": "medium",
                        "risk_path": ["req.params.username", "no guard before string.match"],
                        "safety_evidence": [],
                        "missing_evidence": [],
                        "recommended_next_action": "report",
                        "suggested_fix": "local safe_value = username or ''",
                    },
                    "defender": {
                        "role": "defender",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["no explicit guard"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "risky",
                        "confidence": "medium",
                        "risk_path": ["req.params.username", "no guard before string.match"],
                        "safety_evidence": [],
                        "counterarguments_considered": ["no explicit guard"],
                        "suggested_fix": "local safe_value = username or ''",
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = DemoCliBackend(runner=fake_runner, workdir=tmp_path)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.judge.status == "risky"
    assert record.prosecutor.role == "prosecutor"
    assert captured["cwd"] == tmp_path
    output_path = Path(captured["command"][captured["command"].index("-o") + 1])
    schema_path = Path(captured["command"][captured["command"].index("--schema") + 1])
    assert tmp_path in output_path.parents
    assert tmp_path in schema_path.parents
    assert "Adjudication policy: lua-nil-adjudicator" in str(captured["stdin_text"])
    assert "Unknown is not risk." in str(captured["stdin_text"])
    assert "prefer read-only evidence collection and cite concrete file:line evidence." in str(
        captured["stdin_text"]
    )


def test_cli_agent_backend_rejects_invalid_json_output() -> None:
    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text("not-json", encoding="utf-8")

    backend = DemoCliBackend(runner=fake_runner)

    with pytest.raises(BackendError, match="Invalid CLI backend JSON output"):
        backend.adjudicate(_sample_packet(), _sample_sink_rule())


def test_cli_agent_backend_reuses_cached_result_without_runner(tmp_path: Path) -> None:
    cache_path = tmp_path / "backend-cache.json"
    attempts = {"count": 0}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        attempts["count"] += 1
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["cached"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["cached"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = DemoCliBackend(runner=fake_runner, cache_path=cache_path)

    first = backend.adjudicate(_sample_packet(), _sample_sink_rule())
    second = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert first.judge.status == "safe"
    assert second.judge.status == "safe"
    assert attempts["count"] == 1
    assert backend.cache_hits == 1
    assert backend.cache_misses == 1
    assert backend.backend_call_count == 1
    assert backend.backend_total_seconds >= 0.0
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert len(payload) == 1


def test_cli_agent_backend_emits_cache_lookup_trace_events(tmp_path: Path) -> None:
    cache_path = tmp_path / "backend-cache.json"
    attempts = {"count": 0}
    collector = _TraceCollector()

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        attempts["count"] += 1
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["cached"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["cached"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = DemoCliBackend(runner=fake_runner, cache_path=cache_path)
    backend.set_trace_recorder(collector)
    backend.adjudicate(_sample_packet(), _sample_sink_rule())
    backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert attempts["count"] == 1
    cache_lookup_events = [event for event in collector.finished if event["stage"] == "cache_lookup"]
    assert len(cache_lookup_events) == 2
    assert cache_lookup_events[0]["payload"]["cache_hit"] is False
    assert cache_lookup_events[1]["payload"]["cache_hit"] is True


def test_codex_cli_backend_builds_expected_exec_command(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        captured["command"] = command
        captured["stdin_text"] = stdin_text
        captured["cwd"] = cwd
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["safety evidence blocks a clean risk proof"],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["if username then"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["if username then"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = CodexCliBackend(runner=fake_runner, workdir=tmp_path, model="o3")
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command[0:2] == ("codex", "exec")
    assert "--output-schema" in command
    assert "--skip-git-repo-check" in command
    assert "--sandbox" in command
    assert "-o" in command
    assert "-C" in command
    assert "-m" in command
    assert record.judge.status == "safe"


def test_codex_cli_backend_passes_config_overrides_to_exec_command(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        captured["command"] = command
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["guard"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["guard"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = CodexCliBackend(
        runner=fake_runner,
        workdir=tmp_path,
        config_overrides=("model='o3'", "features.fast=true"),
    )
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command.count("-c") == 2
    first = command.index("-c")
    second = command.index("-c", first + 1)
    assert command[first + 1] == "model='o3'"
    assert command[second + 1] == "features.fast=true"
    assert record.judge.status == "safe"


def test_codex_cli_backend_normalizes_relative_workdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        captured["command"] = command
        captured["cwd"] = cwd
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["guard"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["guard"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = CodexCliBackend(runner=fake_runner, workdir=Path("repo"))
    backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command[command.index("-C") + 1] == str(repo_dir.resolve())
    assert captured["cwd"] == repo_dir.resolve()


def test_codex_cli_backend_retries_after_backend_error(tmp_path: Path) -> None:
    attempts = {"count": 0}

    def flaky_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise BackendError("temporary codex failure")
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["guard"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["guard"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    backend = CodexCliBackend(runner=flaky_runner, workdir=tmp_path, max_attempts=2)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert attempts["count"] == 2
    assert record.judge.status == "safe"


def test_codex_cli_backend_falls_back_to_uncertain_after_exhausted_retries(tmp_path: Path) -> None:
    attempts = {"count": 0}
    collector = _TraceCollector()

    def failing_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        attempts["count"] += 1
        raise BackendError("temporary codex failure")

    backend = CodexCliBackend(runner=failing_runner, workdir=tmp_path, max_attempts=2)
    backend.set_trace_recorder(collector)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert attempts["count"] == 2
    assert record.judge.status == "uncertain"
    assert record.judge.needs_human is True
    assert record.judge.counterarguments_considered == ("temporary codex failure",)
    fallback_events = [event for event in collector.finished if event["stage"] == "fallback"]
    assert len(fallback_events) == 1
    assert fallback_events[0]["attempt_no"] == 2
    assert fallback_events[0]["payload"]["fallback_used"] is True


def test_claude_cli_backend_uses_claude_executable_by_default(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        captured["command"] = command
        captured["stdin_text"] = stdin_text
        captured["cwd"] = cwd
        return json.dumps(
            {
                "structured_output": {
                    "prosecutor": {
                        "role": "prosecutor",
                        "status": "uncertain",
                        "confidence": "low",
                        "risk_path": [],
                        "safety_evidence": [],
                        "missing_evidence": ["stub"],
                        "recommended_next_action": "expand_context",
                        "suggested_fix": None,
                    },
                    "defender": {
                        "role": "defender",
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["if username then"],
                        "missing_evidence": [],
                        "recommended_next_action": "suppress",
                        "suggested_fix": None,
                    },
                    "judge": {
                        "status": "safe",
                        "confidence": "high",
                        "risk_path": [],
                        "safety_evidence": ["if username then"],
                        "counterarguments_considered": [],
                        "suggested_fix": None,
                        "needs_human": False,
                    },
                }
            }
        )

    backend = ClaudeCliBackend(runner=fake_runner, workdir=tmp_path, model="sonnet")
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command[0] == "claude"
    assert "-p" in command
    assert "--output-format" in command
    assert command[command.index("--output-format") + 1] == "json"
    assert "--permission-mode" in command
    assert command[command.index("--permission-mode") + 1] == "dontAsk"
    assert "--json-schema" not in command
    assert "--tools" in command
    assert command[command.index("--tools") + 1] == ""
    assert "--no-session-persistence" in command
    assert "--model" in command
    assert command[-2] == "--"
    assert "Adjudication policy: lua-nil-adjudicator" in command[-1]
    assert "use only the prompt payload as admissible evidence." in command[-1]
    assert "The prosecutor and defender objects must each contain:" in command[-1]
    assert captured["stdin_text"] == ""
    assert captured["cwd"] == tmp_path
    assert record.judge.status == "safe"


def test_claude_cli_backend_accepts_result_string_payload() -> None:
    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        del command, stdin_text, cwd
        return json.dumps(
            {
                "result": json.dumps(
                    {
                        "prosecutor": {
                            "role": "prosecutor",
                            "status": "risky",
                            "confidence": "high",
                            "risk_path": ["req.params.username"],
                            "safety_evidence": [],
                            "missing_evidence": [],
                            "recommended_next_action": "report",
                            "suggested_fix": "username = username or ''",
                        },
                        "defender": {
                            "role": "defender",
                            "status": "uncertain",
                            "confidence": "low",
                            "risk_path": [],
                            "safety_evidence": [],
                            "missing_evidence": ["no guard"],
                            "recommended_next_action": "expand_context",
                            "suggested_fix": None,
                        },
                        "judge": {
                            "status": "risky",
                            "confidence": "high",
                            "risk_path": ["req.params.username"],
                            "safety_evidence": [],
                            "counterarguments_considered": ["no guard"],
                            "suggested_fix": "username = username or ''",
                            "needs_human": False,
                        },
                    }
                )
            }
        )

    backend = ClaudeCliBackend(runner=fake_runner)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.judge.status == "risky"


def test_claude_cli_backend_runs_optional_warmup_before_first_request(tmp_path: Path) -> None:
    commands: list[tuple[str, ...]] = []

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        assert stdin_text == ""
        assert cwd == tmp_path
        commands.append(command)
        prompt = command[-1]
        if 'Return exactly this JSON object and nothing else: {"ok": true}' in prompt:
            return json.dumps({"result": '{"ok": true}'})
        return json.dumps(
            {
                "result": json.dumps(
                    {
                        "prosecutor": {
                            "role": "prosecutor",
                            "status": "risky",
                            "confidence": "high",
                            "risk_path": ["nil"],
                            "safety_evidence": [],
                            "missing_evidence": [],
                            "recommended_next_action": "report",
                            "suggested_fix": "subject = subject or ''",
                        },
                        "defender": {
                            "role": "defender",
                            "status": "uncertain",
                            "confidence": "low",
                            "risk_path": [],
                            "safety_evidence": [],
                            "missing_evidence": ["no guard"],
                            "recommended_next_action": "expand_context",
                            "suggested_fix": None,
                        },
                        "judge": {
                            "status": "risky",
                            "confidence": "high",
                            "risk_path": ["nil"],
                            "safety_evidence": [],
                            "counterarguments_considered": ["no guard"],
                            "suggested_fix": "subject = subject or ''",
                            "needs_human": False,
                        },
                    }
                )
            }
        )

    backend = ClaudeCliBackend(
        runner=fake_runner,
        workdir=tmp_path,
        warmup_enabled=True,
    )
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.judge.status == "risky"
    assert len(commands) == 2
    assert 'Return exactly this JSON object and nothing else: {"ok": true}' in commands[0][-1]
    assert "Adjudication policy: lua-nil-adjudicator" in commands[1][-1]
    assert backend.backend_call_count == 2
    assert backend.backend_warmup_call_count == 1
    assert backend.backend_warmup_total_seconds >= 0.0


def test_codeagent_cli_backend_uses_gemini_executable_by_default(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        captured["command"] = command
        captured["stdin_text"] = stdin_text
        captured["cwd"] = cwd
        return json.dumps(
            {
                "response": json.dumps(
                    {
                        "prosecutor": {
                            "role": "prosecutor",
                            "status": "uncertain",
                            "confidence": "low",
                            "risk_path": [],
                            "safety_evidence": [],
                            "missing_evidence": ["stub"],
                            "recommended_next_action": "expand_context",
                            "suggested_fix": None,
                        },
                        "defender": {
                            "role": "defender",
                            "status": "safe",
                            "confidence": "high",
                            "risk_path": [],
                            "safety_evidence": ["if username then"],
                            "missing_evidence": [],
                            "recommended_next_action": "suppress",
                            "suggested_fix": None,
                        },
                        "judge": {
                            "status": "safe",
                            "confidence": "high",
                            "risk_path": [],
                            "safety_evidence": ["if username then"],
                            "counterarguments_considered": [],
                            "suggested_fix": None,
                            "needs_human": False,
                        },
                    }
                )
            }
        )

    backend = CodeAgentCliBackend(runner=fake_runner, workdir=tmp_path, model="codeagent-test-model")
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command[0] == "gemini"
    assert "exec" not in command
    assert "--output-format" in command
    assert command[command.index("--output-format") + 1] == "json"
    assert "-m" in command
    prompt_argument = command[-1]
    assert "Adjudication policy: lua-nil-adjudicator" in prompt_argument
    assert "use only the prompt payload as admissible evidence." in prompt_argument
    assert captured["stdin_text"] == ""
    assert captured["cwd"] == tmp_path
    assert record.judge.status == "safe"


def test_codeagent_cli_backend_direct_prompt_command_uses_gemini_prompt_flag() -> None:
    backend = CodeAgentCliBackend(model="codeagent-test-model")

    command = backend.build_prompt_command(prompt="judge this case", cwd=None)

    assert command == (
        "gemini",
        "--output-format",
        "json",
        "-m",
        "codeagent-test-model",
        "--prompt",
        "judge this case",
    )


def test_codeagent_cli_backend_uses_positional_prompt_for_non_gemini_executable() -> None:
    backend = CodeAgentCliBackend(
        model="codeagent-test-model",
        executable="custom-agent",
    )

    command = backend.build_prompt_command(prompt="judge this case", cwd=None)

    assert command == (
        "custom-agent",
        "--output-format",
        "json",
        "-m",
        "codeagent-test-model",
        "judge this case",
    )


def test_codeagent_cli_backend_rejects_unsupported_config_overrides() -> None:
    backend = CodeAgentCliBackend(config_overrides=("features.fast=true",))

    with pytest.raises(BackendError, match="does not support config overrides"):
        backend.build_prompt_command(prompt="judge this case", cwd=None)


def test_codeagent_cli_backend_accepts_markdown_wrapped_json_response() -> None:
    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        return json.dumps(
            {
                "response": "\n".join(
                    [
                        "```json",
                        json.dumps(
                            {
                                "prosecutor": {
                                    "role": "prosecutor",
                                    "status": "risky",
                                    "confidence": "high",
                                    "risk_path": ["req.params.username"],
                                    "safety_evidence": [],
                                    "missing_evidence": [],
                                    "recommended_next_action": "report",
                                    "suggested_fix": "local safe_value = username or ''",
                                },
                                "defender": {
                                    "role": "defender",
                                    "status": "uncertain",
                                    "confidence": "low",
                                    "risk_path": [],
                                    "safety_evidence": [],
                                    "missing_evidence": ["no guard"],
                                    "recommended_next_action": "expand_context",
                                    "suggested_fix": None,
                                },
                                "judge": {
                                    "status": "risky",
                                    "confidence": "high",
                                    "risk_path": ["req.params.username"],
                                    "safety_evidence": [],
                                    "counterarguments_considered": ["no guard"],
                                    "suggested_fix": "local safe_value = username or ''",
                                    "needs_human": False,
                                },
                            }
                        ),
                        "```",
                    ]
                )
            }
        )

    backend = CodeAgentCliBackend(runner=fake_runner)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.judge.status == "risky"


def test_codeagent_cli_backend_coerces_string_fields_into_singleton_arrays() -> None:
    def fake_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        del command, stdin_text, cwd
        return json.dumps(
            {
                "response": json.dumps(
                    {
                        "prosecutor": {
                            "role": "Prosecutor",
                            "status": "risky",
                            "confidence": "high",
                            "risk_path": "local username = nil",
                            "safety_evidence": [],
                            "missing_evidence": "",
                            "recommended_next_action": "report",
                            "suggested_fix": None,
                        },
                        "defender": {
                            "role": "Defender",
                            "status": "uncertain",
                            "confidence": "low",
                            "risk_path": [],
                            "safety_evidence": [],
                            "missing_evidence": "no explicit guard",
                            "recommended_next_action": "expand_context",
                            "suggested_fix": None,
                        },
                        "judge": {
                            "status": "risky",
                            "confidence": "high",
                            "risk_path": "local username = nil",
                            "safety_evidence": [],
                            "counterarguments_considered": "direct nil assignment observed",
                            "suggested_fix": "username = username or ''",
                            "needs_human": False,
                        },
                    }
                )
            }
        )

    backend = CodeAgentCliBackend(runner=fake_runner)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.prosecutor.risk_path == ("local username = nil",)
    assert record.prosecutor.missing_evidence == ()
    assert record.defender.missing_evidence == ("no explicit guard",)
    assert record.judge.risk_path == ("local username = nil",)
    assert record.judge.counterarguments_considered == ("direct nil assignment observed",)


def test_codeagent_cli_backend_falls_back_to_uncertain_after_exhausted_retries() -> None:
    attempts = {"count": 0}

    def failing_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> str:
        attempts["count"] += 1
        raise BackendError("temporary codeagent failure")

    backend = CodeAgentCliBackend(runner=failing_runner)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert attempts["count"] == 2
    assert record.judge.status == "uncertain"
    assert record.judge.counterarguments_considered == ("temporary codeagent failure",)


def test_codeagent_cli_backend_simulates_headless_json_subprocess(tmp_path: Path) -> None:
    executable = tmp_path / "codeagent"
    executable.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import json",
                "import sys",
                "",
                "args = sys.argv[1:]",
                "assert '--output-format' in args",
                "assert args[args.index('--output-format') + 1] == 'json'",
                "assert '-p' not in args",
                "assert args[-1]",
                "payload = {",
                "    'prosecutor': {",
                "        'role': 'prosecutor',",
                "        'status': 'uncertain',",
                "        'confidence': 'low',",
                "        'risk_path': [],",
                "        'safety_evidence': [],",
                "        'missing_evidence': ['stub'],",
                "        'recommended_next_action': 'expand_context',",
                "        'suggested_fix': None,",
                "    },",
                "    'defender': {",
                "        'role': 'defender',",
                "        'status': 'safe',",
                "        'confidence': 'high',",
                "        'risk_path': [],",
                "        'safety_evidence': ['if username then'],",
                "        'missing_evidence': [],",
                "        'recommended_next_action': 'suppress',",
                "        'suggested_fix': None,",
                "    },",
                "    'judge': {",
                "        'status': 'safe',",
                "        'confidence': 'high',",
                "        'risk_path': [],",
                "        'safety_evidence': ['if username then'],",
                "        'counterarguments_considered': [],",
                "        'suggested_fix': None,",
                "        'needs_human': False,",
                "    },",
                "}",
                "print(json.dumps({'response': json.dumps(payload)}))",
            ]
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)

    backend = CodeAgentCliBackend(
        executable=str(executable),
        workdir=tmp_path,
        model="codeagent-test-model",
    )
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.judge.status == "safe"


def test_create_adjudication_backend_builds_selected_backend() -> None:
    heuristic = create_adjudication_backend("heuristic")
    codex = create_adjudication_backend("codex", model="o3")
    claude = create_adjudication_backend("claude", model="sonnet")
    gemini = create_adjudication_backend("gemini")
    codeagent = create_adjudication_backend("codeagent")

    assert heuristic.__class__.__name__ == "HeuristicAdjudicationBackend"
    assert isinstance(codex, CodexCliBackend)
    assert isinstance(claude, ClaudeCliBackend)
    assert isinstance(gemini, CodeAgentCliBackend)
    assert isinstance(codeagent, CodeAgentCliBackend)


def test_backend_factory_registry_exposes_builtin_factories() -> None:
    heuristic_factory = get_adjudication_backend_factory("heuristic")
    codex_factory = get_adjudication_backend_factory("codex")
    claude_factory = get_adjudication_backend_factory("claude")
    gemini_factory = get_adjudication_backend_factory("gemini")
    codeagent_factory = get_adjudication_backend_factory("codeagent")

    assert callable(heuristic_factory)
    assert callable(codex_factory)
    assert callable(claude_factory)
    assert callable(gemini_factory)
    assert callable(codeagent_factory)
    assert heuristic_factory().__class__.__name__ == "HeuristicAdjudicationBackend"


def test_cli_protocol_backend_registry_exposes_builtin_backend_types() -> None:
    assert get_cli_protocol_backend("schema_file_cli") is CodexCliBackend
    assert get_cli_protocol_backend("stdout_structured_cli") is ClaudeCliBackend
    assert get_cli_protocol_backend("stdout_envelope_cli") is CodeAgentCliBackend


def test_build_manifest_backed_backend_factory_uses_provider_protocol_mapping() -> None:
    codex_factory = build_manifest_backed_backend_factory("codex")
    claude_factory = build_manifest_backed_backend_factory("claude")
    gemini_factory = build_manifest_backed_backend_factory("gemini")
    codeagent_factory = build_manifest_backed_backend_factory("codeagent")

    codex = codex_factory(model="o3")
    claude = claude_factory(model="sonnet")
    gemini = gemini_factory()
    codeagent = codeagent_factory()

    assert isinstance(codex, CodexCliBackend)
    assert codex.provider_spec == CODEX_PROVIDER_SPEC
    assert isinstance(claude, ClaudeCliBackend)
    assert claude.provider_spec == CLAUDE_PROVIDER_SPEC
    assert isinstance(gemini, CodeAgentCliBackend)
    assert gemini.provider_spec == GEMINI_PROVIDER_SPEC
    assert isinstance(codeagent, CodeAgentCliBackend)
    assert codeagent.provider_spec == CODEAGENT_PROVIDER_SPEC


def test_build_provider_spec_backed_backend_factory_uses_explicit_spec() -> None:
    factory = build_provider_spec_backed_backend_factory(CLAUDE_PROVIDER_SPEC)
    backend = factory(model="custom-model")

    assert isinstance(backend, ClaudeCliBackend)
    assert backend.provider_spec == CLAUDE_PROVIDER_SPEC
    assert backend.model == "custom-model"


def test_backend_factory_registry_supports_custom_registration() -> None:
    calls: list[str] = []

    def custom_factory(**_kwargs) -> object:
        calls.append("called")
        return HeuristicSentinel()

    class HeuristicSentinel:
        pass

    register_adjudication_backend("custom-test", custom_factory)
    try:
        backend = create_adjudication_backend("custom-test")
        assert get_adjudication_backend_factory("custom-test") is custom_factory
        assert isinstance(backend, HeuristicSentinel)
        assert calls == ["called"]
    finally:
        unregister_adjudication_backend("custom-test")


def test_cli_protocol_backend_registry_supports_custom_registration() -> None:
    class DemoProtocolBackend(CliAgentBackend):
        def build_command(
            self,
            *,
            schema_path: Path,
            output_path: Path,
            cwd: Path | None,
        ) -> tuple[str, ...]:
            return ("demo", str(schema_path), str(output_path), str(cwd) if cwd else "")

    register_cli_protocol_backend("demo_protocol", DemoProtocolBackend)
    try:
        assert get_cli_protocol_backend("demo_protocol") is DemoProtocolBackend
    finally:
        unregister_cli_protocol_backend("demo_protocol")


def test_register_manifest_backed_adjudication_backend_loads_custom_provider(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "claude-code.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "claude-code",
                "protocol": "stdout_envelope_cli",
                "default_executable": "claude-code",
                "default_timeout_seconds": 30.0,
                "default_max_attempts": 2,
                "default_fallback_to_uncertain_on_error": True,
                "default_expanded_evidence_retry_mode": "on",
                "capabilities": {
                    "supports_model_override": True,
                    "supports_config_overrides": True,
                    "supports_stdout_json": True,
                },
            }
        ),
        encoding="utf-8",
    )

    provider_spec = register_manifest_backed_adjudication_backend(manifest_path)
    try:
        backend = create_adjudication_backend("claude-code")
        assert isinstance(backend, CodeAgentCliBackend)
        assert backend.provider_spec == provider_spec
        assert backend.executable == "claude-code"
        assert backend.timeout_seconds == 30.0
        assert backend.expanded_evidence_retry is True
    finally:
        unregister_adjudication_backend("claude-code")


def test_register_manifest_backed_adjudication_backend_loads_structured_stdout_provider(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "claude-live.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "claude-live",
                "protocol": "stdout_structured_cli",
                "default_executable": "claude",
                "default_timeout_seconds": 25.0,
                "default_max_attempts": 1,
                "default_fallback_to_uncertain_on_error": True,
                "default_expanded_evidence_retry_mode": "off",
                "capabilities": {
                    "supports_model_override": True,
                    "supports_config_overrides": False,
                    "supports_output_schema": True,
                    "supports_stdout_json": True,
                },
            }
        ),
        encoding="utf-8",
    )

    provider_spec = register_manifest_backed_adjudication_backend(manifest_path)
    try:
        backend = create_adjudication_backend("claude-live", model="sonnet")
        assert isinstance(backend, ClaudeCliBackend)
        assert backend.provider_spec == provider_spec
        assert backend.executable == "claude"
        assert backend.timeout_seconds == 25.0
        assert backend.expanded_evidence_retry is False
    finally:
        unregister_adjudication_backend("claude-live")


def test_builtin_provider_specs_describe_supported_cli_protocols() -> None:
    assert get_builtin_agent_provider_spec("codex") == CODEX_PROVIDER_SPEC
    assert CODEX_PROVIDER_SPEC.protocol == "schema_file_cli"
    assert CODEX_PROVIDER_SPEC.capabilities.supports_output_schema is True
    assert CODEX_PROVIDER_SPEC.capabilities.supports_output_file is True

    assert get_builtin_agent_provider_spec("claude") == CLAUDE_PROVIDER_SPEC
    assert CLAUDE_PROVIDER_SPEC.protocol == "stdout_structured_cli"
    assert CLAUDE_PROVIDER_SPEC.capabilities.supports_stdout_json is True
    assert CLAUDE_PROVIDER_SPEC.capabilities.supports_config_overrides is False

    assert get_builtin_agent_provider_spec("gemini") == GEMINI_PROVIDER_SPEC
    assert GEMINI_PROVIDER_SPEC.protocol == "stdout_envelope_cli"
    assert GEMINI_PROVIDER_SPEC.capabilities.supports_stdout_json is True
    assert GEMINI_PROVIDER_SPEC.capabilities.supports_config_overrides is False
    assert GEMINI_PROVIDER_SPEC.capabilities.supports_output_file is False
    assert GEMINI_PROVIDER_SPEC.default_executable == "gemini"

    assert get_builtin_agent_provider_spec("codeagent") == CODEAGENT_PROVIDER_SPEC
    assert CODEAGENT_PROVIDER_SPEC.protocol == "stdout_envelope_cli"
    assert CODEAGENT_PROVIDER_SPEC.capabilities.supports_stdout_json is True
    assert CODEAGENT_PROVIDER_SPEC.capabilities.supports_config_overrides is False
    assert CODEAGENT_PROVIDER_SPEC.capabilities.supports_output_file is False
    assert CODEAGENT_PROVIDER_SPEC.default_executable == "gemini"


def test_create_adjudication_backend_passes_skill_path_to_cli_backend(tmp_path: Path) -> None:
    skill_path = _write_minimal_skill(tmp_path / "factory-skill.md", name="factory-skill")
    backend = create_adjudication_backend("codex", skill_path=skill_path)

    assert isinstance(backend, CodexCliBackend)
    assert backend.skill_path == skill_path


def test_create_adjudication_backend_passes_executable_override() -> None:
    backend = create_adjudication_backend("codeagent", executable="/tmp/codeagent-bin")

    assert isinstance(backend, CodeAgentCliBackend)
    assert backend.executable == "/tmp/codeagent-bin"


def test_create_adjudication_backend_passes_timeout_and_attempts() -> None:
    backend = create_adjudication_backend(
        "codex",
        timeout_seconds=12.5,
        max_attempts=3,
    )

    assert isinstance(backend, CodexCliBackend)
    assert backend.timeout_seconds == 12.5
    assert backend.max_attempts == 3


def test_create_adjudication_backend_passes_expanded_evidence_retry_override() -> None:
    backend = create_adjudication_backend(
        "gemini",
        expanded_evidence_retry=True,
    )

    assert isinstance(backend, CodeAgentCliBackend)
    assert backend.expanded_evidence_retry is True


def test_create_adjudication_backend_passes_config_overrides() -> None:
    backend = create_adjudication_backend(
        "codex",
        config_overrides=("features.fast=true",),
    )

    assert isinstance(backend, CodexCliBackend)
    assert backend.config_overrides == ("features.fast=true",)


def test_create_adjudication_backend_passes_config_overrides_to_codeagent() -> None:
    with pytest.raises(ValueError, match="does not support backend config overrides"):
        create_adjudication_backend(
            "codeagent",
            config_overrides=("features.fast=true",),
        )


def test_create_adjudication_backend_rejects_unsupported_config_overrides() -> None:
    with pytest.raises(ValueError, match="does not support backend config overrides"):
        create_adjudication_backend(
            "claude",
            config_overrides=("features.fast=true",),
        )


def test_create_adjudication_backend_uses_codex_like_defaults_for_codeagent() -> None:
    backend = create_adjudication_backend("codeagent")

    assert isinstance(backend, CodeAgentCliBackend)
    assert backend.provider_spec == CODEAGENT_PROVIDER_SPEC
    assert backend.timeout_seconds == 45.0
    assert backend.max_attempts == 2
    assert backend.fallback_to_uncertain_on_error is True


def test_create_adjudication_backend_uses_builtin_defaults_for_gemini() -> None:
    backend = create_adjudication_backend("gemini")

    assert isinstance(backend, CodeAgentCliBackend)
    assert backend.provider_spec == GEMINI_PROVIDER_SPEC
    assert backend.model == DEFAULT_GEMINI_BACKEND_MODEL
    assert backend.expanded_evidence_retry is None
    assert backend.timeout_seconds == 45.0
    assert backend.max_attempts == 2
    assert backend.fallback_to_uncertain_on_error is True


def test_create_adjudication_backend_uses_builtin_defaults_for_claude() -> None:
    backend = create_adjudication_backend("claude")

    assert isinstance(backend, ClaudeCliBackend)
    assert backend.provider_spec == CLAUDE_PROVIDER_SPEC
    assert backend.timeout_seconds == 75.0
    assert backend.max_attempts == 2
    assert backend.fallback_to_uncertain_on_error is True


def test_create_adjudication_backend_attaches_builtin_provider_specs() -> None:
    codex = create_adjudication_backend("codex")
    claude = create_adjudication_backend("claude")
    gemini = create_adjudication_backend("gemini")
    codeagent = create_adjudication_backend("codeagent")

    assert isinstance(codex, CodexCliBackend)
    assert codex.provider_spec == CODEX_PROVIDER_SPEC
    assert codex.executable == CODEX_PROVIDER_SPEC.default_executable

    assert isinstance(claude, ClaudeCliBackend)
    assert claude.provider_spec == CLAUDE_PROVIDER_SPEC
    assert claude.executable == CLAUDE_PROVIDER_SPEC.default_executable

    assert isinstance(gemini, CodeAgentCliBackend)
    assert gemini.provider_spec == GEMINI_PROVIDER_SPEC
    assert gemini.executable == GEMINI_PROVIDER_SPEC.default_executable

    assert isinstance(codeagent, CodeAgentCliBackend)
    assert codeagent.provider_spec == CODEAGENT_PROVIDER_SPEC
    assert codeagent.executable == CODEAGENT_PROVIDER_SPEC.default_executable


def test_create_adjudication_backend_passes_cache_path(tmp_path: Path) -> None:
    cache_path = tmp_path / "backend-cache.json"
    backend = create_adjudication_backend(
        "codex",
        cache_path=cache_path,
    )

    assert isinstance(backend, CodexCliBackend)
    assert backend.cache_path == cache_path


def _sample_packet() -> EvidencePacket:
    return EvidencePacket(
        case_id="case_cli_backend",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=8,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="local username = req.params.username\nreturn string.match(username, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
    )


def _sample_sink_rule() -> SinkRule:
    return SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''",),
    )


def _write_minimal_skill(path: Path, *, name: str) -> Path:
    path.write_text(
        "\n".join(
            [
                "---",
                f"name: {name}",
                "description: Test skill.",
                "skill_contract: lua-nil-adjudicator/v1",
                "---",
                "",
                "## Goal",
                "- Keep precision high.",
                "",
                "## Required Review Order",
                "1. Read the sink.",
                "",
                "## Canonical Principles",
                "- Unknown is not risk.",
                "- Absence of proof is not proof of bug.",
                "",
                "## Hard Rules",
                "- Return `uncertain` when evidence is incomplete.",
                "- Do not assume undocumented business guarantees.",
                "",
                "## Evidence Checklist",
                "- variable origin",
                "",
                "## Output Contract",
                "- `status`: `safe`, `risky`, or `uncertain`",
                "",
                "## Review Bias",
                "- Prefer silence over speculative warnings.",
            ]
        ),
        encoding="utf-8",
    )
    return path
