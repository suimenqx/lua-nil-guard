from __future__ import annotations

import json
from pathlib import Path

import pytest

from lua_nil_review_agent.agent_backend import (
    BackendError,
    CliAgentBackend,
    CodeAgentCliBackend,
    CodexCliBackend,
    create_adjudication_backend,
)
from lua_nil_review_agent.models import EvidencePacket, EvidenceTarget, SinkRule


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
    assert "Unknown is not risk." in str(captured["stdin_text"])


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


def test_codeagent_cli_backend_uses_codeagent_executable_by_default(tmp_path: Path) -> None:
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

    backend = CodeAgentCliBackend(runner=fake_runner, workdir=tmp_path, model="gemini-2.5-pro")
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command[0] == "codeagent"
    assert "exec" not in command
    assert "--output-format" in command
    assert command[command.index("--output-format") + 1] == "json"
    assert "-p" in command
    assert "-m" in command
    assert captured["stdin_text"] == ""
    assert captured["cwd"] == tmp_path
    assert record.judge.status == "safe"


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


def test_codeagent_cli_backend_simulates_gemini_style_subprocess(tmp_path: Path) -> None:
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
                "assert '-p' in args",
                "assert args[args.index('-p') + 1]",
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
        model="gemini-2.5-pro",
    )
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert record.judge.status == "safe"


def test_create_adjudication_backend_builds_selected_backend() -> None:
    heuristic = create_adjudication_backend("heuristic")
    codex = create_adjudication_backend("codex", model="o3")
    codeagent = create_adjudication_backend("codeagent")

    assert heuristic.__class__.__name__ == "HeuristicAdjudicationBackend"
    assert isinstance(codex, CodexCliBackend)
    assert isinstance(codeagent, CodeAgentCliBackend)


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
