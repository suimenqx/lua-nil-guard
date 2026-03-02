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
    assert "Do not execute shell commands, open files, or inspect the repository." in str(captured["stdin_text"])


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
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert len(payload) == 1


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

    def failing_runner(
        command: tuple[str, ...],
        *,
        stdin_text: str,
        cwd: Path | None,
    ) -> None:
        attempts["count"] += 1
        raise BackendError("temporary codex failure")

    backend = CodexCliBackend(runner=failing_runner, workdir=tmp_path, max_attempts=2)
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    assert attempts["count"] == 2
    assert record.judge.status == "uncertain"
    assert record.judge.needs_human is True
    assert record.judge.counterarguments_considered == ("temporary codex failure",)


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

    backend = CodeAgentCliBackend(runner=fake_runner, workdir=tmp_path, model="codeagent-test-model")
    record = backend.adjudicate(_sample_packet(), _sample_sink_rule())

    command = captured["command"]
    assert command[0] == "codeagent"
    assert "exec" not in command
    assert "--output-format" in command
    assert command[command.index("--output-format") + 1] == "json"
    assert "-p" in command
    assert "-m" in command
    prompt_argument = command[command.index("-p") + 1]
    assert "Adjudication policy: lua-nil-adjudicator" in prompt_argument
    assert "Use only the prompt payload as admissible evidence." in prompt_argument
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
        model="codeagent-test-model",
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


def test_create_adjudication_backend_passes_config_overrides() -> None:
    backend = create_adjudication_backend(
        "codex",
        config_overrides=("features.fast=true",),
    )

    assert isinstance(backend, CodexCliBackend)
    assert backend.config_overrides == ("features.fast=true",)


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
