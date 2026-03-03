from __future__ import annotations

from pathlib import Path

import pytest

from lua_nil_review_agent.agent_protocols import (
    CLI_PROTOCOL_BUILDERS,
    SchemaFileCliProtocol,
    StdoutEnvelopeCliProtocol,
    StdoutStructuredCliProtocol,
    get_cli_protocol_builder,
)


def test_get_cli_protocol_builder_returns_registered_builders() -> None:
    schema_builder = get_cli_protocol_builder("schema_file_cli")
    structured_builder = get_cli_protocol_builder("stdout_structured_cli")
    stdout_builder = get_cli_protocol_builder("stdout_envelope_cli")

    assert isinstance(schema_builder, SchemaFileCliProtocol)
    assert isinstance(structured_builder, StdoutStructuredCliProtocol)
    assert isinstance(stdout_builder, StdoutEnvelopeCliProtocol)
    assert CLI_PROTOCOL_BUILDERS["schema_file_cli"] is schema_builder
    assert CLI_PROTOCOL_BUILDERS["stdout_structured_cli"] is structured_builder
    assert CLI_PROTOCOL_BUILDERS["stdout_envelope_cli"] is stdout_builder


def test_get_cli_protocol_builder_rejects_unknown_names() -> None:
    with pytest.raises(ValueError, match="Unknown CLI protocol builder"):
        get_cli_protocol_builder("claude_sdk")


def test_schema_file_cli_protocol_builds_expected_command() -> None:
    builder = get_cli_protocol_builder("schema_file_cli")
    assert isinstance(builder, SchemaFileCliProtocol)

    command = builder.build_command(
        executable="codex",
        base_args=("exec", "--sandbox", "read-only"),
        config_overrides=("model='o3'", "features.fast=true"),
        schema_path=Path("/tmp/schema.json"),
        output_path=Path("/tmp/result.json"),
        schema_flag="--output-schema",
        output_flag="-o",
        cwd=Path("/repo"),
        cwd_flag="-C",
        model="o3",
        model_flag="-m",
        stdin_sentinel="-",
    )

    assert command == (
        "codex",
        "exec",
        "--sandbox",
        "read-only",
        "-c",
        "model='o3'",
        "-c",
        "features.fast=true",
        "--output-schema",
        "/tmp/schema.json",
        "-o",
        "/tmp/result.json",
        "-C",
        "/repo",
        "-m",
        "o3",
        "-",
    )


def test_stdout_envelope_cli_protocol_builds_expected_command() -> None:
    builder = get_cli_protocol_builder("stdout_envelope_cli")
    assert isinstance(builder, StdoutEnvelopeCliProtocol)

    command = builder.build_command(
        executable="codeagent",
        base_args=("--output-format", "json"),
        config_overrides=("features.fast=true",),
        model="fast-model",
        model_flag="-m",
        prompt="judge this case",
        prompt_flag=None,
    )

    assert command == (
        "codeagent",
        "--output-format",
        "json",
        "-c",
        "features.fast=true",
        "-m",
        "fast-model",
        "judge this case",
    )


def test_stdout_envelope_cli_protocol_supports_prompt_flags() -> None:
    builder = get_cli_protocol_builder("stdout_envelope_cli")
    assert isinstance(builder, StdoutEnvelopeCliProtocol)

    command = builder.build_command(
        executable="custom-agent",
        base_args=("--output-format", "json"),
        config_overrides=(),
        model=None,
        model_flag="-m",
        prompt="judge this case",
        prompt_flag="-p",
    )

    assert command == (
        "custom-agent",
        "--output-format",
        "json",
        "-p",
        "judge this case",
    )


def test_stdout_structured_cli_protocol_builds_expected_command() -> None:
    builder = get_cli_protocol_builder("stdout_structured_cli")
    assert isinstance(builder, StdoutStructuredCliProtocol)

    command = builder.build_command(
        executable="claude",
        base_args=("--output-format", "json", "--tools", ""),
        model="sonnet",
        model_flag="--model",
        schema='{"type":"object"}',
        schema_flag="--json-schema",
        print_flag="-p",
        prompt="judge this case",
    )

    assert command == (
        "claude",
        "-p",
        "--output-format",
        "json",
        "--tools",
        "",
        "--json-schema",
        '{"type":"object"}',
        "--model",
        "sonnet",
        "--",
        "judge this case",
    )
