from __future__ import annotations

from pathlib import Path
from typing import Protocol


class CliProtocolBuilder(Protocol):
    """Protocol interface for command-building strategies."""

    name: str


class SchemaFileCliProtocol:
    """Build commands for CLIs that consume schema/output files."""

    name = "schema_file_cli"

    def build_command(
        self,
        *,
        executable: str,
        base_args: tuple[str, ...],
        config_overrides: tuple[str, ...],
        schema_path: Path,
        output_path: Path,
        schema_flag: str,
        output_flag: str,
        cwd: Path | None,
        cwd_flag: str | None,
        model: str | None,
        model_flag: str | None,
        stdin_sentinel: str | None,
    ) -> tuple[str, ...]:
        command: list[str] = [executable, *base_args]
        for override in config_overrides:
            command.extend(["-c", override])
        command.extend([schema_flag, str(schema_path), output_flag, str(output_path)])
        if cwd is not None and cwd_flag is not None:
            command.extend([cwd_flag, str(cwd)])
        if model is not None and model_flag is not None:
            command.extend([model_flag, model])
        if stdin_sentinel is not None:
            command.append(stdin_sentinel)
        return tuple(command)


class StdoutEnvelopeCliProtocol:
    """Build commands for CLIs that emit JSON on stdout from prompt args."""

    name = "stdout_envelope_cli"

    def build_command(
        self,
        *,
        executable: str,
        base_args: tuple[str, ...],
        config_overrides: tuple[str, ...],
        model: str | None,
        model_flag: str | None,
        prompt: str,
        prompt_flag: str | None,
    ) -> tuple[str, ...]:
        command: list[str] = [executable, *base_args]
        for override in config_overrides:
            command.extend(["-c", override])
        if model is not None and model_flag is not None:
            command.extend([model_flag, model])
        if prompt_flag is None:
            command.append(prompt)
        else:
            command.extend([prompt_flag, prompt])
        return tuple(command)


class StdoutStructuredCliProtocol:
    """Build commands for CLIs that emit a structured JSON envelope on stdout."""

    name = "stdout_structured_cli"

    def build_command(
        self,
        *,
        executable: str,
        base_args: tuple[str, ...],
        model: str | None,
        model_flag: str | None,
        schema: str | None,
        schema_flag: str | None,
        print_flag: str,
        prompt: str,
    ) -> tuple[str, ...]:
        command: list[str] = [executable, print_flag, *base_args]
        if schema is not None and schema_flag is not None:
            command.extend([schema_flag, schema])
        if model is not None and model_flag is not None:
            command.extend([model_flag, model])
        command.extend(["--", prompt])
        return tuple(command)


_SCHEMA_FILE_CLI_PROTOCOL = SchemaFileCliProtocol()
_STDOUT_STRUCTURED_CLI_PROTOCOL = StdoutStructuredCliProtocol()
_STDOUT_ENVELOPE_CLI_PROTOCOL = StdoutEnvelopeCliProtocol()


CLI_PROTOCOL_BUILDERS: dict[str, CliProtocolBuilder] = {
    _SCHEMA_FILE_CLI_PROTOCOL.name: _SCHEMA_FILE_CLI_PROTOCOL,
    _STDOUT_STRUCTURED_CLI_PROTOCOL.name: _STDOUT_STRUCTURED_CLI_PROTOCOL,
    _STDOUT_ENVELOPE_CLI_PROTOCOL.name: _STDOUT_ENVELOPE_CLI_PROTOCOL,
}


def get_cli_protocol_builder(name: str) -> CliProtocolBuilder:
    """Return the registered command builder for a protocol name."""

    normalized = name.strip().lower()
    if normalized not in CLI_PROTOCOL_BUILDERS:
        raise ValueError(f"Unknown CLI protocol builder: {name}")
    return CLI_PROTOCOL_BUILDERS[normalized]
