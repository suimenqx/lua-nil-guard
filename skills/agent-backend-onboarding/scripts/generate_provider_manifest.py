#!/usr/bin/env python3
"""
Generate a valid provider manifest for lua-nil-review-agent.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROTOCOL_DEFAULTS: dict[str, dict[str, object]] = {
    "schema_file_cli": {
        "default_timeout_seconds": 45.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": True,
            "supports_backend_cache": True,
            "supports_output_schema": True,
            "supports_output_file": True,
            "supports_stdout_json": False,
            "supports_tool_free_prompting": True,
        },
    },
    "stdout_structured_cli": {
        "default_timeout_seconds": 75.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": False,
            "supports_backend_cache": True,
            "supports_output_schema": True,
            "supports_output_file": False,
            "supports_stdout_json": True,
            "supports_tool_free_prompting": True,
        },
    },
    "stdout_envelope_cli": {
        "default_timeout_seconds": 45.0,
        "default_max_attempts": 2,
        "default_fallback_to_uncertain_on_error": True,
        "capabilities": {
            "supports_model_override": True,
            "supports_config_overrides": True,
            "supports_backend_cache": True,
            "supports_output_schema": False,
            "supports_output_file": False,
            "supports_stdout_json": True,
            "supports_tool_free_prompting": True,
        },
    },
}

CAPABILITY_KEYS = (
    "supports_model_override",
    "supports_config_overrides",
    "supports_backend_cache",
    "supports_output_schema",
    "supports_output_file",
    "supports_stdout_json",
    "supports_tool_free_prompting",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a provider manifest JSON file with protocol-aligned defaults.",
    )
    parser.add_argument("name", help="Backend name to register")
    parser.add_argument(
        "protocol",
        choices=sorted(PROTOCOL_DEFAULTS.keys()),
        help="Existing runtime protocol to reuse",
    )
    parser.add_argument(
        "--executable",
        help="Executable name or path (defaults to the backend name)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="Override default_timeout_seconds",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        help="Override default_max_attempts",
    )
    parser.add_argument(
        "--fallback",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override default_fallback_to_uncertain_on_error",
    )
    for key in CAPABILITY_KEYS:
        flag = key.replace("_", "-")
        parser.add_argument(
            f"--{flag}",
            action=argparse.BooleanOptionalAction,
            default=None,
            help=f"Override capability {key}",
        )
    parser.add_argument(
        "--output",
        help="Write the manifest to a file instead of stdout",
    )
    return parser


def _normalize_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("name must not be empty")
    for character in normalized:
        if character not in "abcdefghijklmnopqrstuvwxyz0123456789-":
            raise ValueError("name must use lowercase letters, digits, and hyphens only")
    if normalized.startswith("-") or normalized.endswith("-") or "--" in normalized:
        raise ValueError("name cannot start/end with a hyphen or contain consecutive hyphens")
    return normalized


def _build_manifest(args: argparse.Namespace) -> dict[str, object]:
    name = _normalize_name(args.name)
    defaults = PROTOCOL_DEFAULTS[args.protocol]
    capabilities = dict(defaults["capabilities"])
    for key in CAPABILITY_KEYS:
        override = getattr(args, key)
        if override is not None:
            capabilities[key] = override

    attempts = defaults["default_max_attempts"] if args.attempts is None else args.attempts
    if attempts < 1:
        raise ValueError("--attempts must be a positive integer")

    timeout = defaults["default_timeout_seconds"] if args.timeout is None else args.timeout
    if timeout is not None and timeout <= 0:
        raise ValueError("--timeout must be positive when provided")

    fallback = (
        defaults["default_fallback_to_uncertain_on_error"]
        if args.fallback is None
        else args.fallback
    )

    return {
        "name": name,
        "protocol": args.protocol,
        "default_executable": args.executable or name,
        "default_timeout_seconds": float(timeout) if timeout is not None else None,
        "default_max_attempts": attempts,
        "default_fallback_to_uncertain_on_error": fallback,
        "capabilities": capabilities,
    }


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        payload = _build_manifest(args)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
        print(f"[OK] Wrote manifest: {output_path}")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
