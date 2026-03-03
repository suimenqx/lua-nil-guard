#!/usr/bin/env python3
"""
Classify whether a provider can directly reuse an existing runtime protocol.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROMPT_MODES = ("stdin", "flag_arg", "positional", "unknown")
OUTPUT_MODES = (
    "schema_file",
    "stdout_envelope",
    "stdout_structured",
    "top_level_json",
    "unknown",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify whether a provider can directly integrate without runtime code changes.",
    )
    parser.add_argument("name", help="Provider name under evaluation")
    parser.add_argument(
        "--prompt-mode",
        choices=PROMPT_MODES,
        default="unknown",
        help="How the prompt reaches the provider",
    )
    parser.add_argument(
        "--output-mode",
        choices=OUTPUT_MODES,
        default="unknown",
        help="Where the structured result comes back",
    )
    parser.add_argument(
        "--envelope-field",
        help="Exact field name when output-mode is stdout_envelope",
    )
    parser.add_argument(
        "--structured-field",
        help="Exact field name when output-mode is stdout_structured",
    )
    parser.add_argument(
        "--model-override",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Whether the provider supports model selection",
    )
    parser.add_argument(
        "--config-overrides",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Whether the provider supports config override flags",
    )
    parser.add_argument(
        "--output",
        help="Write JSON output to a file instead of stdout",
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


def _classify(args: argparse.Namespace) -> dict[str, object]:
    name = _normalize_name(args.name)
    rationale: list[str] = []
    missing_evidence: list[str] = []

    if args.prompt_mode == "unknown":
        missing_evidence.append("prompt mode")
    if args.output_mode == "unknown":
        missing_evidence.append("output mode")

    if args.output_mode == "stdout_envelope" and not args.envelope_field:
        missing_evidence.append("envelope field")
    if args.output_mode == "stdout_structured" and not args.structured_field:
        missing_evidence.append("structured field")

    if missing_evidence:
        rationale.append("Not enough transport facts are known to classify the provider.")
        return {
            "status": "insufficient-evidence",
            "can_directly_integrate": False,
            "recommended_protocol": None,
            "integration_path": "gather-more-facts",
            "rationale": rationale,
            "missing_evidence": missing_evidence,
            "observed_features": {
                "prompt_mode": args.prompt_mode,
                "output_mode": args.output_mode,
                "envelope_field": args.envelope_field,
                "structured_field": args.structured_field,
                "supports_model_override": args.model_override,
                "supports_config_overrides": args.config_overrides,
            },
            "provider_name": name,
        }

    if args.prompt_mode == "stdin" and args.output_mode == "schema_file":
        rationale.append("Transport matches the schema_file_cli shape.")
        return _direct_fit_payload(name, "schema_file_cli", rationale, args)

    if args.prompt_mode == "flag_arg" and args.output_mode == "stdout_envelope":
        if args.envelope_field == "response":
            rationale.append("Transport matches stdout_envelope_cli and the envelope field is supported.")
            return _direct_fit_payload(name, "stdout_envelope_cli", rationale, args)
        rationale.append(
            "Envelope output is present, but the runtime currently expects the response field to be named 'response'."
        )
        return _runtime_change_payload(name, rationale, args)

    if args.prompt_mode == "positional":
        if args.output_mode == "top_level_json":
            rationale.append("Transport matches stdout_structured_cli with top-level adjudication JSON.")
            return _direct_fit_payload(name, "stdout_structured_cli", rationale, args)
        if args.output_mode == "stdout_structured":
            if args.structured_field in {"structured_output", "result"}:
                rationale.append(
                    "Transport matches stdout_structured_cli and the structured field is supported."
                )
                return _direct_fit_payload(name, "stdout_structured_cli", rationale, args)
            rationale.append(
                "Structured stdout is present, but the runtime only recognizes 'structured_output' and 'result'."
            )
            return _runtime_change_payload(name, rationale, args)

    rationale.append("Observed transport does not match any current direct-fit protocol.")
    return _runtime_change_payload(name, rationale, args)


def _direct_fit_payload(
    name: str,
    protocol: str,
    rationale: list[str],
    args: argparse.Namespace,
) -> dict[str, object]:
    return {
        "status": "direct-fit",
        "can_directly_integrate": True,
        "recommended_protocol": protocol,
        "integration_path": "manifest-only",
        "rationale": rationale,
        "missing_evidence": [],
        "observed_features": {
            "prompt_mode": args.prompt_mode,
            "output_mode": args.output_mode,
            "envelope_field": args.envelope_field,
            "structured_field": args.structured_field,
            "supports_model_override": args.model_override,
            "supports_config_overrides": args.config_overrides,
        },
        "provider_name": name,
    }


def _runtime_change_payload(
    name: str,
    rationale: list[str],
    args: argparse.Namespace,
) -> dict[str, object]:
    return {
        "status": "needs-runtime-changes",
        "can_directly_integrate": False,
        "recommended_protocol": None,
        "integration_path": "new-protocol",
        "rationale": rationale,
        "missing_evidence": [],
        "observed_features": {
            "prompt_mode": args.prompt_mode,
            "output_mode": args.output_mode,
            "envelope_field": args.envelope_field,
            "structured_field": args.structured_field,
            "supports_model_override": args.model_override,
            "supports_config_overrides": args.config_overrides,
        },
        "provider_name": name,
    }


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        payload = _classify(args)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
        print(f"[OK] Wrote classification: {output_path}")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
