from __future__ import annotations

from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
from typing import Sequence

from .agent_backend import (
    BackendError,
    create_adjudication_backend,
    get_cli_protocol_backend,
    register_manifest_backed_adjudication_backend,
)
from .agent_driver_manifest import (
    build_agent_provider_manifest_template,
    load_agent_provider_spec_manifest_file,
)
from .baseline import BaselineStore, build_baseline, filter_new_findings
from .config_loader import ConfigError, initialize_repository_config
from .parser_backend import get_parser_backend_info
from .repository import audit_lua_source_encodings, normalize_lua_source_encodings
from .reporting import (
    render_improvement_analytics_json,
    render_improvement_analytics_markdown,
    render_improvement_proposals_json,
    render_improvement_proposals_markdown,
    render_json_report,
    render_markdown_report,
)
from .skill_runtime import SkillRuntimeError
from .service import (
    analyze_review_improvements,
    apply_autofix_manifest,
    benchmark_cache_compare,
    benchmark_repository_review,
    build_repository_macro_cache,
    bootstrap_repository,
    clear_backend_cache,
    draft_review_improvements,
    export_adjudication_tasks,
    export_autofix_patches,
    export_autofix_unified_diff,
    find_repository_root_for_file,
    macro_audit_repository,
    macro_cache_status_for_repository,
    refresh_knowledge_base,
    refresh_summary_cache,
    review_repository_file,
    review_repository,
    run_file_review,
    run_repository_review,
)

_FOCUS_MODE_ALL = "all"
_FOCUS_MODE_STRING = "string"
_FOCUS_MODE_VALUES = (_FOCUS_MODE_ALL, _FOCUS_MODE_STRING)
_STRING_FOCUS_RULE_PREFIXES = ("string.", "concat.")


def run(argv: Sequence[str]) -> tuple[int, str]:
    """Execute the minimal CLI and return an exit code with rendered output."""

    args = list(argv)
    if not args or args[0] in {"-h", "--help"}:
        return 0, _usage()

    command = args[0]
    if command == "scan":
        try:
            focus_mode, positional = _parse_focus_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "scan requires exactly one repository path"
        root = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot, error = _load_repository_snapshot(root)
        if error is not None:
            return 2, error
        snapshot = _apply_focus_mode(snapshot, focus_mode)
        assessments = review_repository(snapshot)
        return 0, _render_scan_summary(snapshot.root, assessments, focus_mode=focus_mode)

    if command == "scan-file":
        try:
            focus_mode, positional = _parse_focus_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "scan-file requires exactly one Lua file path"
        file_path = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        try:
            root = find_repository_root_for_file(file_path)
            snapshot = bootstrap_repository(root)
            snapshot = _apply_focus_mode(snapshot, focus_mode)
            assessments = review_repository_file(snapshot, file_path)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        return 0, _render_scan_summary(
            snapshot.root,
            assessments,
            target_file=file_path,
            focus_mode=focus_mode,
        )

    if command == "doctor":
        if len(args) != 1:
            return 2, "doctor does not accept positional arguments"
        return 0, _render_doctor_report()

    if command == "init-config":
        force = False
        positional: list[str] = []
        for token in args[1:]:
            if token == "--force":
                force = True
            else:
                positional.append(token)
        if len(positional) != 1:
            return 2, "init-config requires exactly one repository path"
        root = Path(positional[0])
        try:
            sink_path, policy_path, contracts_path, preprocessor_path = initialize_repository_config(
                root,
                force=force,
            )
        except (ConfigError, OSError) as exc:
            return 2, str(exc)
        return 0, "\n".join(
            [
                "Repository config initialized.",
                f"Force overwrite: {'yes' if force else 'no'}",
                f"Sink rules: {sink_path}",
                f"Confidence policy: {policy_path}",
                f"Function contracts: {contracts_path}",
                f"Preprocessor config: {preprocessor_path}",
            ]
        )

    if command == "macro-audit":
        if len(args) not in {2, 3}:
            return 2, "macro-audit requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        snapshot, error = _load_repository_snapshot(root)
        if error is not None:
            return 2, error
        audit = macro_audit_repository(snapshot)
        rendered = _render_macro_audit_markdown(snapshot.root, audit)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Macro audit complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "macro-audit-json":
        if len(args) not in {2, 3}:
            return 2, "macro-audit-json requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        snapshot, error = _load_repository_snapshot(root)
        if error is not None:
            return 2, error
        audit = macro_audit_repository(snapshot)
        rendered = json.dumps(_serialize_macro_audit(snapshot.root, audit), indent=2, sort_keys=True)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Macro audit JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "macro-build-cache":
        if len(args) not in {2, 3}:
            return 2, "macro-build-cache requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            status = build_repository_macro_cache(root)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = _render_macro_cache_status_markdown(root, status)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Macro cache build complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "macro-build-cache-json":
        if len(args) not in {2, 3}:
            return 2, "macro-build-cache-json requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            status = build_repository_macro_cache(root)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = json.dumps(_serialize_macro_cache_status(root, status), indent=2, sort_keys=True)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Macro cache build JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "macro-cache-status":
        if len(args) not in {2, 3}:
            return 2, "macro-cache-status requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            status = macro_cache_status_for_repository(root)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = _render_macro_cache_status_markdown(root, status)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Macro cache status export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "macro-cache-status-json":
        if len(args) not in {2, 3}:
            return 2, "macro-cache-status-json requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            status = macro_cache_status_for_repository(root)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = json.dumps(_serialize_macro_cache_status(root, status), indent=2, sort_keys=True)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Macro cache status JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "encoding-audit":
        if len(args) not in {2, 3}:
            return 2, "encoding-audit requires a repository path and optional output path"
        root = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            records = audit_lua_source_encodings(root)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = _render_encoding_audit(records, root)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Encoding audit complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "normalize-encoding":
        write = False
        positional: list[str] = []
        for token in args[1:]:
            if token == "--write":
                write = True
            else:
                positional.append(token)
        if len(positional) not in {1, 2}:
            return 2, "normalize-encoding requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        try:
            results = normalize_lua_source_encodings(root, write=write)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = _render_encoding_normalization(results, root, write=write)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Encoding normalization complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "clear-backend-cache":
        if len(args) != 2:
            return 2, "clear-backend-cache requires exactly one cache file path"
        cache_path = Path(args[1])
        try:
            removed_entries = clear_backend_cache(cache_path)
        except OSError as exc:
            return 2, str(exc)
        return 0, "\n".join(
            [
                "Backend cache cleared.",
                f"Removed entries: {removed_entries}",
                f"Output: {cache_path}",
            ]
        )

    if command == "generate-backend-manifest":
        if len(args) not in {3, 4}:
            return 2, "generate-backend-manifest requires a name, protocol, and optional output path"
        name = args[1]
        protocol = args[2]
        output_path = Path(args[3]) if len(args) == 4 else None
        try:
            payload = build_agent_provider_manifest_template(name, protocol)
        except ValueError as exc:
            return 2, str(exc)
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Backend manifest template generated.",
                f"Output: {output_path}",
            ]
        )

    if command == "validate-backend-manifest":
        if len(args) != 2:
            return 2, "validate-backend-manifest requires exactly one manifest path"
        manifest_path = Path(args[1])
        try:
            provider_spec = load_agent_provider_spec_manifest_file(manifest_path)
            protocol_backend = get_cli_protocol_backend(provider_spec.protocol)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        payload = _serialize_backend_manifest_summary(
            provider_spec,
            manifest_path=manifest_path,
            protocol_backend_name=protocol_backend.__name__,
            registered=False,
        )
        return 0, _render_backend_manifest_summary(payload)

    if command == "validate-backend-manifest-json":
        if len(args) not in {2, 3}:
            return 2, "validate-backend-manifest-json requires a manifest path and optional output path"
        manifest_path = Path(args[1])
        output_path = Path(args[2]) if len(args) == 3 else None
        try:
            provider_spec = load_agent_provider_spec_manifest_file(manifest_path)
            protocol_backend = get_cli_protocol_backend(provider_spec.protocol)
            payload = _serialize_backend_manifest_summary(
                provider_spec,
                manifest_path=manifest_path,
                protocol_backend_name=protocol_backend.__name__,
                registered=False,
            )
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Backend manifest JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "register-backend-manifest":
        try:
            replace, manifest_path, output_path = _parse_register_backend_manifest_args(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if output_path is not None:
            return 2, "register-backend-manifest does not accept an output path"
        try:
            provider_spec = register_manifest_backed_adjudication_backend(
                manifest_path,
                replace=replace,
            )
            protocol_backend = get_cli_protocol_backend(provider_spec.protocol)
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        payload = _serialize_backend_manifest_summary(
            provider_spec,
            manifest_path=manifest_path,
            protocol_backend_name=protocol_backend.__name__,
            registered=True,
        )
        return 0, _render_backend_manifest_summary(payload)

    if command == "register-backend-manifest-json":
        try:
            replace, manifest_path, output_path = _parse_register_backend_manifest_args(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        try:
            provider_spec = register_manifest_backed_adjudication_backend(
                manifest_path,
                replace=replace,
            )
            protocol_backend = get_cli_protocol_backend(provider_spec.protocol)
            payload = _serialize_backend_manifest_summary(
                provider_spec,
                manifest_path=manifest_path,
                protocol_backend_name=protocol_backend.__name__,
                registered=True,
            )
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Backend manifest registration JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "compare-benchmark-json":
        if len(args) not in {3, 4}:
            return 2, "compare-benchmark-json requires two input files and optional output path"
        before_path = Path(args[1])
        after_path = Path(args[2])
        output_path = Path(args[3]) if len(args) == 4 else None
        try:
            report = _render_benchmark_json_comparison(
                before_path=before_path,
                after_path=after_path,
            )
        except (OSError, ValueError) as exc:
            return 2, str(exc)
        if output_path is None:
            return 0, report
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
        return 0, "\n".join(
            [
                "Benchmark comparison export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "report":
        try:
            focus_mode, review_args = _parse_focus_options(args[1:])
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(review_args)
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "report requires exactly one repository path"
        root = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot, error = _load_repository_snapshot(root)
        if error is not None:
            return 2, error
        snapshot = _apply_focus_mode(snapshot, focus_mode)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        return 0, render_markdown_report(verdicts, snapshot.confidence_policy)

    if command == "report-file":
        try:
            focus_mode, review_args = _parse_focus_options(args[1:])
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(review_args)
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "report-file requires exactly one Lua file path"
        file_path = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        try:
            root = find_repository_root_for_file(file_path)
            snapshot = bootstrap_repository(root)
            snapshot = _apply_focus_mode(snapshot, focus_mode)
            verdicts = run_file_review(
                snapshot,
                file_path,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (OSError, SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        return 0, render_markdown_report(verdicts, snapshot.confidence_policy)

    if command == "report-json":
        try:
            focus_mode, review_args = _parse_focus_options(args[1:])
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(review_args)
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "report-json requires exactly one repository path"
        root = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot, error = _load_repository_snapshot(root)
        if error is not None:
            return 2, error
        snapshot = _apply_focus_mode(snapshot, focus_mode)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        return 0, render_json_report(verdicts, snapshot.confidence_policy)

    if command == "report-file-json":
        try:
            focus_mode, review_args = _parse_focus_options(args[1:])
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(review_args)
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "report-file-json requires exactly one Lua file path"
        file_path = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        try:
            root = find_repository_root_for_file(file_path)
            snapshot = bootstrap_repository(root)
            snapshot = _apply_focus_mode(snapshot, focus_mode)
            verdicts = run_file_review(
                snapshot,
                file_path,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (OSError, SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        return 0, render_json_report(verdicts, snapshot.confidence_policy)

    if command == "benchmark":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "benchmark requires exactly one repository path"
        root = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            summary = benchmark_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        return 0, _render_benchmark_summary(snapshot.root, summary)

    if command == "benchmark-json":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "benchmark-json requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            summary = benchmark_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        payload = json.dumps(_serialize_benchmark_summary(snapshot.root, summary), indent=2, sort_keys=True)
        if output_path is None:
            return 0, payload
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
        return 0, "\n".join(
            [
                "Benchmark JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "proposal-export":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "proposal-export requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            proposals = draft_review_improvements(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        rendered = render_improvement_proposals_markdown(proposals)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Improvement proposal export complete.",
                f"Proposals: {len(proposals)}",
                f"Output: {output_path}",
            ]
        )

    if command == "proposal-export-json":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "proposal-export-json requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            proposals = draft_review_improvements(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        rendered = render_improvement_proposals_json(proposals)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Improvement proposal JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "proposal-analytics":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "proposal-analytics requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            analytics = analyze_review_improvements(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        rendered = render_improvement_analytics_markdown(analytics)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Improvement analytics export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "proposal-analytics-json":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "proposal-analytics-json requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            analytics = analyze_review_improvements(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        rendered = render_improvement_analytics_json(analytics)
        if output_path is None:
            return 0, rendered
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0, "\n".join(
            [
                "Improvement analytics JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "benchmark-cache-compare":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "benchmark-cache-compare requires exactly one repository path"
        if backend_cache_path is None:
            return 2, "benchmark-cache-compare requires --backend-cache PATH"
        root = Path(positional[0])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            comparison = benchmark_cache_compare(
                snapshot,
                cache_path=backend_cache_path,
                backend_factory=lambda: _create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        return 0, _render_benchmark_cache_comparison(snapshot.root, comparison)

    if command == "benchmark-cache-compare-json":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "benchmark-cache-compare-json requires a repository path and optional output path"
        if backend_cache_path is None:
            return 2, "benchmark-cache-compare-json requires --backend-cache PATH"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            comparison = benchmark_cache_compare(
                snapshot,
                cache_path=backend_cache_path,
                backend_factory=lambda: _create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        payload = json.dumps(
            _serialize_benchmark_cache_comparison(snapshot.root, comparison),
            indent=2,
            sort_keys=True,
        )
        if output_path is None:
            return 0, payload
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
        return 0, "\n".join(
            [
                "Benchmark cache comparison JSON export complete.",
                f"Output: {output_path}",
            ]
        )

    if command == "baseline-create":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 2:
            return 2, "baseline-create requires a repository path and output path"
        root = Path(positional[0])
        baseline_path = Path(positional[1])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        baseline = build_baseline(verdicts, snapshot.confidence_policy)
        BaselineStore(baseline_path).save(baseline)
        return 0, "\n".join(
            [
                "Baseline created.",
                f"Baseline entries: {len(baseline)}",
                f"Output: {baseline_path}",
            ]
        )

    if command == "report-new":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 2:
            return 2, "report-new requires a repository path and baseline path"
        root = Path(positional[0])
        baseline_path = Path(positional[1])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        filtered = filter_new_findings(
            verdicts,
            BaselineStore(baseline_path).load(),
            snapshot.confidence_policy,
        )
        return 0, render_markdown_report(filtered, snapshot.confidence_policy)

    if command == "refresh-summaries":
        if len(args) not in {2, 3}:
            return 2, "refresh-summaries requires a repository path and optional output path"
        root = Path(args[1])
        summary_path = Path(args[2]) if len(args) == 3 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        summaries = refresh_summary_cache(snapshot, summary_path=summary_path)
        target = summary_path or (snapshot.root / "data" / "function_summaries.json")
        return 0, "\n".join(
            [
                "Summary cache refreshed.",
                f"Summary entries: {len(summaries)}",
                f"Output: {target}",
            ]
        )

    if command == "refresh-knowledge":
        if len(args) not in {2, 3}:
            return 2, "refresh-knowledge requires a repository path and optional output path"
        root = Path(args[1])
        knowledge_path = Path(args[2]) if len(args) == 3 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        facts = refresh_knowledge_base(snapshot, knowledge_path=knowledge_path)
        target = knowledge_path or (snapshot.root / "data" / "knowledge.json")
        return 0, "\n".join(
            [
                "Knowledge cache refreshed.",
                f"Knowledge entries: {len(facts)}",
                f"Output: {target}",
            ]
        )

    if command == "ci-check":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 2:
            return 2, "ci-check requires a repository path and baseline path"
        root = Path(positional[0])
        baseline_path = Path(positional[1])
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            verdicts = run_repository_review(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        filtered = filter_new_findings(
            verdicts,
            BaselineStore(baseline_path).load(),
            snapshot.confidence_policy,
        )
        exit_code = 1 if filtered else 0
        return exit_code, "\n".join(
            [
                "CI check complete.",
                f"New findings: {len(filtered)}",
            ]
        )

    if command == "export-prompts":
        try:
            skill_path, strict_skill, positional = _parse_export_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "export-prompts requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            tasks = export_adjudication_tasks(
                snapshot,
                output_path=output_path,
                skill_path=skill_path,
                strict_skill=strict_skill,
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        if output_path is None:
            return 0, json.dumps(tasks, indent=2, sort_keys=True)
        return 0, "\n".join(
            [
                "Prompt export complete.",
                f"Prompt tasks: {len(tasks)}",
                f"Output: {output_path}",
            ]
        )

    if command == "export-autofix":
        try:
            (
                backend_name,
                model,
                skill_path,
                strict_skill,
                executable,
                backend_manifest_path,
                backend_timeout,
                backend_attempts,
                expanded_evidence_retry,
                backend_cache_path,
                backend_config_overrides,
                positional,
            ) = _parse_review_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "export-autofix requires a repository path and optional output path"
        root = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        parser_error = _require_tree_sitter_backend()
        if parser_error is not None:
            return 2, parser_error
        snapshot = bootstrap_repository(root)
        try:
            patches = export_autofix_patches(
                snapshot,
                backend=_create_review_backend(
                    backend_name=backend_name,
                    root=root,
                    model=model,
                    skill_path=skill_path,
                    strict_skill=strict_skill,
                    executable=executable,
                    backend_manifest_path=backend_manifest_path,
                    timeout_seconds=backend_timeout,
                    max_attempts=backend_attempts,
                    expanded_evidence_retry=expanded_evidence_retry,
                    cache_path=backend_cache_path,
                    config_overrides=backend_config_overrides,
                ),
                output_path=output_path,
            )
        except (SkillRuntimeError, BackendError, ValueError) as exc:
            return 2, str(exc)
        if output_path is None:
            payload = [
                {
                    "case_id": patch.case_id,
                    "file": patch.file,
                    "action": patch.action,
                    "start_line": patch.start_line,
                    "end_line": patch.end_line,
                    "replacement": patch.replacement,
                    "expected_original": patch.expected_original,
                }
                for patch in patches
            ]
            return 0, json.dumps(payload, indent=2, sort_keys=True)
        return 0, "\n".join(
            [
                "Autofix export complete.",
                f"Autofix patches: {len(patches)}",
                f"Output: {output_path}",
            ]
        )

    if command == "apply-autofix":
        try:
            dry_run, case_ids, file_paths, positional = _parse_autofix_selection_options(
                args[1:],
                allow_dry_run=True,
            )
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) != 1:
            return 2, "apply-autofix requires exactly one autofix manifest path"
        try:
            applied, conflicts = apply_autofix_manifest(
                Path(positional[0]),
                dry_run=dry_run,
                case_ids=case_ids,
                file_paths=file_paths,
            )
        except (ValueError, OSError) as exc:
            return 2, str(exc)
        lines = [
            "Autofix apply complete.",
            f"Dry run: {'yes' if dry_run else 'no'}",
            f"Applied patches: {len(applied)}",
            f"Conflicts: {len(conflicts)}",
        ]
        if conflicts:
            lines.extend(conflicts)
            return 1, "\n".join(lines)
        return 0, "\n".join(lines)

    if command == "export-unified-diff":
        try:
            _, case_ids, file_paths, positional = _parse_autofix_selection_options(args[1:])
        except ValueError as exc:
            return 2, str(exc)
        if len(positional) not in {1, 2}:
            return 2, "export-unified-diff requires an autofix manifest path and optional output path"
        manifest_path = Path(positional[0])
        output_path = Path(positional[1]) if len(positional) == 2 else None
        try:
            diff_text, conflicts = export_autofix_unified_diff(
                manifest_path,
                output_path=output_path,
                case_ids=case_ids,
                file_paths=file_paths,
            )
        except (ValueError, OSError) as exc:
            return 2, str(exc)
        if conflicts:
            lines = [
                "Unified diff export blocked.",
                f"Conflicts: {len(conflicts)}",
            ]
            lines.extend(conflicts)
            return 1, "\n".join(lines)
        if output_path is None:
            return 0, diff_text or "No unified diff output."
        return 0, "\n".join(
            [
                "Unified diff export complete.",
                f"Output: {output_path}",
            ]
        )

    return 2, _usage()


def _create_review_backend(
    *,
    backend_name: str,
    root: Path,
    model: str | None,
    skill_path: Path | None,
    strict_skill: bool,
    executable: str | None,
    backend_manifest_path: Path | None,
    timeout_seconds: float | None,
    max_attempts: int | None,
    expanded_evidence_retry: bool | None,
    cache_path: Path | None,
    config_overrides: tuple[str, ...],
):
    if backend_manifest_path is not None:
        register_manifest_backed_adjudication_backend(backend_manifest_path, replace=True)
    return create_adjudication_backend(
        backend_name,
        workdir=root,
        model=model,
        skill_path=skill_path,
        strict_skill=strict_skill,
        executable=executable,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
        expanded_evidence_retry=expanded_evidence_retry,
        cache_path=cache_path,
        config_overrides=config_overrides,
    )


def _parse_register_backend_manifest_args(args: list[str]) -> tuple[bool, Path, Path | None]:
    replace = False
    positional: list[str] = []
    for token in args:
        if token == "--replace":
            replace = True
        else:
            positional.append(token)
    if len(positional) not in {1, 2}:
        raise ValueError(
            "register-backend-manifest requires one manifest path, optional --replace, and optional output path"
        )
    manifest_path = Path(positional[0])
    output_path = Path(positional[1]) if len(positional) == 2 else None
    return replace, manifest_path, output_path


def _serialize_backend_manifest_summary(
    provider_spec,  # noqa: ANN001
    *,
    manifest_path: Path,
    protocol_backend_name: str,
    registered: bool,
) -> dict[str, object]:
    capabilities = provider_spec.capabilities
    return {
        "status": "registered" if registered else "valid",
        "manifest": str(manifest_path),
        "name": provider_spec.name,
        "protocol": provider_spec.protocol,
        "protocol_backend": protocol_backend_name,
        "runtime_compatibility": "supported",
        "default_executable": provider_spec.default_executable,
        "default_timeout_seconds": provider_spec.default_timeout_seconds,
        "default_max_attempts": provider_spec.default_max_attempts,
        "default_expanded_evidence_retry_mode": provider_spec.default_expanded_evidence_retry_mode,
        "capabilities": {
            "supports_model_override": getattr(capabilities, "supports_model_override", False),
            "supports_config_overrides": getattr(capabilities, "supports_config_overrides", False),
            "supports_backend_cache": getattr(capabilities, "supports_backend_cache", False),
            "supports_output_schema": getattr(capabilities, "supports_output_schema", False),
            "supports_output_file": getattr(capabilities, "supports_output_file", False),
            "supports_stdout_json": getattr(capabilities, "supports_stdout_json", False),
            "supports_tool_free_prompting": getattr(
                capabilities,
                "supports_tool_free_prompting",
                True,
            ),
        },
        "registration_scope": "current_process_invocation" if registered else None,
    }


def _render_backend_manifest_summary(payload: dict[str, object]) -> str:
    capabilities = payload["capabilities"]
    lines = [
        "Backend manifest registered." if payload["status"] == "registered" else "Backend manifest valid.",
        f"Manifest: {payload['manifest']}",
        f"Name: {payload['name']}",
        f"Protocol: {payload['protocol']}",
        f"Protocol backend: {payload['protocol_backend']}",
        f"Runtime compatibility: {payload['runtime_compatibility']}",
        f"Default executable: {payload['default_executable']}",
        f"Default timeout: {payload['default_timeout_seconds']}",
        f"Default attempts: {payload['default_max_attempts']}",
        f"Default expanded evidence retry: {payload['default_expanded_evidence_retry_mode']}",
        "Runtime-consumed capabilities:",
        f"  model override: {capabilities['supports_model_override']}",
        f"  config overrides: {capabilities['supports_config_overrides']}",
        f"  backend cache: {capabilities['supports_backend_cache']}",
        f"  output schema: {capabilities['supports_output_schema']}",
        f"  output file: {capabilities['supports_output_file']}",
        f"  stdout json: {capabilities['supports_stdout_json']}",
        f"  tool-free prompting: {capabilities['supports_tool_free_prompting']}",
    ]
    if payload["registration_scope"] is not None:
        lines.append("Registration scope: current process invocation")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point."""

    import sys

    try:
        exit_code, output = run(sys.argv[1:] if argv is None else argv)
    except (OSError, ValueError, ConfigError) as exc:
        print(str(exc))
        return 2
    print(output)
    return exit_code


def _load_repository_snapshot(root: Path) -> tuple[object | None, str | None]:
    """Load a repository snapshot and render failures as user-facing strings."""

    try:
        return bootstrap_repository(root), None
    except (OSError, ValueError, ConfigError) as exc:
        return None, str(exc)


def _require_tree_sitter_backend() -> str | None:
    backend_info = get_parser_backend_info()
    if backend_info.tree_sitter_available:
        return None
    lines = [
        "Tree-sitter is required for analysis commands.",
        f"Parser backend: {backend_info.name}",
        f"Reason: {backend_info.reason}",
    ]
    if backend_info.selected_compiler is not None:
        lines.append(f"Detected compiler: {backend_info.selected_compiler}")
    lines.append("Run `lua-nil-guard doctor` to diagnose and fix the environment.")
    return "\n".join(lines)


def _render_scan_summary(
    root: Path,
    assessments: tuple[object, ...],
    *,
    target_file: Path | None = None,
    focus_mode: str = _FOCUS_MODE_ALL,
) -> str:
    backend_info = get_parser_backend_info()
    counts = Counter(
        assessment.candidate.static_state
        for assessment in assessments
    )

    lines = [
        "# Lua Nil Review Static Summary",
        "",
        f"Repository: {root}",
        f"Parser backend: {backend_info.name}",
        f"Parser detail: {backend_info.reason}",
        f"Focus mode: {focus_mode}",
        f"Total candidates: {len(assessments)}",
    ]
    if backend_info.selected_compiler is not None:
        lines.append(f"Detected compiler: {backend_info.selected_compiler}")
    if target_file is not None:
        lines.insert(3, f"Target file: {target_file}")

    for state in ("safe_static", "unknown_static", "risky_static"):
        lines.append(f"{state}: {counts.get(state, 0)}")

    return "\n".join(lines)


def _render_doctor_report() -> str:
    backend_info = get_parser_backend_info()

    lines = [
        "# Lua Nil Guard Doctor",
        "",
        f"Parser backend: {backend_info.name}",
        f"Tree-sitter available: {'yes' if backend_info.tree_sitter_available else 'no'}",
        f"Tree-sitter Python package: {'yes' if backend_info.tree_sitter_python_available else 'no'}",
        f"Status: {backend_info.reason}",
        "Compiler probe order: cc, gcc, clang",
        f"Detected compiler: {backend_info.selected_compiler or '(none)'}",
        f"Local grammar library: {backend_info.local_library_path or '(not available)'}",
        "Repository macro cache: repository-specific (use `lua-nil-guard macro-cache-status <repository>`)",
    ]
    if not backend_info.tree_sitter_available:
        lines.extend(
            [
                "",
                "Action:",
                "- Ensure one of cc, gcc, or clang is available.",
                "- Ensure the Python tree_sitter dependency is installed in the active environment.",
                "- Re-run `lua-nil-guard doctor` and confirm parser backend is tree_sitter_local.",
            ]
        )
    return "\n".join(lines)


def _render_benchmark_summary(root: Path, summary) -> str:  # noqa: ANN001
    payload = _serialize_benchmark_summary(root, summary)

    lines = [
        "# Lua Nil Review Benchmark",
        "",
        f"Repository: {payload['repository']}",
        f"Backend: {payload['backend_name']}",
        f"Total labeled cases: {payload['total_cases']}",
        f"Exact matches: {payload['exact_matches']}",
        f"Accuracy: {payload['accuracy']:.1f}%",
        f"Expected risky: {payload['expected_risky']}",
        f"Expected safe: {payload['expected_safe']}",
        f"Expected uncertain: {payload['expected_uncertain']}",
        f"Actual risky: {payload['actual_risky']}",
        f"Actual safe: {payload['actual_safe']}",
        f"Actual uncertain: {payload['actual_uncertain']}",
        f"Missed risks: {payload['missed_risks']}",
        f"False positive risks: {payload['false_positive_risks']}",
        f"Unresolved labeled cases: {payload['unresolved_cases']}",
        f"Backend fallbacks: {payload['backend_fallbacks']}",
        f"Backend timeouts: {payload['backend_timeouts']}",
        f"Backend cache hits: {payload['backend_cache_hits']}",
        f"Backend cache misses: {payload['backend_cache_misses']}",
        f"Backend calls: {payload['backend_calls']}",
        f"Backend warm-up calls: {payload['backend_warmup_calls']}",
        f"Backend review calls: {payload['backend_review_calls']}",
        f"Backend total latency: {payload['backend_total_seconds']:.3f}s",
        f"Backend warm-up latency: {payload['backend_warmup_total_seconds']:.3f}s",
        f"Backend review latency: {payload['backend_review_total_seconds']:.3f}s",
        f"Backend average latency: {payload['backend_average_seconds']:.3f}s",
        f"Backend review average latency: {payload['backend_review_average_seconds']:.3f}s",
        f"AST primary cases: {payload['ast_primary_cases']}",
        f"AST fallback cases: {payload['ast_fallback_to_legacy_cases']}",
        f"Legacy-only cases: {payload['legacy_only_cases']}",
    ]
    if payload["backend_model"] is not None:
        lines.insert(4, f"Backend model: {payload['backend_model']}")
    if payload["backend_executable"] is not None:
        insert_at = 5 if payload["backend_model"] is not None else 4
        lines.insert(insert_at, f"Backend executable: {payload['backend_executable']}")

    mismatches = [case for case in summary.cases if not case.matches_expectation]
    if mismatches:
        lines.append("")
        lines.append("Mismatches:")
        for case in mismatches:
            lines.append(
                f"- {Path(case.file).name}: expected {case.expected_status}, got {case.actual_status}"
            )

    return "\n".join(lines)


def _render_benchmark_cache_comparison(root: Path, comparison) -> str:  # noqa: ANN001
    payload = _serialize_benchmark_cache_comparison(root, comparison)
    cold = payload["cold"]
    warm = payload["warm"]
    delta = payload["delta"]

    lines = [
        "# Lua Nil Review Cache Comparison",
        "",
        f"Repository: {payload['repository']}",
        f"Cache file: {payload['cache_path']}",
        f"Cleared entries before cold run: {payload['cache_cleared_entries']}",
        "",
        "Cold run:",
        f"- Exact matches: {cold['exact_matches']}/{cold['total_cases']}",
        f"- Backend cache hits: {cold['backend_cache_hits']}",
        f"- Backend cache misses: {cold['backend_cache_misses']}",
        f"- Backend calls: {cold['backend_calls']}",
        f"- Backend warm-up calls: {cold['backend_warmup_calls']}",
        f"- Backend review calls: {cold['backend_review_calls']}",
        f"- Backend total latency: {cold['backend_total_seconds']:.3f}s",
        f"- Backend warm-up latency: {cold['backend_warmup_total_seconds']:.3f}s",
        f"- Backend review latency: {cold['backend_review_total_seconds']:.3f}s",
        "",
        "Warm run:",
        f"- Exact matches: {warm['exact_matches']}/{warm['total_cases']}",
        f"- Backend cache hits: {warm['backend_cache_hits']}",
        f"- Backend cache misses: {warm['backend_cache_misses']}",
        f"- Backend calls: {warm['backend_calls']}",
        f"- Backend warm-up calls: {warm['backend_warmup_calls']}",
        f"- Backend review calls: {warm['backend_review_calls']}",
        f"- Backend total latency: {warm['backend_total_seconds']:.3f}s",
        f"- Backend warm-up latency: {warm['backend_warmup_total_seconds']:.3f}s",
        f"- Backend review latency: {warm['backend_review_total_seconds']:.3f}s",
        "",
        "Delta (warm - cold):",
        f"- Cache hits: {delta['backend_cache_hits']:+d}",
        f"- Backend calls: {delta['backend_calls']:+d}",
        f"- Backend warm-up calls: {delta['backend_warmup_calls']:+d}",
        f"- Backend review calls: {delta['backend_review_calls']:+d}",
        f"- Total latency: {delta['backend_total_seconds']:+.3f}s",
        f"- Warm-up latency: {delta['backend_warmup_total_seconds']:+.3f}s",
        f"- Review latency: {delta['backend_review_total_seconds']:+.3f}s",
    ]
    return "\n".join(lines)


def _render_benchmark_json_comparison(*, before_path: Path, after_path: Path) -> str:
    before = _load_benchmark_json_payload(before_path)
    after = _load_benchmark_json_payload(after_path)

    lines = [
        "# Lua Nil Review Benchmark Comparison",
        "",
        f"Before: {before_path}",
        f"After: {after_path}",
        f"Repository before: {before['repository']}",
        f"Repository after: {after['repository']}",
    ]
    _append_benchmark_metadata_comparison(lines, label="Backend", key="backend_name", before=before, after=after)
    _append_benchmark_metadata_comparison(
        lines,
        label="Backend model",
        key="backend_model",
        before=before,
        after=after,
    )
    _append_benchmark_metadata_comparison(
        lines,
        label="Backend executable",
        key="backend_executable",
        before=before,
        after=after,
    )
    lines.append("")
    lines.extend(
        [
            _format_int_change("Exact matches", before["exact_matches"], after["exact_matches"]),
            _format_float_change("Accuracy", before["accuracy"], after["accuracy"], suffix="%"),
            _format_int_change("Missed risks", before["missed_risks"], after["missed_risks"]),
            _format_int_change(
                "False positive risks",
                before["false_positive_risks"],
                after["false_positive_risks"],
            ),
            _format_int_change(
                "Unresolved labeled cases",
                before["unresolved_cases"],
                after["unresolved_cases"],
            ),
            _format_int_change(
                "Backend fallbacks",
                before["backend_fallbacks"],
                after["backend_fallbacks"],
            ),
            _format_int_change(
                "Backend timeouts",
                before["backend_timeouts"],
                after["backend_timeouts"],
            ),
            _format_int_change(
                "Backend cache hits",
                before["backend_cache_hits"],
                after["backend_cache_hits"],
            ),
            _format_int_change(
                "Backend cache misses",
                before["backend_cache_misses"],
                after["backend_cache_misses"],
            ),
            _format_int_change(
                "Backend calls",
                before["backend_calls"],
                after["backend_calls"],
            ),
            _format_int_change(
                "Backend warm-up calls",
                before["backend_warmup_calls"],
                after["backend_warmup_calls"],
            ),
            _format_int_change(
                "Backend review calls",
                before["backend_review_calls"],
                after["backend_review_calls"],
            ),
            _format_float_change(
                "Backend total latency",
                before["backend_total_seconds"],
                after["backend_total_seconds"],
                suffix="s",
            ),
            _format_float_change(
                "Backend warm-up latency",
                before["backend_warmup_total_seconds"],
                after["backend_warmup_total_seconds"],
                suffix="s",
            ),
            _format_float_change(
                "Backend review latency",
                before["backend_review_total_seconds"],
                after["backend_review_total_seconds"],
                suffix="s",
            ),
            _format_float_change(
                "Backend average latency",
                before["backend_average_seconds"],
                after["backend_average_seconds"],
                suffix="s",
            ),
            _format_float_change(
                "Backend review average latency",
                before["backend_review_average_seconds"],
                after["backend_review_average_seconds"],
                suffix="s",
            ),
        ]
    )
    return "\n".join(lines)


def _append_benchmark_metadata_comparison(
    lines: list[str],
    *,
    label: str,
    key: str,
    before: dict[str, float | int | str | None],
    after: dict[str, float | int | str | None],
) -> None:
    before_value = before.get(key)
    after_value = after.get(key)
    if before_value is None and after_value is None:
        return
    lines.append(f"{label} before: {before_value or '(unknown)'}")
    lines.append(f"{label} after: {after_value or '(unknown)'}")


def _serialize_benchmark_summary(root: Path, summary) -> dict[str, object]:  # noqa: ANN001
    accuracy = 0.0
    if summary.total_cases:
        accuracy = (summary.exact_matches / summary.total_cases) * 100
    total_calls = summary.backend_calls
    warmup_calls = summary.backend_warmup_calls
    review_calls = summary.backend_review_calls
    total_seconds = summary.backend_total_seconds
    warmup_total_seconds = summary.backend_warmup_total_seconds
    review_total_seconds = summary.backend_review_total_seconds
    review_average_seconds = summary.backend_review_average_seconds

    if review_calls == 0 and total_calls > 0 and warmup_calls == 0:
        review_calls = total_calls
    if review_total_seconds == 0.0 and total_seconds > 0.0 and warmup_total_seconds == 0.0:
        review_total_seconds = total_seconds
    if review_average_seconds == 0.0 and review_calls > 0 and review_total_seconds > 0.0:
        review_average_seconds = review_total_seconds / review_calls

    return {
        "repository": str(root),
        "backend_name": summary.backend_name,
        "backend_model": summary.backend_model,
        "backend_executable": summary.backend_executable,
        "total_cases": summary.total_cases,
        "exact_matches": summary.exact_matches,
        "accuracy": accuracy,
        "expected_risky": summary.expected_risky,
        "expected_safe": summary.expected_safe,
        "expected_uncertain": summary.expected_uncertain,
        "actual_risky": summary.actual_risky,
        "actual_safe": summary.actual_safe,
        "actual_uncertain": summary.actual_uncertain,
        "false_positive_risks": summary.false_positive_risks,
        "missed_risks": summary.missed_risks,
        "unresolved_cases": summary.unresolved_cases,
        "backend_fallbacks": summary.backend_fallbacks,
        "backend_timeouts": summary.backend_timeouts,
        "backend_cache_hits": summary.backend_cache_hits,
        "backend_cache_misses": summary.backend_cache_misses,
        "backend_calls": total_calls,
        "backend_warmup_calls": warmup_calls,
        "backend_review_calls": review_calls,
        "backend_total_seconds": total_seconds,
        "backend_warmup_total_seconds": warmup_total_seconds,
        "backend_review_total_seconds": review_total_seconds,
        "backend_average_seconds": summary.backend_average_seconds,
        "backend_review_average_seconds": review_average_seconds,
        "ast_primary_cases": summary.ast_primary_cases,
        "ast_fallback_to_legacy_cases": summary.ast_fallback_to_legacy_cases,
        "legacy_only_cases": summary.legacy_only_cases,
        "cases": [
            {
                "case_id": case.case_id,
                "file": case.file,
                "expected_status": case.expected_status,
                "actual_status": case.actual_status,
                "matches_expectation": case.matches_expectation,
                "backend_failure_reason": case.backend_failure_reason,
            }
            for case in summary.cases
        ],
    }


def _serialize_benchmark_cache_comparison(root: Path, comparison) -> dict[str, object]:  # noqa: ANN001
    cold = _serialize_benchmark_summary(root, comparison.cold)
    warm = _serialize_benchmark_summary(root, comparison.warm)
    return {
        "repository": str(root),
        "cache_path": comparison.cache_path,
        "cache_cleared_entries": comparison.cache_cleared_entries,
        "cold": cold,
        "warm": warm,
        "delta": {
            "backend_cache_hits": warm["backend_cache_hits"] - cold["backend_cache_hits"],
            "backend_cache_misses": warm["backend_cache_misses"] - cold["backend_cache_misses"],
            "backend_calls": warm["backend_calls"] - cold["backend_calls"],
            "backend_warmup_calls": warm["backend_warmup_calls"] - cold["backend_warmup_calls"],
            "backend_review_calls": warm["backend_review_calls"] - cold["backend_review_calls"],
            "backend_total_seconds": warm["backend_total_seconds"] - cold["backend_total_seconds"],
            "backend_warmup_total_seconds": (
                warm["backend_warmup_total_seconds"] - cold["backend_warmup_total_seconds"]
            ),
            "backend_review_total_seconds": (
                warm["backend_review_total_seconds"] - cold["backend_review_total_seconds"]
            ),
            "exact_matches": warm["exact_matches"] - cold["exact_matches"],
        },
    }


def _load_benchmark_json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid benchmark JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Benchmark JSON must contain an object: {path}")

    if _is_benchmark_summary_payload(payload):
        normalized = payload
    elif _is_benchmark_cache_compare_payload(payload):
        warm = payload["warm"]
        if not isinstance(warm, dict) or not _is_benchmark_summary_payload(warm):
            raise ValueError(f"Benchmark cache comparison JSON missing warm summary: {path}")
        normalized = warm
    else:
        raise ValueError(f"Unsupported benchmark JSON shape: {path}")

    return _coerce_benchmark_summary_payload(normalized, path=path)


def _is_benchmark_summary_payload(payload: dict[str, object]) -> bool:
    return "total_cases" in payload and "exact_matches" in payload and "accuracy" in payload


def _is_benchmark_cache_compare_payload(payload: dict[str, object]) -> bool:
    return "cold" in payload and "warm" in payload


def _coerce_benchmark_summary_payload(
    payload: dict[str, object],
    *,
    path: Path,
) -> dict[str, float | int | str | None]:
    return {
        "repository": _require_payload_string(payload, "repository", path=path),
        "backend_name": _optional_payload_string(payload, "backend_name", path=path),
        "backend_model": _optional_payload_string(payload, "backend_model", path=path),
        "backend_executable": _optional_payload_string(payload, "backend_executable", path=path),
        "exact_matches": _require_payload_int(payload, "exact_matches", path=path),
        "accuracy": _require_payload_float(payload, "accuracy", path=path),
        "missed_risks": _require_payload_int(payload, "missed_risks", path=path),
        "false_positive_risks": _require_payload_int(payload, "false_positive_risks", path=path),
        "unresolved_cases": _require_payload_int(payload, "unresolved_cases", path=path),
        "backend_fallbacks": _require_payload_int(payload, "backend_fallbacks", path=path),
        "backend_timeouts": _require_payload_int(payload, "backend_timeouts", path=path),
        "backend_cache_hits": _require_payload_int(payload, "backend_cache_hits", path=path),
        "backend_cache_misses": _require_payload_int(payload, "backend_cache_misses", path=path),
        "backend_calls": _require_payload_int(payload, "backend_calls", path=path),
        "backend_warmup_calls": _optional_payload_int(
            payload,
            "backend_warmup_calls",
            path=path,
            default=0,
        ),
        "backend_review_calls": _optional_payload_int(
            payload,
            "backend_review_calls",
            path=path,
            default=_require_payload_int(payload, "backend_calls", path=path),
        ),
        "backend_total_seconds": _require_payload_float(payload, "backend_total_seconds", path=path),
        "backend_warmup_total_seconds": _optional_payload_float(
            payload,
            "backend_warmup_total_seconds",
            path=path,
            default=0.0,
        ),
        "backend_review_total_seconds": _optional_payload_float(
            payload,
            "backend_review_total_seconds",
            path=path,
            default=_require_payload_float(payload, "backend_total_seconds", path=path),
        ),
        "backend_average_seconds": _require_payload_float(
            payload,
            "backend_average_seconds",
            path=path,
        ),
        "backend_review_average_seconds": _optional_payload_float(
            payload,
            "backend_review_average_seconds",
            path=path,
            default=_require_payload_float(payload, "backend_average_seconds", path=path),
        ),
    }


def _require_payload_string(payload: dict[str, object], key: str, *, path: Path) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Benchmark JSON field {key!r} must be a string: {path}")
    return value


def _optional_payload_string(payload: dict[str, object], key: str, *, path: Path) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Benchmark JSON field {key!r} must be a string when present: {path}")
    return value


def _require_payload_int(payload: dict[str, object], key: str, *, path: Path) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Benchmark JSON field {key!r} must be an integer: {path}")
    return value


def _optional_payload_int(
    payload: dict[str, object],
    key: str,
    *,
    path: Path,
    default: int,
) -> int:
    value = payload.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Benchmark JSON field {key!r} must be an integer when present: {path}")
    return value


def _require_payload_float(payload: dict[str, object], key: str, *, path: Path) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Benchmark JSON field {key!r} must be a number: {path}")
    return float(value)


def _optional_payload_float(
    payload: dict[str, object],
    key: str,
    *,
    path: Path,
    default: float,
) -> float:
    value = payload.get(key)
    if value is None:
        return float(default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Benchmark JSON field {key!r} must be a number when present: {path}")
    return float(value)


def _format_int_change(label: str, before: int, after: int) -> str:
    delta = after - before
    return f"{label}: {before} -> {after} ({delta:+d})"


def _format_float_change(label: str, before: float, after: float, *, suffix: str = "") -> str:
    delta = after - before
    return (
        f"{label}: "
        f"{before:.3f}{suffix} -> {after:.3f}{suffix} ({delta:+.3f}{suffix})"
    )


def _render_encoding_audit(records: tuple[object, ...], root: Path) -> str:
    total = len(records)
    already_utf8 = sum(1 for record in records if record.encoding == "utf-8")
    needs_normalization = sum(1 for record in records if record.needs_normalization)
    unsupported = sum(1 for record in records if not record.convertible)

    lines = [
        "# Lua Source Encoding Audit",
        "",
        f"Repository: {root}",
        f"Total Lua files: {total}",
        f"UTF-8 compliant: {already_utf8}",
        f"Needs normalization: {needs_normalization}",
        f"Unsupported encoding: {unsupported}",
        "",
    ]

    if needs_normalization:
        lines.append("## Convertible Non-UTF-8 Files")
        for record in records:
            if record.needs_normalization:
                lines.append(f"- {record.path} ({record.encoding})")
        lines.append("")

    if unsupported:
        lines.append("## Unsupported Files")
        for record in records:
            if not record.convertible:
                lines.append(f"- {record.path}: {record.reason}")
        lines.append("")

    if not needs_normalization and not unsupported:
        lines.append("All Lua source files are valid UTF-8.")

    return "\n".join(lines).rstrip()


def _serialize_macro_audit(root: Path, audit: object) -> dict[str, object]:
    return {
        "repository": str(root),
        "files": list(audit.files),
        "total_files": len(audit.files),
        "total_facts": len(audit.facts),
        "total_unresolved_lines": len(audit.unresolved_lines),
        "facts": [
            {
                "key": fact.key,
                "kind": fact.kind,
                "value": fact.value,
                "provably_non_nil": fact.provably_non_nil,
                "file": fact.file,
                "line": fact.line,
                "resolved_kind": fact.resolved_kind,
                "resolved_value": fact.resolved_value,
                "alias_target": fact.alias_target,
            }
            for fact in audit.facts
        ],
        "unresolved_lines": [
            {
                "file": item.file,
                "line": item.line,
                "content": item.content,
                "reason": item.reason,
            }
            for item in audit.unresolved_lines
        ],
    }


def _render_macro_audit_markdown(root: Path, audit: object) -> str:
    lines = [
        "# Preprocessor Macro Audit",
        "",
        f"Repository: {root}",
        f"Configured macro files: {len(audit.files)}",
        f"Resolved macro facts: {len(audit.facts)}",
        f"Unresolved lines: {len(audit.unresolved_lines)}",
        "",
    ]

    if audit.files:
        lines.append("## Macro Files")
        for file in audit.files:
            lines.append(f"- {file}")
        lines.append("")

    if audit.facts:
        lines.append("## Resolved Macro Facts")
        for fact in audit.facts:
            resolved_kind = fact.resolved_kind or fact.kind
            resolved_value = fact.resolved_value if fact.resolved_value is not None else fact.value
            suffix = (
                f" -> {resolved_kind} {resolved_value!r}"
                if resolved_value is not None
                else f" -> {resolved_kind}"
            )
            lines.append(
                f"- {fact.key} ({fact.file}:{fact.line}){suffix}"
            )
        lines.append("")

    if audit.unresolved_lines:
        lines.append("## Unresolved Macro Lines")
        for item in audit.unresolved_lines:
            lines.append(
                f"- {item.file}:{item.line} [{item.reason}] {item.content}"
            )
        lines.append("")

    if not audit.facts and not audit.unresolved_lines:
        lines.append("No configured macro dictionary files were found or no macro lines were parsed.")

    return "\n".join(lines).rstrip()


def _serialize_macro_cache_status(root: Path, status: object) -> dict[str, object]:
    return {
        "repository": str(root),
        "path": status.path,
        "state": status.state,
        "reason": status.reason,
        "configured_files": list(status.configured_files),
        "file_count": status.file_count,
        "fact_count": status.fact_count,
        "unresolved_count": status.unresolved_count,
        "parser_version": status.parser_version,
    }


def _render_macro_cache_status_markdown(root: Path, status: object) -> str:
    lines = [
        "# Preprocessor Macro Cache Status",
        "",
        f"Repository: {root}",
        f"Cache path: {status.path}",
        f"State: {status.state}",
        f"Reason: {status.reason}",
        f"Configured macro files: {status.file_count}",
        f"Resolved macro facts: {status.fact_count}",
        f"Unresolved lines: {status.unresolved_count}",
        f"Parser version: {status.parser_version}",
        "",
    ]
    if status.configured_files:
        lines.append("## Macro Files")
        for file in status.configured_files:
            lines.append(f"- {file}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_encoding_normalization(
    results: tuple[object, ...],
    root: Path,
    *,
    write: bool,
) -> str:
    already_utf8 = sum(1 for result in results if result.action == "already_utf8")
    converted = sum(1 for result in results if result.action == "converted")
    would_convert = sum(1 for result in results if result.action == "would_convert")
    skipped = sum(1 for result in results if result.action == "skipped")

    lines = [
        "# Lua Source Encoding Normalization",
        "",
        f"Repository: {root}",
        f"Mode: {'write' if write else 'dry-run'}",
        f"Total Lua files: {len(results)}",
        f"Already UTF-8: {already_utf8}",
        f"{'Converted' if write else 'Would convert'}: {converted if write else would_convert}",
        f"Skipped: {skipped}",
        "",
    ]

    changed_actions = {"converted"} if write else {"would_convert"}
    changed_label = "## Converted Files" if write else "## Files To Convert"
    changed = [result for result in results if result.action in changed_actions]
    if changed:
        lines.append(changed_label)
        for result in changed:
            lines.append(f"- {result.path} ({result.previous_encoding} -> utf-8)")
        lines.append("")

    skipped_results = [result for result in results if result.action == "skipped"]
    if skipped_results:
        lines.append("## Skipped Files")
        for result in skipped_results:
            lines.append(f"- {result.path}: {result.reason}")
        lines.append("")

    if not changed and not skipped_results:
        lines.append("No encoding changes needed.")

    if not write:
        lines.append("Run again with --write to apply the conversion.")

    return "\n".join(lines).rstrip()


def _usage() -> str:
    cli_name = "lua-nil-guard"
    return "\n".join(
        line.format(cli=cli_name)
        for line in [
            "Usage:",
            "  {cli} scan [--focus MODE] <repository>",
            "  {cli} doctor",
            "  {cli} init-config [--force] <repository>",
            "  {cli} macro-audit <repository> [output]",
            "  {cli} macro-audit-json <repository> [output]",
            "  {cli} macro-build-cache <repository> [output]",
            "  {cli} macro-build-cache-json <repository> [output]",
            "  {cli} macro-cache-status <repository> [output]",
            "  {cli} macro-cache-status-json <repository> [output]",
            "  {cli} encoding-audit <repository> [output]",
            "  {cli} normalize-encoding [--write] <repository> [output]",
            "  {cli} clear-backend-cache <cache-file>",
            "  {cli} generate-backend-manifest <name> <protocol> [output]",
            "  {cli} validate-backend-manifest <manifest-path>",
            "  {cli} validate-backend-manifest-json <manifest-path> [output]",
            "  {cli} register-backend-manifest [--replace] <manifest-path>",
            "  {cli} register-backend-manifest-json [--replace] <manifest-path> [output]",
            "  {cli} compare-benchmark-json <before> <after> [output]",
            "  {cli} report [--focus MODE] [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository>",
            "  {cli} report-json [--focus MODE] [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository>",
            "  {cli} benchmark [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository>",
            "  {cli} benchmark-json [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> [output]",
            "  {cli} benchmark-cache-compare [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] --backend-cache PATH [--backend-config KEY=VALUE] <repository>",
            "  {cli} benchmark-cache-compare-json [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] --backend-cache PATH [--backend-config KEY=VALUE] <repository> [output]",
            "  {cli} baseline-create [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> <output>",
            "  {cli} report-new [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> <baseline>",
            "  {cli} refresh-summaries <repository> [output]",
            "  {cli} refresh-knowledge <repository> [output]",
            "  {cli} ci-check [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> <baseline>",
            "  {cli} export-prompts [--skill SKILL] [--allow-skill-fallback] <repository> [output]",
            "  {cli} export-autofix [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> [output]",
            "  {cli} apply-autofix [--dry-run] [--case-id CASE_ID] [--file PATH] <autofix-manifest>",
            "  {cli} export-unified-diff [--case-id CASE_ID] [--file PATH] <autofix-manifest> [output]",
            "  {cli} scan-file [--focus MODE] <file.lua>",
            "  {cli} report-file [--focus MODE] [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <file.lua>",
            "  {cli} report-file-json [--focus MODE] [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <file.lua>",
            "  {cli} proposal-export [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> [output]",
            "  {cli} proposal-export-json [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> [output]",
            "  {cli} proposal-analytics [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> [output]",
            "  {cli} proposal-analytics-json [--backend BACKEND] [--model MODEL] [--skill SKILL] [--allow-skill-fallback] [--backend-executable PATH] [--backend-manifest PATH] [--backend-timeout SECONDS] [--backend-attempts N] [--expanded-evidence-retry MODE] [--backend-cache PATH] [--backend-config KEY=VALUE] <repository> [output]",
            "",
            "Backend values: heuristic | codex | claude | gemini",
            "Focus values: all | string",
        ]
    )


def _parse_focus_options(args: list[str]) -> tuple[str, list[str]]:
    focus_mode = _FOCUS_MODE_ALL
    positional: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--focus":
            if index + 1 >= len(args):
                raise ValueError("--focus requires a value")
            focus_value = args[index + 1].strip().lower()
            if focus_value not in _FOCUS_MODE_VALUES:
                allowed = ", ".join(_FOCUS_MODE_VALUES)
                raise ValueError(f"--focus must be one of: {allowed}")
            focus_mode = focus_value
            index += 2
            continue
        positional.append(token)
        index += 1
    return focus_mode, positional


def _apply_focus_mode(snapshot, focus_mode: str):  # noqa: ANN001
    if focus_mode == _FOCUS_MODE_ALL:
        return snapshot
    if focus_mode != _FOCUS_MODE_STRING:
        raise ValueError(f"Unsupported focus mode: {focus_mode}")
    filtered_rules = tuple(
        rule
        for rule in snapshot.sink_rules
        if any(rule.id.startswith(prefix) for prefix in _STRING_FOCUS_RULE_PREFIXES)
    )
    return replace(snapshot, sink_rules=filtered_rules)


def _parse_review_options(
    args: list[str],
) -> tuple[
    str,
    str | None,
    Path | None,
    bool,
    str | None,
    Path | None,
    float | None,
    int | None,
    Path | None,
    bool | None,
    tuple[str, ...],
    list[str],
]:
    backend_name = "heuristic"
    model: str | None = None
    skill_path: Path | None = None
    strict_skill = True
    executable: str | None = None
    backend_manifest_path: Path | None = None
    backend_timeout: float | None = None
    backend_attempts: int | None = None
    expanded_evidence_retry: bool | None = None
    backend_cache_path: Path | None = None
    backend_config_overrides: list[str] = []
    positional: list[str] = []
    index = 0

    while index < len(args):
        token = args[index]
        if token == "--backend":
            if index + 1 >= len(args):
                raise ValueError("--backend requires a value")
            backend_name = args[index + 1]
            index += 2
            continue
        if token == "--model":
            if index + 1 >= len(args):
                raise ValueError("--model requires a value")
            model = args[index + 1]
            index += 2
            continue
        if token == "--skill":
            if index + 1 >= len(args):
                raise ValueError("--skill requires a value")
            skill_path = Path(args[index + 1])
            index += 2
            continue
        if token == "--allow-skill-fallback":
            strict_skill = False
            index += 1
            continue
        if token == "--backend-executable":
            if index + 1 >= len(args):
                raise ValueError("--backend-executable requires a value")
            executable = args[index + 1]
            index += 2
            continue
        if token == "--backend-manifest":
            if index + 1 >= len(args):
                raise ValueError("--backend-manifest requires a value")
            backend_manifest_path = Path(args[index + 1])
            index += 2
            continue
        if token == "--backend-timeout":
            if index + 1 >= len(args):
                raise ValueError("--backend-timeout requires a value")
            try:
                backend_timeout = float(args[index + 1])
            except ValueError as exc:
                raise ValueError("--backend-timeout must be a positive number") from exc
            if backend_timeout <= 0:
                raise ValueError("--backend-timeout must be a positive number")
            index += 2
            continue
        if token == "--backend-attempts":
            if index + 1 >= len(args):
                raise ValueError("--backend-attempts requires a value")
            try:
                backend_attempts = int(args[index + 1])
            except ValueError as exc:
                raise ValueError("--backend-attempts must be an integer >= 1") from exc
            if backend_attempts < 1:
                raise ValueError("--backend-attempts must be an integer >= 1")
            index += 2
            continue
        if token == "--expanded-evidence-retry":
            if index + 1 >= len(args):
                raise ValueError("--expanded-evidence-retry requires a value")
            raw_mode = args[index + 1].strip().lower()
            if raw_mode == "auto":
                expanded_evidence_retry = None
            elif raw_mode == "on":
                expanded_evidence_retry = True
            elif raw_mode == "off":
                expanded_evidence_retry = False
            else:
                raise ValueError("--expanded-evidence-retry must be one of: auto, on, off")
            index += 2
            continue
        if token == "--backend-cache":
            if index + 1 >= len(args):
                raise ValueError("--backend-cache requires a value")
            backend_cache_path = Path(args[index + 1])
            index += 2
            continue
        if token == "--backend-config":
            if index + 1 >= len(args):
                raise ValueError("--backend-config requires a value")
            override = args[index + 1]
            if "=" not in override:
                raise ValueError("--backend-config must be in KEY=VALUE form")
            backend_config_overrides.append(override)
            index += 2
            continue
        positional.append(token)
        index += 1

    return (
        backend_name,
        model,
        skill_path,
        strict_skill,
        executable,
        backend_manifest_path,
        backend_timeout,
        backend_attempts,
        expanded_evidence_retry,
        backend_cache_path,
        tuple(backend_config_overrides),
        positional,
    )


def _parse_export_options(args: list[str]) -> tuple[Path | None, bool, list[str]]:
    skill_path: Path | None = None
    strict_skill = True
    positional: list[str] = []
    index = 0

    while index < len(args):
        token = args[index]
        if token == "--skill":
            if index + 1 >= len(args):
                raise ValueError("--skill requires a value")
            skill_path = Path(args[index + 1])
            index += 2
            continue
        if token == "--allow-skill-fallback":
            strict_skill = False
            index += 1
            continue
        positional.append(token)
        index += 1

    return skill_path, strict_skill, positional


def _parse_autofix_selection_options(
    args: list[str],
    *,
    allow_dry_run: bool = False,
) -> tuple[bool, tuple[str, ...], tuple[Path, ...], list[str]]:
    dry_run = False
    case_ids: list[str] = []
    file_paths: list[Path] = []
    positional: list[str] = []
    index = 0

    while index < len(args):
        token = args[index]
        if allow_dry_run and token == "--dry-run":
            dry_run = True
            index += 1
            continue
        if token == "--case-id":
            if index + 1 >= len(args):
                raise ValueError("--case-id requires a value")
            case_ids.append(args[index + 1])
            index += 2
            continue
        if token == "--file":
            if index + 1 >= len(args):
                raise ValueError("--file requires a value")
            file_paths.append(Path(args[index + 1]))
            index += 2
            continue
        positional.append(token)
        index += 1

    return dry_run, tuple(case_ids), tuple(file_paths), positional


if __name__ == "__main__":
    raise SystemExit(main())
