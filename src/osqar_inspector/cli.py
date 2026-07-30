"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from .configuration import ConfigurationError, parse_json, resolve_configuration
from .coverage_adapter import CoverageAdapter
from .doxygen_adapter import DoxygenAdapter
from .orchestrator import OrchestrationError, create_candidate
from .plan import create_plan
from .process_protocol import (
    BUILD_RESULT_SCHEMA,
    PLAN_RESULT_SCHEMA,
    PROTOCOL,
    VERIFY_RESULT_SCHEMA,
    capabilities,
    protocol_error,
    source_binding,
)
from .process_protocol import write_result as _write_result
from .process_runner import WorkspaceManager
from .publication import (
    LinuxPublicationOperations,
    PublicationDiagnostic,
    PublicationResult,
    PublicationState,
    publish_candidate,
    recover_publication_if_present,
    valid_caller_run_id,
)
from .snapshot import SnapshotError, capture_git_snapshot
from .verify import VerificationError, verify_bundle


def _diagnostic(code: str, message: str) -> str:
    return json.dumps(
        {"diagnostics": [{"code": code, "message": message}], "valid": False},
        separators=(",", ":"),
        sort_keys=True,
    )


def _close_result_directory(args: argparse.Namespace) -> None:
    descriptor = getattr(args, "result_directory_fd", None)
    if descriptor is not None:
        os.close(descriptor)
        args.result_directory_fd = None


class _ResultChannelError(RuntimeError):
    pass


def _write_machine_result(args: argparse.Namespace, value: dict[str, Any]) -> None:
    descriptor = getattr(args, "result_directory_fd", None)
    if descriptor is None:
        raise _ResultChannelError("machine result channel is no longer available")
    try:
        try:
            current = Path(args.result_directory_path).stat(follow_symlinks=False)
            anchored = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or (current.st_dev, current.st_ino)
                != (anchored.st_dev, anchored.st_ino)
            ):
                raise _ResultChannelError(
                    "machine result directory changed during execution"
                )
            _write_result(args.result_file, value, directory_fd=descriptor)
        except OSError as error:
            raise _ResultChannelError("machine result channel failed") from error
    finally:
        _close_result_directory(args)


def _project_file(project: Path, value: str) -> Path:
    parts = PurePosixPath(value).parts
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ConfigurationError(
            "configuration.invalid_path",
            "configuration path must satisfy the project-relative path profile",
        )
    return project.joinpath(*parts)


def _overrides(values: list[list[str]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for arguments in values:
        if len(arguments) == 1 and "=" in arguments[0]:
            pointer, encoded = arguments[0].split("=", 1)
        elif len(arguments) == 2:
            pointer, encoded = arguments
        else:
            raise ConfigurationError(
                "configuration.invalid_override",
                "override must be POINTER=JSON or POINTER JSON",
            )
        try:
            parsed = parse_json(encoded.encode("utf-8"), require_object=False)
        except UnicodeEncodeError as error:
            raise ConfigurationError(
                "configuration.invalid_override", "override is not valid UTF-8"
            ) from error
        result.append({"pointer": pointer, "value": parsed})
    return result


def _run_plan(args: argparse.Namespace) -> int:
    project = Path(args.project)
    configuration_path = _project_file(project, args.configuration)
    controlled = configuration_path.read_bytes()
    configuration = resolve_configuration(
        controlled, args.configuration, _overrides(args.override)
    )
    policy = configuration.value["project"]
    snapshot = capture_git_snapshot(
        project,
        include=policy["include"],
        exclude=policy["exclude"],
    )
    plan = create_plan(configuration, snapshot)
    if args.result_file is not None:
        _write_machine_result(
            args,
            {
                "configuration_identity": configuration.identity,
                "diagnostics": [
                    {"code": item["code"], "message": item["message"]}
                    for item in plan.value["diagnostics"]
                ],
                "plan": plan.value,
                "protocol": PROTOCOL,
                "schema": PLAN_RESULT_SCHEMA,
                "source": source_binding(snapshot.manifest),
                "status": "blocked" if plan.blocked else "succeeded",
            },
        )
    else:
        sys.stdout.write(plan.plan_bytes.decode("utf-8") + "\n")
    return 1 if plan.blocked else 0


def _inspect_publication_root(project: Path, relative: str) -> Path | None:
    """Return an existing safe publication root without creating snapshot-visible paths."""

    root = project.resolve(strict=True)
    project_info = root.lstat()
    current = root
    for part in PurePosixPath(relative).parts:
        candidate = current / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(
                "publication destination contains a non-directory or symbolic-link component"
            )
        if info.st_dev != project_info.st_dev:
            raise OSError("publication destination crosses a filesystem boundary")
        current = candidate
    return current


def _prepare_publication_root(project: Path, relative: str) -> Path:
    """Create a project-relative publication root without following symlink components."""

    root = project.resolve(strict=True)
    project_info = root.lstat()
    current = root
    operations = LinuxPublicationOperations()
    for part in PurePosixPath(relative).parts:
        candidate = current / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            try:
                candidate.mkdir()
            except FileExistsError:
                pass
            info = candidate.lstat()
            operations.fsync_directory(current)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(
                "publication destination contains a non-directory or symbolic-link component"
            )
        if info.st_dev != project_info.st_dev:
            raise OSError("publication destination crosses a filesystem boundary")
        current = candidate
    return current


def _not_attempted(run_id: str, code: str, message: str) -> PublicationResult:
    return PublicationResult(
        run_id,
        PublicationState.NOT_ATTEMPTED,
        None,
        None,
        "reports/run.json",
        None,
        None,
        None,
        (PublicationDiagnostic(code, message),),
    )


def _run_build(args: argparse.Namespace) -> int:
    run_id = args.run_id or f"run-{secrets.token_hex(16)}"
    configuration = None
    snapshot = None
    try:
        project = Path(args.project).resolve(strict=True)
        configuration_path = _project_file(project, args.configuration)
        configuration = resolve_configuration(
            configuration_path.read_bytes(),
            args.configuration,
            _overrides(args.override),
        )
        publication_relative = configuration.value["publication"]["destination"]
        existing_publication = _inspect_publication_root(project, publication_relative)
        if existing_publication is not None:
            recovered = recover_publication_if_present(existing_publication)
            if recovered is not None:
                if args.result_file is None:
                    sys.stdout.buffer.write(recovered.canonical_bytes + b"\n")
                    return recovered.exit_code
                policy = configuration.value["project"]
                snapshot = capture_git_snapshot(
                    project,
                    include=policy["include"],
                    exclude=policy["exclude"],
                    allowed_untracked=(publication_relative,),
                )
                result = recovered
                _write_machine_result(
                    args,
                    {
                        "configuration_identity": configuration.identity,
                        "protocol": PROTOCOL,
                        "publication": json.loads(result.canonical_bytes),
                        "schema": BUILD_RESULT_SCHEMA,
                        "source": source_binding(snapshot.manifest),
                        "status": (
                            "succeeded"
                            if result.state
                            in {
                                PublicationState.DURABLE_SUCCESS,
                                PublicationState.RECOVERED_DURABLE_SUCCESS,
                            }
                            else "failed"
                        ),
                    },
                )
                return result.exit_code
        policy = configuration.value["project"]
        snapshot = capture_git_snapshot(
            project,
            include=policy["include"],
            exclude=policy["exclude"],
            allowed_untracked=(publication_relative,),
        )
        stage_policy = configuration.value["stages"]
        adapters = {}
        if stage_policy["doxygen"]["enabled"]:
            adapters["doxygen"] = DoxygenAdapter()
        if stage_policy["coverage"]["enabled"]:
            adapters["coverage"] = CoverageAdapter()
        plan = create_plan(configuration, snapshot, adapters)
        candidate = create_candidate(
            configuration,
            snapshot,
            plan,
            adapters,
            WorkspaceManager(project),
        )
        publication_root = _prepare_publication_root(project, publication_relative)
        result = publish_candidate(candidate, publication_root, run_id=run_id)
    except (ConfigurationError, SnapshotError, OrchestrationError) as error:
        result = _not_attempted(run_id, error.code, error.message)
    except (OSError, RuntimeError, ValueError) as error:
        result = _not_attempted(run_id, "build.infrastructure_error", str(error))
    if args.result_file is not None:
        _write_machine_result(
            args,
            {
                "configuration_identity": (
                    configuration.identity if configuration is not None else None
                ),
                "protocol": PROTOCOL,
                "publication": json.loads(result.canonical_bytes),
                "schema": BUILD_RESULT_SCHEMA,
                "source": (
                    source_binding(snapshot.manifest) if snapshot is not None else None
                ),
                "status": (
                    "succeeded"
                    if result.state
                    in {
                        PublicationState.DURABLE_SUCCESS,
                        PublicationState.RECOVERED_DURABLE_SUCCESS,
                    }
                    else "failed"
                ),
            },
        )
    else:
        sys.stdout.buffer.write(result.canonical_bytes + b"\n")
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osqar-inspector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    capability = subparsers.add_parser("capabilities")
    capability.add_argument("--protocol", required=True)
    capability.add_argument("--result-file", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--project", required=True)
    plan.add_argument("--configuration", required=True)
    plan.add_argument("--override", action="append", default=[], nargs="+")
    plan.add_argument("--protocol")
    plan.add_argument("--result-schema")
    plan.add_argument("--result-file")
    build = subparsers.add_parser("build")
    build.add_argument("--project", required=True)
    build.add_argument("--configuration", required=True)
    build.add_argument("--override", action="append", default=[], nargs="+")
    build.add_argument("--run-id")
    build.add_argument("--protocol")
    build.add_argument("--result-schema")
    build.add_argument("--result-file")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--protocol")
    verify.add_argument("--result-schema")
    verify.add_argument("--result-file")
    args = parser.parse_args(argv)

    requested_protocol = getattr(args, "protocol", None)
    result_file = getattr(args, "result_file", None)
    args.result_directory_fd = None
    if result_file is not None:
        result_path = Path(result_file)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(result_path.parent, flags)
        except OSError:
            return 2
        try:
            parent_info = os.fstat(descriptor)
            try:
                os.stat(result_path.name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                exists = False
            else:
                exists = True
        except OSError:
            os.close(descriptor)
            return 2
        if not result_path.name or exists or not stat.S_ISDIR(parent_info.st_mode):
            os.close(descriptor)
            return 2
        args.result_directory_fd = descriptor
        args.result_directory_path = result_path.parent
    if result_file is not None and args.command in {"plan", "build", "verify"}:
        protected = args.bundle if args.command == "verify" else args.project
        protected_root = Path(protected).resolve(strict=False)
        result_path = Path(result_file).resolve(strict=False)
        if result_path == protected_root or protected_root in result_path.parents:
            _close_result_directory(args)
            return 2
    if requested_protocol is not None and requested_protocol != PROTOCOL:
        if result_file is not None:
            _write_machine_result(
                args,
                protocol_error(
                    requested_protocol,
                    "protocol.unsupported",
                    f"unsupported process protocol {requested_protocol!r}",
                ),
            )
        return 2
    expected_schema = {
        "plan": PLAN_RESULT_SCHEMA,
        "build": BUILD_RESULT_SCHEMA,
        "verify": VERIFY_RESULT_SCHEMA,
    }.get(args.command)
    requested_schema = getattr(args, "result_schema", None)
    if expected_schema is not None:
        negotiation = (requested_protocol, requested_schema, result_file)
        if any(item is not None for item in negotiation) and any(
            item is None for item in negotiation
        ):
            if result_file is not None:
                _write_machine_result(
                    args,
                    protocol_error(
                        requested_protocol or PROTOCOL,
                        "protocol.incomplete_negotiation",
                        "protocol, result schema, and result file are required together",
                    ),
                )
            return 2
    if requested_schema is not None and requested_schema != expected_schema:
        if result_file is not None:
            _write_machine_result(
                args,
                protocol_error(
                    requested_protocol or PROTOCOL,
                    "protocol.unsupported_result_schema",
                    f"unsupported {args.command} result schema {requested_schema!r}",
                ),
            )
        return 2
    if args.command == "build" and result_file is not None and not args.run_id:
        _write_machine_result(
            args,
            protocol_error(
                requested_protocol or PROTOCOL,
                "protocol.missing_run_id",
                "machine build requires a caller-owned run ID",
            ),
        )
        return 2
    if (
        args.command == "build"
        and result_file is not None
        and not valid_caller_run_id(args.run_id)
    ):
        _write_machine_result(
            args,
            protocol_error(
                requested_protocol or PROTOCOL,
                "protocol.invalid_run_id",
                "run identifier must be one safe path component",
            ),
        )
        return 2

    if args.command == "capabilities":
        _write_machine_result(args, capabilities())
        return 0

    if args.command == "build":
        return _run_build(args)

    if args.command == "plan":
        try:
            return _run_plan(args)
        except ConfigurationError as error:
            if args.result_file is not None:
                _write_machine_result(
                    args,
                    {
                        "configuration_identity": None,
                        "diagnostics": [
                            {"code": error.code, "message": error.message}
                        ],
                        "plan": None,
                        "protocol": PROTOCOL,
                        "schema": PLAN_RESULT_SCHEMA,
                        "source": None,
                        "status": "failed",
                    },
                )
                return 1
            print(_diagnostic(error.code, error.message), file=sys.stderr)
            return 1
        except SnapshotError as error:
            if args.result_file is not None:
                _write_machine_result(
                    args,
                    {
                        "configuration_identity": None,
                        "diagnostics": [
                            {"code": error.code, "message": error.message}
                        ],
                        "plan": None,
                        "protocol": PROTOCOL,
                        "schema": PLAN_RESULT_SCHEMA,
                        "source": None,
                        "status": "failed",
                    },
                )
                return 1
            print(_diagnostic(error.code, error.message), file=sys.stderr)
            return 1
        except OSError as error:
            if args.result_file is not None:
                _write_machine_result(
                    args,
                    {
                        "configuration_identity": None,
                        "diagnostics": [
                            {
                                "code": "plan.input_error",
                                "message": (
                                    os.strerror(error.errno)
                                    if error.errno
                                    else str(error)
                                ),
                            }
                        ],
                        "plan": None,
                        "protocol": PROTOCOL,
                        "schema": PLAN_RESULT_SCHEMA,
                        "source": None,
                        "status": "failed",
                    },
                )
                return 1
            print(
                _diagnostic(
                    "plan.input_error",
                    os.strerror(error.errno) if error.errno else str(error),
                ),
                file=sys.stderr,
            )
            return 1

    try:
        bundle_id = verify_bundle(Path(args.bundle))
    except VerificationError as error:
        if args.result_file is not None:
            _write_machine_result(
                args,
                {
                    "bundle_id": None,
                    "diagnostics": [error.diagnostic()],
                    "protocol": PROTOCOL,
                    "schema": VERIFY_RESULT_SCHEMA,
                    "status": "failed",
                    "valid": False,
                },
            )
        else:
            print(
                json.dumps(
                    {"diagnostics": [error.diagnostic()], "valid": False},
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        return 1
    if args.result_file is not None:
        _write_machine_result(
            args,
            {
                "bundle_id": bundle_id,
                "diagnostics": [],
                "protocol": PROTOCOL,
                "schema": VERIFY_RESULT_SCHEMA,
                "status": "succeeded",
                "valid": True,
            },
        )
        return 0
    print(
        json.dumps(
            {"bundle_id": bundle_id, "valid": True},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
