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

from .configuration import ConfigurationError, parse_json, resolve_configuration
from .coverage_adapter import CoverageAdapter
from .doxygen_adapter import DoxygenAdapter
from .orchestrator import OrchestrationError, create_candidate
from .plan import create_plan
from .process_runner import WorkspaceManager
from .publication import (
    LinuxPublicationOperations,
    PublicationDiagnostic,
    PublicationResult,
    PublicationState,
    publish_candidate,
    recover_publication_if_present,
)
from .snapshot import SnapshotError, capture_git_snapshot
from .verify import VerificationError, verify_bundle


def _diagnostic(code: str, message: str) -> str:
    return json.dumps(
        {"diagnostics": [{"code": code, "message": message}], "valid": False},
        separators=(",", ":"),
        sort_keys=True,
    )


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
                sys.stdout.buffer.write(recovered.canonical_bytes + b"\n")
                return recovered.exit_code
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
    sys.stdout.buffer.write(result.canonical_bytes + b"\n")
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osqar-inspector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--project", required=True)
    plan.add_argument("--configuration", required=True)
    plan.add_argument("--override", action="append", default=[], nargs="+")
    build = subparsers.add_parser("build")
    build.add_argument("--project", required=True)
    build.add_argument("--configuration", required=True)
    build.add_argument("--override", action="append", default=[], nargs="+")
    build.add_argument("--run-id")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    args = parser.parse_args(argv)

    if args.command == "build":
        return _run_build(args)

    if args.command == "plan":
        try:
            return _run_plan(args)
        except ConfigurationError as error:
            print(_diagnostic(error.code, error.message), file=sys.stderr)
            return 1
        except SnapshotError as error:
            print(_diagnostic(error.code, error.message), file=sys.stderr)
            return 1
        except OSError as error:
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
        print(
            json.dumps(
                {"diagnostics": [error.diagnostic()], "valid": False},
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
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
