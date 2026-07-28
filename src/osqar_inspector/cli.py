"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Sequence

from .configuration import ConfigurationError, parse_json, resolve_configuration
from .plan import create_plan
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osqar-inspector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--project", required=True)
    plan.add_argument("--configuration", required=True)
    plan.add_argument("--override", action="append", default=[], nargs="+")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    args = parser.parse_args(argv)

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
            print(_diagnostic("plan.input_error", os.strerror(error.errno) if error.errno else str(error)), file=sys.stderr)
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
    print(json.dumps({"bundle_id": bundle_id, "valid": True}, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
