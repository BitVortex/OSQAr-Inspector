"""Versioned process boundary for OSQAr callers."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any

from .configuration import SAFE_INTEGER, ConfigurationError, canonical_json
from .configuration import _overrides as validate_overrides
from .configuration import _path as validate_project_path
from .publication import valid_caller_run_id, valid_run_id

PROTOCOL = "osqar-inspector-run-v1"
CAPABILITIES_SCHEMA = "osqar.inspector.capabilities-result.v1"
PLAN_RESULT_SCHEMA = "osqar.inspector.plan-process-result.v1"
BUILD_RESULT_SCHEMA = "osqar.inspector.build-process-result.v1"
VERIFY_RESULT_SCHEMA = "osqar.inspector.verify-process-result.v1"
ERROR_SCHEMA = "osqar.inspector.protocol-error.v1"

SUPPORTED_SCHEMAS = {
    "bundle": ("osqar.inspector.bundle-manifest.v1",),
    "config": ("osqar.inspector.config.v1",),
    "plan": ("osqar.inspector.plan.v1",),
    "publication-result": ("osqar.inspector.publication-result.v1",),
    "run-report": ("osqar.inspector.run.v1",),
    "signature-envelope": ("osqar.inspector.detached-signature.v1",),
    "snapshot": ("osqar.inspector.snapshot.v1",),
    "stage-result": ("osqar.inspector.stage-result.v1",),
}


class ProcessProtocolError(ValueError):
    """A caller-side rejection of malformed or inconsistent process output."""

    @property
    def message(self) -> str:
        return str(self)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProcessProtocolError(f"duplicate result member {key!r}")
        value[key] = item
    return value


def _parse_integer(token: str) -> int:
    if token == "-0" or re.fullmatch(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)", token) is None:
        raise ProcessProtocolError("result contains an invalid integer token")
    try:
        value = int(token)
    except (ValueError, RecursionError) as error:
        raise ProcessProtocolError("result integer cannot be represented") from error
    if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
        raise ProcessProtocolError("result integer is outside the safe range")
    return value


def _reject_noninteger(token: str) -> None:
    raise ProcessProtocolError(f"result contains forbidden number token {token!r}")


def _keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProcessProtocolError(f"{name} is not a closed protocol object")
    return value


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _bundle_id(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"bundle:sha256:[0-9a-f]{64}", value
    ) is not None


def _source_binding(value: Any) -> dict[str, Any]:
    source = _keys(value, {"commit", "kind", "object_format", "tree"}, "source")
    if (
        source["kind"] != "git-clean"
        or source["object_format"] not in {"sha1", "sha256"}
        or not all(isinstance(source[name], str) for name in ("commit", "tree"))
    ):
        raise ProcessProtocolError("invalid source binding")
    object_id_size = 40 if source["object_format"] == "sha1" else 64
    if any(
        re.fullmatch(rf"[0-9a-f]{{{object_id_size}}}", source[name]) is None
        for name in ("commit", "tree")
    ):
        raise ProcessProtocolError("invalid source object identity")
    return source


def _configuration_identity(value: Any) -> dict[str, Any]:
    identity = _keys(
        value,
        {"controlled_input", "defaults", "overrides", "resolved", "schema"},
        "configuration identity",
    )
    controlled = _keys(
        identity["controlled_input"], {"path", "sha256", "size"}, "controlled input"
    )
    defaults = _keys(identity["defaults"], {"id", "sha256"}, "defaults identity")
    resolved = _keys(identity["resolved"], {"sha256"}, "resolved identity")
    schema = _keys(
        identity["schema"], {"id", "sha256"}, "configuration schema identity"
    )
    try:
        validate_project_path(controlled["path"])
        accepted = validate_overrides(identity["overrides"])
    except ConfigurationError as error:
        raise ProcessProtocolError("invalid configuration identity binding") from error
    normalized_overrides = [
        {"pointer": pointer, "value": item} for pointer, _, item in accepted
    ]
    if (
        not isinstance(controlled["size"], str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)", controlled["size"]) is None
        or not _sha256(controlled["sha256"])
        or defaults["id"] != "builtin-v1"
        or not _sha256(defaults["sha256"])
        or not _sha256(resolved["sha256"])
        or schema["id"] != "osqar.inspector.config.v1"
        or not _sha256(schema["sha256"])
        or identity["overrides"] != normalized_overrides
    ):
        raise ProcessProtocolError("invalid configuration identity binding")
    return identity


def _binding_shapes(result: dict[str, Any]) -> None:
    _source_binding(result["source"])
    _configuration_identity(result["configuration_identity"])


def _diagnostics(value: Any) -> None:
    if not isinstance(value, list):
        raise ProcessProtocolError("diagnostics must be an array")
    for diagnostic in value:
        if not isinstance(diagnostic, dict):
            raise ProcessProtocolError("diagnostic is not a closed protocol object")
        keys = set(diagnostic)
        if keys not in ({"code", "message"}, {"code", "message", "path"}):
            raise ProcessProtocolError("diagnostic is not a closed protocol object")
        checked = diagnostic
        scalar_members = ("code", "message", "path") if "path" in checked else (
            "code",
            "message",
        )
        if not all(
            isinstance(checked[name], str) and checked[name] for name in scalar_members
        ):
            raise ProcessProtocolError("diagnostic fields must be non-empty strings")


def _strings(value: Any, name: str, *, paths: bool = False) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ProcessProtocolError(f"{name} must be an array of non-empty strings")
    if paths:
        try:
            for item in value:
                validate_project_path(item)
        except ConfigurationError as error:
            raise ProcessProtocolError(f"{name} contains an invalid path") from error
    if len(value) != len(set(value)):
        raise ProcessProtocolError(f"{name} contains duplicates")
    return value


def _snapshot_identity(value: Any, source: dict[str, Any]) -> dict[str, Any]:
    snapshot = _keys(
        value,
        {"files", "policy", "schema", "snapshot_id", "source"},
        "plan snapshot",
    )
    if snapshot["schema"] != "osqar.inspector.snapshot.v1" or snapshot["source"] != source:
        raise ProcessProtocolError("invalid plan snapshot binding")
    _source_binding(snapshot["source"])
    policy = _keys(snapshot["policy"], {"exclude", "include"}, "snapshot policy")
    for name in ("include", "exclude"):
        paths = _strings(policy[name], f"snapshot policy {name}", paths=True)
        if paths != sorted(paths, key=str.encode):
            raise ProcessProtocolError("snapshot policy paths are not canonical")
    if not isinstance(snapshot["files"], list):
        raise ProcessProtocolError("snapshot files must be an array")
    seen: set[str] = set()
    for item in snapshot["files"]:
        record = _keys(
            item, {"identity", "kind", "mode", "path", "size"}, "snapshot file"
        )
        try:
            validate_project_path(record["path"])
        except ConfigurationError as error:
            raise ProcessProtocolError("snapshot file path is invalid") from error
        if record["path"] in seen:
            raise ProcessProtocolError("snapshot file paths are not unique")
        seen.add(record["path"])
        if (
            record["kind"] not in {"file", "symlink"}
            or record["mode"] not in {"100644", "100755", "120000"}
            or (record["kind"] == "symlink") != (record["mode"] == "120000")
            or not isinstance(record["size"], str)
            or re.fullmatch(r"(?:0|[1-9][0-9]*)", record["size"]) is None
        ):
            raise ProcessProtocolError("snapshot file record is invalid")
        expected_identity = {"sha256"} if record["kind"] == "file" else {"sha256", "target"}
        identity = _keys(record["identity"], expected_identity, "snapshot file identity")
        if not _sha256(identity["sha256"]):
            raise ProcessProtocolError("snapshot file digest is invalid")
        if record["kind"] == "symlink":
            try:
                validate_project_path(identity["target"])
            except ConfigurationError as error:
                raise ProcessProtocolError("snapshot symlink target is invalid") from error
    paths = [record["path"] for record in snapshot["files"]]
    if paths != sorted(paths, key=str.encode):
        raise ProcessProtocolError("snapshot files are not canonically ordered")
    selected_modes = {record["path"]: record["mode"] for record in snapshot["files"]}
    for record in snapshot["files"]:
        if record["kind"] != "symlink":
            continue
        target = record["identity"]["target"]
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(record["path"]), target)
        )
        if (
            selected_modes.get(resolved) not in {"100644", "100755"}
            or record["identity"]["sha256"]
            != hashlib.sha256(target.encode("utf-8")).hexdigest()
        ):
            raise ProcessProtocolError(
                "snapshot symlink must identify a selected non-symlink file"
            )
    identity = {
        "schema": snapshot["schema"],
        "source": snapshot["source"],
        "policy": snapshot["policy"],
        "files": snapshot["files"],
    }
    digest = hashlib.sha256(
        canonical_json({"kind": "snapshot", "identity": identity})
    ).hexdigest()
    if snapshot["snapshot_id"] != f"snapshot:sha256:{digest}":
        raise ProcessProtocolError("snapshot identity digest is inconsistent")
    return snapshot


def _plan_payload(result: dict[str, Any]) -> bool:
    plan = _keys(
        result["plan"],
        {"configuration", "diagnostics", "edges", "plan_digest", "schema", "snapshot", "stages"},
        "plan payload",
    )
    if plan["schema"] != "osqar.inspector.plan.v1":
        raise ProcessProtocolError("unsupported nested plan schema")
    if plan["configuration"] != result["configuration_identity"]:
        raise ProcessProtocolError("plan configuration contradicts handoff binding")
    _configuration_identity(plan["configuration"])
    _snapshot_identity(plan["snapshot"], result["source"])
    if not isinstance(plan["stages"], list):
        raise ProcessProtocolError("plan stages must be an array")
    stage_ids: list[str] = []
    for item in plan["stages"]:
        stage = _keys(
            item,
            {
                "adapter", "adapter_options", "capability", "dependencies",
                "expected_outputs", "id", "invocation", "policy", "required_inputs",
                "workspace",
            },
            "plan stage",
        )
        if not isinstance(stage["id"], str) or not stage["id"]:
            raise ProcessProtocolError("plan stage ID is invalid")
        stage_ids.append(stage["id"])
        adapter = _keys(stage["adapter"], {"selector"}, "plan adapter")
        if not isinstance(adapter["selector"], str) or not adapter["selector"]:
            raise ProcessProtocolError("plan adapter selector is invalid")
        options = stage["adapter_options"]
        if not isinstance(options, dict) or set(options) - {"warnings_as_errors"}:
            raise ProcessProtocolError("plan adapter options are not closed")
        if "warnings_as_errors" in options and not isinstance(options["warnings_as_errors"], bool):
            raise ProcessProtocolError("plan adapter option is invalid")
        _strings(stage["dependencies"], "plan dependencies")
        _strings(stage["expected_outputs"], "plan outputs", paths=True)
        _strings(stage["required_inputs"], "plan inputs", paths=True)
        if stage["policy"] not in {"required", "optional"}:
            raise ProcessProtocolError("plan stage policy is invalid")
        capability = stage["capability"]
        if capability is not None:
            checked = _keys(
                capability,
                {"executable", "status", "version_constraint"},
                "plan capability",
            )
            if (
                not isinstance(checked["executable"], str)
                or not checked["executable"]
                or checked["status"] != "unresolved"
                or (
                    checked["version_constraint"] is not None
                    and not isinstance(checked["version_constraint"], str)
                )
            ):
                raise ProcessProtocolError("plan capability is invalid")
        try:
            validate_project_path(stage["workspace"])
        except ConfigurationError as error:
            raise ProcessProtocolError("plan workspace is invalid") from error
        invocation = _keys(stage["invocation"], {"argv"}, "plan invocation")
        if not isinstance(invocation["argv"], list) or not invocation["argv"] or not all(
            isinstance(item, str) and item for item in invocation["argv"]
        ):
            raise ProcessProtocolError("plan invocation argv is invalid")
    if stage_ids != sorted(stage_ids, key=str.encode) or len(stage_ids) != len(set(stage_ids)):
        raise ProcessProtocolError("plan stages are not uniquely ordered")
    stage_id_set = set(stage_ids)
    dependencies = {
        stage["id"]: set(stage["dependencies"]) for stage in plan["stages"]
    }
    allowed_dependencies = stage_id_set | {"snapshot"}
    if any(
        dependency not in allowed_dependencies
        for stage_dependencies in dependencies.values()
        for dependency in stage_dependencies
    ):
        raise ProcessProtocolError("plan dependency names an unknown stage or root")
    pending = {
        stage: required & stage_id_set for stage, required in dependencies.items()
    }
    while pending:
        ready = {stage for stage, required in pending.items() if not required}
        if not ready:
            raise ProcessProtocolError("plan dependency graph contains a cycle")
        pending = {
            stage: required - ready
            for stage, required in pending.items()
            if stage not in ready
        }
    expected_edges = sorted(
        (
            {"from": dependency, "to": stage["id"]}
            for stage in plan["stages"]
            for dependency in stage["dependencies"]
        ),
        key=lambda edge: (edge["from"].encode(), edge["to"].encode()),
    )
    if plan["edges"] != expected_edges:
        raise ProcessProtocolError("plan edges contradict stage dependencies")
    if not isinstance(plan["diagnostics"], list):
        raise ProcessProtocolError("plan diagnostics must be an array")
    blocking = False
    projected: list[dict[str, str]] = []
    for item in plan["diagnostics"]:
        diagnostic = _keys(
            item, {"blocking", "code", "message", "stage"}, "plan diagnostic"
        )
        if (
            not isinstance(diagnostic["blocking"], bool)
            or not all(
                isinstance(diagnostic[name], str) and diagnostic[name]
                for name in ("code", "message", "stage")
            )
            or diagnostic["stage"] not in stage_ids
        ):
            raise ProcessProtocolError("plan diagnostic is invalid")
        blocking = blocking or diagnostic["blocking"]
        projected.append({"code": diagnostic["code"], "message": diagnostic["message"]})
    if result["diagnostics"] != projected:
        raise ProcessProtocolError("plan diagnostics contradict process diagnostics")
    identity = {key: item for key, item in plan.items() if key != "plan_digest"}
    digest = hashlib.sha256(
        canonical_json({"kind": "plan", "identity": identity})
    ).hexdigest()
    if plan["plan_digest"] != digest:
        raise ProcessProtocolError("plan digest is inconsistent")
    return blocking


def _publication_payload(value: Any) -> tuple[dict[str, Any], bool, int]:
    publication = _keys(
        value,
        {
            "bundle_id", "diagnostics", "intended_current_target",
            "prior_current_target", "release_path", "run_id", "run_report_path",
            "run_report_sha256", "schema", "state",
        },
        "publication result",
    )
    _diagnostics(publication["diagnostics"])
    if publication["schema"] != "osqar.inspector.publication-result.v1":
        raise ProcessProtocolError("unsupported publication result schema")
    run_id = publication["run_id"]
    if not isinstance(run_id, str) or not valid_run_id(run_id):
        raise ProcessProtocolError("publication run ID is invalid")
    if publication["run_report_path"] != "reports/run.json":
        raise ProcessProtocolError("publication run report path is invalid")
    if publication["bundle_id"] is not None and not _bundle_id(publication["bundle_id"]):
        raise ProcessProtocolError("publication bundle ID is invalid")
    if publication["run_report_sha256"] is not None and not _sha256(
        publication["run_report_sha256"]
    ):
        raise ProcessProtocolError("publication run report digest is invalid")
    for name in ("release_path", "prior_current_target", "intended_current_target"):
        item = publication[name]
        if item is not None and (not isinstance(item, str) or not item):
            raise ProcessProtocolError("publication target path is invalid")
    release = (
        f"releases/{publication['bundle_id']}"
        if publication["bundle_id"] is not None
        else None
    )
    for name in ("release_path", "prior_current_target", "intended_current_target"):
        item = publication[name]
        if item is not None and re.fullmatch(r"releases/bundle:sha256:[0-9a-f]{64}", item) is None:
            raise ProcessProtocolError("publication target path is invalid")
    state_exit = {
        "not-attempted": 10,
        "definite-pre-commit-failure": 11,
        "commit-indeterminate": 12,
        "durable-success": 0,
        "recovered-durable-success": 0,
        "recovered-no-commit": 13,
        "recovery-blocked": 14,
    }
    state = publication["state"]
    if state not in state_exit:
        raise ProcessProtocolError("publication state is invalid")
    durable = state in {"durable-success", "recovered-durable-success"}
    if durable and (
        release is None
        or publication["release_path"] != release
        or publication["run_report_sha256"] is None
    ):
        raise ProcessProtocolError("durable publication binding is incomplete")
    if state == "durable-success" and publication["intended_current_target"] != release:
        raise ProcessProtocolError("durable publication target is inconsistent")
    if state == "recovered-durable-success" and (
        publication["prior_current_target"] != release
        or publication["intended_current_target"] is not None
    ):
        raise ProcessProtocolError("recovered publication target is inconsistent")
    if state == "commit-indeterminate" and (
        release is None
        or publication["release_path"] != release
        or publication["intended_current_target"] != release
        or publication["run_report_sha256"] is None
    ):
        raise ProcessProtocolError("indeterminate publication binding is incomplete")
    if state == "definite-pre-commit-failure" and (
        (
            release is None
            and any(
                publication[name] is not None
                for name in ("release_path", "intended_current_target")
            )
        )
        or (
            release is not None
            and (
                publication["release_path"] != release
                or publication["intended_current_target"] != release
                or publication["run_report_sha256"] is None
            )
        )
    ):
        raise ProcessProtocolError("pre-commit publication binding is inconsistent")
    if state in {"not-attempted", "recovered-no-commit", "recovery-blocked"} and any(
        publication[name] is not None
        for name in (
            "bundle_id", "release_path", "run_report_sha256",
            "prior_current_target", "intended_current_target",
        )
    ):
        raise ProcessProtocolError("non-publication state carries publication bindings")
    return publication, durable, state_exit[state]


def validate_process_result(
    command: str,
    content: bytes,
    exit_code: int,
    *,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    """Validate canonical, closed result bytes and their process exit correspondence."""

    if type(exit_code) is not int:
        raise ProcessProtocolError("process exit code must be an integer")
    try:
        result = json.loads(
            content,
            object_pairs_hook=_object,
            parse_int=_parse_integer,
            parse_float=_reject_noninteger,
            parse_constant=_reject_noninteger,
        )
    except ProcessProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProcessProtocolError("result is not one JSON object") from error
    try:
        canonical = canonical_json(result)
    except ConfigurationError as error:
        raise ProcessProtocolError("result is outside the canonical JSON profile") from error
    if not isinstance(result, dict) or canonical != content:
        raise ProcessProtocolError("result is not canonical JSON")
    expected_schema = {
        "capabilities": CAPABILITIES_SCHEMA,
        "plan": PLAN_RESULT_SCHEMA,
        "build": BUILD_RESULT_SCHEMA,
        "verify": VERIFY_RESULT_SCHEMA,
    }.get(command)
    if expected_schema is None:
        raise ProcessProtocolError("unknown protocol command")
    if command == "capabilities":
        _keys(
            result,
            {"inspector_version", "protocol", "schema", "supported_schemas"},
            "capabilities result",
        )
        schemas = _keys(
            result["supported_schemas"], set(SUPPORTED_SCHEMAS), "supported schemas"
        )
        if schemas != {
            name: list(values) for name, values in SUPPORTED_SCHEMAS.items()
        }:
            raise ProcessProtocolError("capability schema sets are not exact")
        if not isinstance(result["inspector_version"], str) or not result[
            "inspector_version"
        ]:
            raise ProcessProtocolError("invalid Inspector version")
        success = True
    elif command == "plan":
        _keys(
            result,
            {
                "configuration_identity",
                "diagnostics",
                "plan",
                "protocol",
                "schema",
                "source",
                "status",
            },
            "plan result",
        )
        _diagnostics(result["diagnostics"])
        if result["status"] in {"succeeded", "blocked"}:
            _binding_shapes(result)
            blocking = _plan_payload(result)
            expected_status = "blocked" if blocking else "succeeded"
            if result["status"] != expected_status:
                raise ProcessProtocolError("plan status contradicts blocking diagnostics")
            success = not blocking
        elif result["status"] == "failed":
            if any(
                result[name] is not None
                for name in ("configuration_identity", "plan", "source")
            ):
                raise ProcessProtocolError("failed plan carries untrusted bindings")
            success = False
        else:
            raise ProcessProtocolError("invalid plan status")
    elif command == "build":
        _keys(
            result,
            {
                "configuration_identity",
                "protocol",
                "publication",
                "schema",
                "source",
                "status",
            },
            "build result",
        )
        publication, durable, expected_exit = _publication_payload(result["publication"])
        recovery_state = publication["state"] in {
            "recovered-durable-success",
            "recovered-no-commit",
            "recovery-blocked",
        }
        if recovery_state:
            if publication["run_id"] != "recovery":
                raise ProcessProtocolError("recovery result has an invalid run identity")
        else:
            if publication["run_id"] == "recovery":
                raise ProcessProtocolError(
                    "recovery is reserved for reconciliation publication states"
                )
            if expected_run_id is None:
                raise ProcessProtocolError(
                    "ordinary build validation requires caller run-ID correlation"
                )
            if not valid_caller_run_id(expected_run_id):
                raise ProcessProtocolError("expected caller run ID is invalid or reserved")
            if publication["run_id"] != expected_run_id:
                raise ProcessProtocolError(
                    "publication result does not match the requested run ID"
                )
        expected_status = "succeeded" if durable else "failed"
        if result["status"] != expected_status:
            raise ProcessProtocolError("build status contradicts publication state")
        success = durable
        if publication["state"] != "not-attempted":
            _binding_shapes(result)
        else:
            if result["configuration_identity"] is not None:
                _configuration_identity(result["configuration_identity"])
            if result["source"] is not None:
                if result["configuration_identity"] is None:
                    raise ProcessProtocolError("source binding lacks configuration identity")
                _source_binding(result["source"])
        if exit_code != expected_exit:
            raise ProcessProtocolError(
                "process exit does not match the publication result state"
            )
    else:
        _keys(
            result,
            {"bundle_id", "diagnostics", "protocol", "schema", "status", "valid"},
            "verify result",
        )
        _diagnostics(result["diagnostics"])
        if result["status"] == "succeeded":
            if result["valid"] is not True or not _bundle_id(result["bundle_id"]):
                raise ProcessProtocolError("successful verification is inconsistent")
            success = True
        elif result["status"] == "failed":
            if result["valid"] is not False or result["bundle_id"] is not None:
                raise ProcessProtocolError("failed verification is inconsistent")
            success = False
        else:
            raise ProcessProtocolError("invalid verification status")
    if result["schema"] != expected_schema or result["protocol"] != PROTOCOL:
        raise ProcessProtocolError("unsupported result protocol or schema")
    if command != "build":
        expected_exit = 0 if success else 1
        if exit_code != expected_exit:
            raise ProcessProtocolError(
                "process exit does not match the closed result state"
            )
    return result


def capabilities() -> dict[str, Any]:
    """Return the closed capability handshake for the one supported protocol."""

    return {
        "inspector_version": package_version("osqar-inspector"),
        "protocol": PROTOCOL,
        "schema": CAPABILITIES_SCHEMA,
        "supported_schemas": {
            name: list(schema_ids) for name, schema_ids in SUPPORTED_SCHEMAS.items()
        },
    }


def write_result(
    path: str,
    value: dict[str, Any],
    *,
    directory_fd: int | None = None,
) -> None:
    """Create a canonical result file without replacing any existing path."""

    content = canonical_json(value)
    if directory_fd is None:
        with Path(path).open("xb") as stream:
            stream.write(content)
        return
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(Path(path).name, flags, 0o666, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
    finally:
        os.close(descriptor)


def source_binding(snapshot_value: dict[str, Any]) -> dict[str, Any]:
    """Select the exact Git trust anchors carried by snapshot v1."""

    return dict(snapshot_value["source"])


def protocol_error(protocol: str, code: str, message: str) -> dict[str, Any]:
    """Return the single closed error shape used before command dispatch."""

    return {
        "diagnostics": [{"code": code, "message": message}],
        "protocol": protocol,
        "schema": ERROR_SCHEMA,
        "status": "rejected",
    }
