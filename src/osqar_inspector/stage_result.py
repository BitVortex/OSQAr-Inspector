"""Immutable canonical stage-result domain model."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .configuration import canonical_json
from .process_runner import (
    ExecutableIdentity,
    OutputArtifact,
    ProcessResult,
    ProcessStatus,
)

SCHEMA_ID = "osqar.inspector.stage-result.v1"


class StageStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    DEGRADED = "degraded"


class StagePolicy(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"


@dataclass(frozen=True)
class StageDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class StageResult:
    schema: str
    stage: str
    adapter: str
    status: StageStatus
    policy: StagePolicy
    snapshot_id: str
    started_at: str
    ended_at: str
    duration_seconds: float
    redacted_argv: tuple[str, ...]
    exit_code: int | None
    internal_failure: str | None
    stdout_path: Path | None
    stderr_path: Path | None
    executable: ExecutableIdentity | None
    outputs: tuple[OutputArtifact, ...]
    identity_bytes: bytes
    digest: str
    diagnostics: tuple[StageDiagnostic, ...] = ()


def _stable_argument(argument: str, workspace_path: Path) -> str:
    stable = argument.replace(str(workspace_path), "<workspace>")
    path = Path(stable)
    if path.is_absolute():
        return f"<absolute>/{path.name}"
    return stable


def create_stage_result(
    *,
    stage: str,
    adapter: str,
    policy: StagePolicy,
    snapshot_id: str,
    process: ProcessResult,
    status_override: StageStatus | None = None,
) -> StageResult:
    """Project process evidence into a deterministic mechanical stage identity."""
    status = status_override or (
        StageStatus.SUCCEEDED
        if process.status is ProcessStatus.SUCCEEDED
        else StageStatus.FAILED
    )
    if status_override not in {None, StageStatus.DEGRADED}:
        raise ValueError("process-backed status override must be degraded")
    identity = {
        "adapter": adapter,
        "executable": {
            "name": process.executable.path.name,
            "sha256": process.executable.sha256,
            "version": process.executable.version,
        },
        "invocation": {
            "argv": [
                _stable_argument(item, process.stdout_path.parent)
                for item in process.redacted_argv
            ],
            "exit_code": process.exit_code,
            "internal_failure": (
                process.failure.kind.value if process.failure is not None else None
            ),
        },
        "outputs": [
            {
                "kind": output.kind,
                "path": output.path,
                "sha256": output.sha256,
                "size": output.size,
            }
            for output in process.outputs
        ],
        "policy": policy.value,
        "schema": SCHEMA_ID,
        "snapshot_id": snapshot_id,
        "stage": stage,
        "status": status.value,
    }
    identity_bytes = canonical_json(identity)
    digest = hashlib.sha256(identity_bytes).hexdigest()
    diagnostics = (
        (
            StageDiagnostic(
                f"process.{process.failure.kind.value}", process.failure.message
            ),
        )
        if process.failure is not None
        else ()
    )
    return StageResult(
        schema=SCHEMA_ID,
        stage=stage,
        adapter=adapter,
        status=status,
        policy=policy,
        snapshot_id=snapshot_id,
        started_at=process.started_at,
        ended_at=process.ended_at,
        duration_seconds=process.duration_seconds,
        redacted_argv=process.redacted_argv,
        exit_code=process.exit_code,
        internal_failure=(
            process.failure.kind.value if process.failure is not None else None
        ),
        stdout_path=process.stdout_path,
        stderr_path=process.stderr_path,
        executable=process.executable,
        outputs=process.outputs,
        identity_bytes=identity_bytes,
        digest=digest,
        diagnostics=diagnostics,
    )


def create_stage_outcome(
    *,
    stage: str,
    adapter: str,
    status: StageStatus,
    policy: StagePolicy,
    snapshot_id: str,
    diagnostics: tuple[StageDiagnostic, ...] = (),
) -> StageResult:
    """Create a canonical result for a stage for which no process was run."""
    if status in {StageStatus.SUCCEEDED, StageStatus.FAILED}:
        raise ValueError("executed stage statuses require process evidence")
    identity_bytes = canonical_json(
        {
            "adapter": adapter,
            "diagnostics": [
                {"code": diagnostic.code, "message": diagnostic.message}
                for diagnostic in diagnostics
            ],
            "policy": policy.value,
            "schema": SCHEMA_ID,
            "snapshot_id": snapshot_id,
            "stage": stage,
            "status": status.value,
        }
    )
    return StageResult(
        schema=SCHEMA_ID,
        stage=stage,
        adapter=adapter,
        status=status,
        policy=policy,
        snapshot_id=snapshot_id,
        started_at="",
        ended_at="",
        duration_seconds=0.0,
        redacted_argv=(),
        exit_code=None,
        internal_failure=None,
        stdout_path=None,
        stderr_path=None,
        executable=None,
        outputs=(),
        identity_bytes=identity_bytes,
        digest=hashlib.sha256(identity_bytes).hexdigest(),
        diagnostics=diagnostics,
    )
