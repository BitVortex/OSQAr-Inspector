"""Application-level execution through deterministic closed candidate input."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .adapters import DeclarativeStagePlan
from .artifact_graph import ArtifactGraph, ProducerLog, build_artifact_graph
from .configuration import (
    ConfigurationError,
    ResolvedConfiguration,
    canonical_json,
    resolve_configuration,
)
from .navigation import NavigationOutput, render_navigation
from .plan import SCHEMA_ID as PLAN_SCHEMA_ID
from .plan import ExecutionPlan, create_plan
from .process_runner import (
    ExecutableIdentity,
    FailureKind,
    InternalFailure,
    OutputArtifact,
    ProcessResult,
    ProcessStatus,
    WorkspaceManager,
)
from .snapshot import (
    GitSnapshot,
    SnapshotError,
    materialize_snapshot,
    verify_materialized_snapshot,
)
from .stage_result import (
    StageDiagnostic,
    StagePolicy,
    StageResult,
    StageStatus,
    create_stage_outcome,
    create_stage_result,
)


@dataclass
class OrchestrationError(Exception):
    code: str
    message: str


def _report_code(code: str) -> str:
    return (
        code
        if re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", code)
        else "stage.invalid_diagnostic_code"
    )


def _report_message(message: str) -> str:
    cleaned = "".join(
        " " if unicodedata.category(character) == "Cc" else character
        for character in message
    ).strip()
    return cleaned or "stage diagnostic unavailable"


@dataclass(frozen=True)
class _CapturedFile:
    content: bytes
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _CapturedProcessEvidence:
    executable: _CapturedFile | None
    outputs: tuple[tuple[str, _CapturedFile], ...]
    stdout: _CapturedFile
    stderr: _CapturedFile


def _capture_regular_file(
    root: Path,
    parts: tuple[str, ...],
    *,
    require_one_link: bool,
) -> _CapturedFile | None:
    """Read a regular file through no-follow descriptors anchored at ``root``."""

    descriptors: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = os.open(root, directory_flags | nofollow)
        descriptors.append(directory)
        for component in parts[:-1]:
            directory = os.open(
                component,
                directory_flags | nofollow,
                dir_fd=directory,
            )
            descriptors.append(directory)
        file_descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | nofollow,
            dir_fd=directory,
        )
        descriptors.append(file_descriptor)
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode) or (
            require_one_link and before.st_nlink != 1
        ):
            return None
        chunks: list[bytes] = []
        while chunk := os.read(file_descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(file_descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            return None
        return _CapturedFile(b"".join(chunks), *identity_after)
    except (IndexError, OSError):
        return None
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _capture_process_evidence(
    process: Any,
    workspace: Any,
    accepted_exit_codes: frozenset[int],
) -> _CapturedProcessEvidence | None:
    """Validate and capture owned process evidence before adapter callbacks."""

    try:
        if (
            not isinstance(process, ProcessResult)
            or not isinstance(process.status, ProcessStatus)
            or not isinstance(process.executable, ExecutableIdentity)
            or not isinstance(process.executable.path, Path)
            or (
                process.executable.sha256 is not None
                and re.fullmatch(r"[0-9a-f]{64}", process.executable.sha256) is None
            )
            or (
                process.executable.version is not None
                and (
                    not isinstance(process.executable.version, str)
                    or not process.executable.version
                )
            )
            or not isinstance(process.redacted_argv, tuple)
            or not process.redacted_argv
            or not all(isinstance(item, str) for item in process.redacted_argv)
            or not isinstance(process.started_at, str)
            or not process.started_at
            or not isinstance(process.ended_at, str)
            or not process.ended_at
            or isinstance(process.duration_seconds, bool)
            or not isinstance(process.duration_seconds, (int, float))
            or process.duration_seconds < 0
            or not math.isfinite(process.duration_seconds)
            or (
                process.exit_code is not None
                and (
                    isinstance(process.exit_code, bool)
                    or not isinstance(process.exit_code, int)
                )
            )
            or (
                process.failure is not None
                and not isinstance(process.failure, InternalFailure)
            )
            or not isinstance(process.stdout_path, Path)
            or not isinstance(process.stderr_path, Path)
            or not isinstance(process.outputs, tuple)
        ):
            return None
        started = datetime.fromisoformat(process.started_at)
        ended = datetime.fromisoformat(process.ended_at)
        wall_duration = (ended - started).total_seconds()
        if (
            started.tzinfo is None
            or started.utcoffset() is None
            or ended.tzinfo is None
            or ended.utcoffset() is None
            or wall_duration < 0
            or abs(wall_duration - process.duration_seconds)
            > max(1.0, 0.25 * max(wall_duration, process.duration_seconds))
        ):
            return None
        if process.status is ProcessStatus.SUCCEEDED and (
            process.failure is not None
            or process.exit_code not in accepted_exit_codes
        ):
            return None
        if process.status is ProcessStatus.FAILED and process.failure is None:
            return None
        if process.failure is not None and (
            not isinstance(process.failure.kind, FailureKind)
            or not isinstance(process.failure.message, str)
            or not process.failure.message
            or (
                process.failure.kind is FailureKind.SPAWN
                and process.exit_code is not None
            )
            or (
                process.failure.kind is not FailureKind.SPAWN
                and process.exit_code is None
            )
            or (
                process.failure.kind is FailureKind.NONZERO_EXIT
                and process.exit_code in accepted_exit_codes
            )
        ):
            return None

        executable_must_exist = (
            process.status is ProcessStatus.SUCCEEDED
            or process.failure is None
            or process.failure.kind is not FailureKind.SPAWN
        )
        captured_executable = None
        if executable_must_exist:
            executable = process.executable.path
            if (
                not executable.is_absolute()
                or process.executable.sha256 is None
            ):
                return None
            captured_executable = _capture_regular_file(
                executable.parent,
                (executable.name,),
                require_one_link=False,
            )
            if (
                captured_executable is None
                or hashlib.sha256(captured_executable.content).hexdigest()
                != process.executable.sha256
            ):
                return None

        expected_logs = (
            (process.stdout_path, "stdout.log"),
            (process.stderr_path, "stderr.log"),
        )
        captured_logs: list[_CapturedFile] = []
        for path, name in expected_logs:
            if path != workspace.path / name:
                return None
            captured_log = _capture_regular_file(
                workspace.path,
                (name,),
                require_one_link=True,
            )
            if captured_log is None:
                return None
            captured_logs.append(captured_log)

        identities: list[tuple[str, str]] = []
        captured_outputs: list[tuple[str, _CapturedFile]] = []
        paths: list[str] = []
        for output in process.outputs:
            if not isinstance(output, OutputArtifact):
                return None
            path = PurePosixPath(output.path)
            identity = (output.path, output.kind)
            if (
                not output.path
                or path.is_absolute()
                or path.as_posix() != output.path
                or any(part in {"", ".", ".."} for part in path.parts)
                or not isinstance(output.kind, str)
                or not output.kind
                or not isinstance(output.size, str)
                or not output.size.isdecimal()
                or (len(output.size) > 1 and output.size.startswith("0"))
                or re.fullmatch(r"[0-9a-f]{64}", output.sha256) is None
            ):
                return None
            captured_output = _capture_regular_file(
                workspace.path,
                path.parts,
                require_one_link=True,
            )
            if (
                captured_output is None
                or str(len(captured_output.content)) != output.size
                or hashlib.sha256(captured_output.content).hexdigest()
                != output.sha256
            ):
                return None
            identities.append(identity)
            paths.append(output.path)
            captured_outputs.append((output.path, captured_output))
        if len(identities) != len(set(identities)) or len(paths) != len(set(paths)):
            return None
        return _CapturedProcessEvidence(
            captured_executable,
            tuple(captured_outputs),
            captured_logs[0],
            captured_logs[1],
        )
    except (AttributeError, IndexError, OSError, TypeError, ValueError):
        return None


def _validate_configuration_bindings(configuration: ResolvedConfiguration) -> None:
    try:
        reconstructed = resolve_configuration(
            configuration.controlled_bytes,
            configuration.controlled_path,
            configuration.identity["overrides"],
        )
    except (ConfigurationError, KeyError, TypeError, ValueError, RecursionError) as error:
        raise OrchestrationError(
            "orchestration.configuration_mismatch",
            "resolved configuration value and identity bindings are inconsistent",
        ) from error
    if reconstructed != configuration:
        raise OrchestrationError(
            "orchestration.configuration_mismatch",
            "resolved configuration value and identity bindings are inconsistent",
        )


def _validate_plan_bindings(
    configuration: ResolvedConfiguration,
    snapshot: GitSnapshot,
    plan: ExecutionPlan,
    adapters: Mapping[str, Any],
) -> None:
    try:
        value = plan.value
        identity = {key: item for key, item in value.items() if key != "plan_digest"}
        expected_digest = hashlib.sha256(
            canonical_json({"kind": "plan", "identity": identity})
        ).hexdigest()
        stages = value["stages"]
        stage_ids = [stage["id"] for stage in stages]
        snapshot_identity = {
            key: item for key, item in snapshot.manifest.items() if key != "metadata"
        }
        expected_edges = sorted(
            (
                {"from": dependency, "to": stage["id"]}
                for stage in stages
                for dependency in stage["dependencies"]
            ),
            key=lambda edge: (edge["from"].encode(), edge["to"].encode()),
        )
        coherent = (
            value["schema"] == PLAN_SCHEMA_ID
            and value["configuration"] == configuration.identity
            and value["snapshot"] == snapshot_identity
            and value["edges"] == expected_edges
            and value["plan_digest"] == expected_digest
            and plan.plan_bytes == canonical_json(value)
            and stage_ids == sorted(stage_ids, key=str.encode)
            and len(stage_ids) == len(set(stage_ids))
            and all(stage_id in adapters for stage_id in stage_ids)
        )
    except (KeyError, TypeError, ValueError, RecursionError):
        coherent = False
    if not coherent:
        raise OrchestrationError(
            "orchestration.plan_mismatch",
            "execution plan bindings or canonical identity are inconsistent",
        )


@dataclass(frozen=True)
class CandidateInput:
    """Closed application output accepted by the bundle generator."""

    stage_results: tuple[StageResult, ...]
    graph: ArtifactGraph
    navigation: NavigationOutput
    run_report: bytes
    payloads: tuple[tuple[str, bytes], ...]
    candidate_ready: bool
    publication_state: str = "not-attempted"
    publication_result: None = None


def create_candidate(
    configuration: ResolvedConfiguration,
    snapshot: GitSnapshot,
    plan: ExecutionPlan,
    adapters: Mapping[str, Any],
    workspaces: WorkspaceManager,
) -> CandidateInput:
    """Execute a plan and return candidate bytes without claiming publication."""

    _validate_configuration_bindings(configuration)
    _validate_plan_bindings(configuration, snapshot, plan, adapters)
    try:
        expected_plan = create_plan(configuration, snapshot, adapters)
    except Exception as error:
        raise OrchestrationError(
            "orchestration.plan_validation_failed",
            _report_message(str(error)) or "adapter declaration validation failed",
        ) from error
    if plan != expected_plan:
        raise OrchestrationError(
            "orchestration.plan_mismatch",
            "execution plan does not match exact adapter declarations",
        )

    results: list[StageResult] = []
    normalized: dict[str, Any] = {}
    collected_outputs: dict[str, Any] = {}
    evidence_payloads: list[tuple[str, bytes]] = []
    producer_logs: list[ProducerLog] = []
    with workspaces.run() as run:
        snapshot_root = run.path / "snapshot"
        materialize_snapshot(snapshot, snapshot_root)
        try:
            verify_materialized_snapshot(snapshot, snapshot_root)
        except SnapshotError as error:
            raise OrchestrationError(
                "orchestration.snapshot_mutated", error.message
            ) from error
        stages = list(plan.value["stages"])
        selected_paths = tuple(record["path"] for record in snapshot.files)
        ordered_stages: list[dict[str, Any]] = []
        pending = list(stages)
        completed = {"snapshot"}
        while pending:
            ready = [
                stage
                for stage in pending
                if set(stage["dependencies"]) <= completed
            ]
            if not ready:
                raise OrchestrationError(
                    "orchestration.invalid_dependencies",
                    "plan dependencies are cyclic or name an absent stage",
                )
            for stage in ready:
                ordered_stages.append(stage)
                completed.add(stage["id"])
                pending.remove(stage)
        for stage in ordered_stages:
            stage_id = stage["id"]
            by_stage = {result.stage: result for result in results}
            static_diagnostics = [
                diagnostic
                for diagnostic in plan.value["diagnostics"]
                if diagnostic["stage"] == stage_id
            ]
            if static_diagnostics:
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=(
                            StageStatus.BLOCKED
                            if stage["policy"] == "required"
                            else StageStatus.SKIPPED
                        ),
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=tuple(
                            StageDiagnostic(item["code"], item["message"])
                            for item in static_diagnostics
                        ),
                    )
                )
                continue
            failed_dependencies = [
                dependency
                for dependency in stage["dependencies"]
                if dependency != "snapshot"
                and (
                    dependency not in by_stage
                    or by_stage[dependency].status is not StageStatus.SUCCEEDED
                )
            ]
            if failed_dependencies:
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=StageStatus.BLOCKED,
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=(
                            StageDiagnostic(
                                "stage.dependency_failed",
                                "dependency did not succeed: "
                                + ", ".join(failed_dependencies),
                            ),
                        ),
                    )
                )
                continue
            declaration = DeclarativeStagePlan(
                stage=stage_id,
                selector=stage["adapter"]["selector"],
                dependencies=tuple(stage["dependencies"]),
                required_inputs=tuple(stage["required_inputs"]),
                invocation=tuple(stage["invocation"]["argv"]),
                expected_outputs=tuple(stage["expected_outputs"]),
                workspace=stage["workspace"],
                adapter_options=tuple(
                    sorted(
                        stage["adapter_options"].items(),
                        key=lambda item: item[0].encode(),
                    )
                ),
            )
            adapter = adapters[stage_id]
            bind_runtime = getattr(adapter, "bind_runtime", None)
            try:
                if bind_runtime is not None:
                    adapter = bind_runtime(
                        workspaces=workspaces,
                        snapshot_root=snapshot_root,
                        selected_paths=selected_paths,
                        configuration=configuration,
                        snapshot=snapshot,
                    )
                bound_diagnostics, bound_capability = adapter.validate_declaration(
                    configuration.value
                )
                bound_declaration = adapter.plan_declaration(
                    configuration.value, snapshot
                )
                bound_capability_value = (
                    None
                    if bound_capability.executable is None
                    else {
                        "executable": bound_capability.executable,
                        "status": "unresolved",
                        "version_constraint": bound_capability.version_constraint,
                    }
                )
                if (
                    bound_diagnostics
                    or bound_declaration != declaration
                    or bound_capability_value != stage["capability"]
                ):
                    raise OrchestrationError(
                        "stage.binding_mismatch",
                        "runtime-bound adapter declaration does not match the sealed plan",
                    )
            except Exception as error:  # noqa: BLE001 - isolate adapter boundary
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=(
                            StageStatus.BLOCKED
                            if stage["policy"] == "required"
                            else StageStatus.SKIPPED
                        ),
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=(
                            StageDiagnostic(
                                str(getattr(error, "code", "stage.binding_failed")),
                                str(getattr(error, "message", str(error)))
                                or "runtime adapter binding failed",
                            ),
                        ),
                    )
                )
                continue
            probe_workspace = run.probe(stage_id)
            capability = None
            try:
                capability = adapter.probe(configuration.value, probe_workspace)
                diagnostics = adapter.validate_capability(
                    configuration.value, capability
                )
            except Exception as error:  # noqa: BLE001 - isolate adapter boundary
                diagnostics = (
                    StageDiagnostic(
                        getattr(error, "code", "capability.unavailable"),
                        getattr(error, "message", str(error))
                        or "capability probe failed",
                    ),
                )
            if diagnostics:
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=(
                            StageStatus.BLOCKED
                            if stage["policy"] == "required"
                            else StageStatus.SKIPPED
                        ),
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=tuple(
                            item
                            if isinstance(item, StageDiagnostic)
                            else StageDiagnostic(item.code, item.message)
                            for item in diagnostics
                        ),
                    )
                )
                continue
            assert capability is not None
            stage_workspace = run.stage(stage_id)
            try:
                command = adapter.plan_command(
                    declaration, capability, stage_workspace
                )
            except Exception as error:  # noqa: BLE001 - isolate adapter boundary
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=(
                            StageStatus.BLOCKED
                            if stage["policy"] == "required"
                            else StageStatus.SKIPPED
                        ),
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=(
                            StageDiagnostic(
                                str(getattr(error, "code", "stage.command_planning_failed")),
                                str(getattr(error, "message", str(error)))
                                or "stage command planning failed",
                            ),
                        ),
                    )
                )
                continue

            try:
                process = adapter.execute(command)
            except Exception as error:  # noqa: BLE001 - isolate adapter boundary
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=(
                            StageStatus.BLOCKED
                            if stage["policy"] == "required"
                            else StageStatus.DEGRADED
                        ),
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=(
                            StageDiagnostic(
                                str(getattr(error, "code", "stage.execution_failed")),
                                str(getattr(error, "message", str(error)))
                                or "adapter execution returned no process evidence",
                            ),
                        ),
                    )
                )
                continue
            captured_evidence = _capture_process_evidence(
                process,
                stage_workspace,
                command.accepted_exit_codes,
            )
            if captured_evidence is None:
                results.append(
                    create_stage_outcome(
                        stage=stage_id,
                        adapter=stage["adapter"]["selector"],
                        status=(
                            StageStatus.BLOCKED
                            if stage["policy"] == "required"
                            else StageStatus.DEGRADED
                        ),
                        policy=(
                            StagePolicy.REQUIRED
                            if stage["policy"] == "required"
                            else StagePolicy.OPTIONAL
                        ),
                        snapshot_id=snapshot.snapshot_id,
                        diagnostics=(
                            StageDiagnostic(
                                "stage.process_result_invalid",
                                "adapter returned malformed or detached process evidence",
                            ),
                        ),
                    )
                )
                continue
            declared_outputs = {
                (output.path, output.kind) for output in command.outputs
            }
            observed_outputs = {
                (output.path, output.kind) for output in process.outputs
            }
            if declared_outputs != observed_outputs:
                missing = sorted(declared_outputs - observed_outputs)
                unexpected = sorted(observed_outputs - declared_outputs)
                details = []
                if not declared_outputs:
                    details.append("adapter declared no exact runtime outputs")
                if missing:
                    details.append(
                        "missing " + ", ".join(f"{path} ({kind})" for path, kind in missing)
                    )
                if unexpected:
                    details.append(
                        "undeclared "
                        + ", ".join(f"{path} ({kind})" for path, kind in unexpected)
                    )
                process = replace(
                    process,
                    status=ProcessStatus.FAILED,
                    failure=InternalFailure(
                        FailureKind.OUTPUT_MISSING,
                        "current-run outputs do not match the exact command declaration: "
                        + "; ".join(details),
                    ),
                    outputs=(),
                )
                captured_evidence = replace(captured_evidence, outputs=())
            collected_output: Any | None = None
            normalized_output: Any | None = None
            if process.status is ProcessStatus.SUCCEEDED:
                try:
                    collected_output = adapter.collect(process, stage_workspace)
                    normalized_output = adapter.normalize(collected_output, snapshot)
                except Exception as error:  # noqa: BLE001 - isolate adapter boundary
                    process = replace(
                        process,
                        status=ProcessStatus.FAILED,
                        failure=InternalFailure(
                            FailureKind.OUTPUT_MALFORMED,
                            getattr(error, "message", str(error))
                            or "stage output collection or normalization failed",
                        ),
                    )
            post_callback_evidence = _capture_process_evidence(
                process,
                stage_workspace,
                command.accepted_exit_codes,
            )
            if post_callback_evidence != captured_evidence:
                process = replace(
                    process,
                    status=ProcessStatus.FAILED,
                    failure=InternalFailure(
                        FailureKind.OUTPUT_MALFORMED,
                        "process evidence changed during adapter semantic processing",
                    ),
                )
                collected_output = None
                normalized_output = None
            captured_outputs = dict(captured_evidence.outputs)
            closed_outputs = []
            for output in process.outputs:
                relative = f"artifacts/stage-outputs/{stage_id}/{output.path}"
                content = captured_outputs[output.path].content
                evidence_payloads.append((relative, content))
                closed_outputs.append(replace(output, path=relative))
            process = replace(process, outputs=tuple(closed_outputs))
            closed_log_paths: dict[str, Any] = {}
            for stream, content in (
                ("stdout", captured_evidence.stdout.content),
                ("stderr", captured_evidence.stderr.content),
            ):
                relative = f"artifacts/logs/{stage_id}/{stream}.log"
                graph_relative = f"{stage_id}/{stream}.log"
                evidence_payloads.append((relative, content))
                producer_logs.append(
                    ProducerLog(
                        stage_id,
                        graph_relative,
                        hashlib.sha256(content).hexdigest(),
                        len(content),
                    )
                )
                closed_log_paths[stream] = relative
            result = create_stage_result(
                stage=stage_id,
                adapter=stage["adapter"]["selector"],
                policy=(
                    StagePolicy.REQUIRED
                    if stage["policy"] == "required"
                    else StagePolicy.OPTIONAL
                ),
                snapshot_id=snapshot.snapshot_id,
                process=process,
                status_override=(
                    StageStatus.DEGRADED
                    if process.status is ProcessStatus.FAILED
                    and stage["policy"] == "optional"
                    else None
                ),
            )
            result = replace(
                result,
                stdout_path=Path(closed_log_paths["stdout"]),
                stderr_path=Path(closed_log_paths["stderr"]),
            )
            results.append(result)
            if result.status is StageStatus.SUCCEEDED:
                collected_outputs[stage_id] = collected_output
                normalized[stage_id] = normalized_output

        try:
            verify_materialized_snapshot(snapshot, snapshot_root)
        except SnapshotError as error:
            raise OrchestrationError(
                "orchestration.snapshot_mutated", error.message
            ) from error
        graph_log_stages = {
            result.stage
            for result in results
            if result.executable is not None
        }
        graph = build_artifact_graph(
            snapshot,
            api_output=normalized.get("doxygen"),
            coverage_output=normalized.get("coverage"),
            stage_results=results,
            producer_logs=tuple(
                log for log in producer_logs if log.stage in graph_log_stages
            ),
        )
        candidate_root = run.path / "candidate"
        artifact_payloads: list[tuple[str, bytes]] = []
        doxygen_output = collected_outputs.get("doxygen")
        for item in getattr(doxygen_output, "files", ()):
            artifact_payloads.append(("artifacts/api/" + item.path, item.content))
        coverage_output = normalized.get("coverage")
        for item in getattr(coverage_output, "artifacts", ()):
            artifact_payloads.append(("artifacts/coverage/" + item.path, item.content))
        for item in getattr(coverage_output, "sidecars", ()):
            if (
                item.kind not in {"mapping", "attestation"}
                or item.size != len(item.content)
                or item.sha256 != hashlib.sha256(item.content).hexdigest()
            ):
                raise OrchestrationError(
                    "orchestration.candidate_unclosed",
                    "coverage sidecar metadata does not match its exact evidence bytes",
                )
            artifact_payloads.append(
                (
                    f"artifacts/coverage-sidecars/{item.kind}/{item.path}",
                    item.content,
                )
            )
        for path, content in artifact_payloads + evidence_payloads:
            destination = candidate_root.joinpath(*path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        navigation_root = candidate_root / "navigation"
        navigation_root.mkdir(parents=True)
        navigation = render_navigation(graph, navigation_root)
        candidate_ready = all(
            result.status is StageStatus.SUCCEEDED
            for result in results
            if result.policy is StagePolicy.REQUIRED
        )
        counts: dict[str, int] = {}
        for node in navigation.graph.nodes:
            counts[node.kind.value] = counts.get(node.kind.value, 0) + 1
        report = canonical_json(
            {
                "artifact_counts": [
                    {"count": str(counts[kind]), "kind": kind}
                    for kind in sorted(counts, key=str.encode)
                ],
                "claim_boundary": {
                    "does_not_establish": [
                        "certification",
                        "evidence-adequacy",
                        "evidence-approval",
                        "fitness-for-use",
                        "functional-safety",
                        "security",
                        "software-qualification",
                        "standards-compliance",
                        "tool-qualification",
                    ],
                    "scope": "mechanical-structural-and-integrity-inspection",
                },
                "configuration_identity": configuration.identity,
                "diagnostics": [
                    {
                        "code": _report_code(diagnostic.code),
                        "message": _report_message(diagnostic.message),
                        "path": None,
                        "severity": (
                            "warning"
                            if result.policy is StagePolicy.OPTIONAL
                            else "error"
                        ),
                    }
                    for result in results
                    for diagnostic in result.diagnostics
                ],
                "inspector": {"version": "0.1.0"},
                "optional_stages": {
                    "degraded": sorted([
                        result.stage
                        for result in results
                        if result.status is StageStatus.DEGRADED
                    ], key=str.encode),
                    "skipped": sorted([
                        result.stage
                        for result in results
                        if result.status is StageStatus.SKIPPED
                    ], key=str.encode),
                },
                "plan_sha256": plan.value["plan_digest"],
                "required_stage_decision": (
                    "satisfied" if candidate_ready else "blocked"
                ),
                "schema": "osqar.inspector.run.v1",
                "snapshot_id": snapshot.snapshot_id,
                "stage_result_digests": [result.digest for result in results],
            }
        )
        evidence_payloads.extend(
            (f"reports/stages/{result.stage}.json", result.identity_bytes)
            for result in results
        )
        evidence_payloads.append(
            ("reports/artifact-graph.json", navigation.graph.identity_bytes)
        )
        candidate_payloads = (
            artifact_payloads
            + evidence_payloads
            + [(f"navigation/{item.path}", item.content) for item in navigation.files]
            + [("reports/run.json", report)]
        )
        candidate_paths = [path for path, _ in candidate_payloads]
        if len(candidate_paths) != len(set(candidate_paths)):
            raise OrchestrationError(
                "orchestration.candidate_unclosed",
                "candidate payload paths are not unique",
            )
        payloads = tuple(sorted(candidate_payloads, key=lambda item: item[0].encode()))
        try:
            verify_materialized_snapshot(snapshot, snapshot_root)
        except SnapshotError as error:
            raise OrchestrationError(
                "orchestration.snapshot_mutated", error.message
            ) from error
        candidate = CandidateInput(
            tuple(results),
            navigation.graph,
            navigation,
            report,
            payloads,
            candidate_ready,
        )
    if run.cleanup_diagnostics:
        raise OrchestrationError(
            "orchestration.workspace_cleanup_failed",
            "; ".join(item.message for item in run.cleanup_diagnostics),
        )
    return candidate
