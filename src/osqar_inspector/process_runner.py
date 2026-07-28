"""Owned workspaces and the shared, shell-free external process runner."""

from __future__ import annotations

import hashlib
import os
import signal
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class ProcessStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class FailureKind(str, Enum):
    SPAWN = "spawn"
    TIMEOUT = "timeout"
    NONZERO_EXIT = "nonzero_exit"
    OUTPUT_MISSING = "output_missing"
    OUTPUT_STALE = "output_stale"
    OUTPUT_MALFORMED = "output_malformed"
    INTERNAL = "internal"


@dataclass(frozen=True)
class InternalFailure:
    kind: FailureKind
    message: str


@dataclass(frozen=True)
class ExecutableIdentity:
    path: Path
    sha256: str | None
    version: str | None


@dataclass(frozen=True)
class OutputDeclaration:
    path: str
    kind: str = "artifact"
    validator: Callable[[Path], bool] | None = None

    def __post_init__(self) -> None:
        candidate = Path(self.path)
        if self.path in {"stdout.log", "stderr.log"}:
            raise ValueError("runner-owned log paths cannot be producer outputs")
        if (
            not self.path
            or candidate.is_absolute()
            or "\\" in self.path
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ValueError("output paths must be normalized workspace-relative paths")


@dataclass(frozen=True)
class OutputArtifact:
    path: str
    kind: str
    size: str
    sha256: str


@dataclass(frozen=True)
class OwnedWorkspace:
    path: Path
    kind: str
    name: str


@dataclass(frozen=True)
class CleanupDiagnostic:
    code: str
    message: str


@dataclass
class RunWorkspace:
    path: Path
    _cleanup_diagnostics: list[CleanupDiagnostic]
    _owned_paths: set[Path]

    @property
    def cleanup_diagnostics(self) -> tuple[CleanupDiagnostic, ...]:
        return tuple(self._cleanup_diagnostics)

    def _child(self, kind: str, name: str) -> OwnedWorkspace:
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise ValueError("workspace names must be single safe path components")
        path = self.path / kind / name
        path.mkdir(parents=True, exist_ok=False)
        self._owned_paths.add(path.resolve(strict=True))
        return OwnedWorkspace(path=path, kind=kind, name=name)

    def probe(self, name: str) -> OwnedWorkspace:
        return self._child("probes", name)

    def stage(self, name: str) -> OwnedWorkspace:
        return self._child("stages", name)


class WorkspaceManager:
    """Creates every execution directory outside the live source project."""

    def __init__(self, source_project: Path, *, base_directory: Path | None = None):
        source = source_project.resolve(strict=True)
        if not source.is_dir():
            raise ValueError("source project must be a directory")
        base = (
            base_directory.resolve()
            if base_directory is not None
            else Path(tempfile.gettempdir()).resolve()
        )
        if base == source or base.is_relative_to(source):
            raise ValueError("workspace base must be outside the source project")
        base.mkdir(parents=True, exist_ok=True)
        self.source_project = source
        self.base_directory = base
        self._owned_paths: set[Path] = set()

    @contextmanager
    def run(self) -> Iterator[RunWorkspace]:
        path = Path(tempfile.mkdtemp(prefix="osqar-inspector-run-", dir=self.base_directory))
        if path == self.source_project or path.is_relative_to(self.source_project):
            shutil.rmtree(path, ignore_errors=True)
            raise RuntimeError("owned run workspace was created inside the source project")
        diagnostics: list[CleanupDiagnostic] = []
        workspace = RunWorkspace(path, diagnostics, self._owned_paths)
        try:
            yield workspace
        finally:
            try:
                shutil.rmtree(path)
            except OSError as error:
                diagnostics.append(
                    CleanupDiagnostic("workspace.cleanup_failed", str(error))
                )
            finally:
                self._owned_paths.difference_update(
                    owned
                    for owned in tuple(self._owned_paths)
                    if owned == path or owned.is_relative_to(path)
                )


@dataclass(frozen=True)
class ProcessResult:
    status: ProcessStatus
    executable: ExecutableIdentity
    redacted_argv: tuple[str, ...]
    started_at: str
    ended_at: str
    duration_seconds: float
    exit_code: int | None
    failure: InternalFailure | None
    stdout_path: Path
    stderr_path: Path
    outputs: tuple[OutputArtifact, ...]


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _redact(argv: Sequence[str], secrets: Iterable[str]) -> tuple[str, ...]:
    protected = tuple(value for value in secrets if value)
    return tuple(
        _redact_argument(argument, protected)
        for argument in argv
    )


def _redact_argument(argument: str, secrets: tuple[str, ...]) -> str:
    result = argument
    for secret in secrets:
        result = result.replace(secret, "<redacted>")
    return result


def _redact_log(path: Path, secrets: tuple[str, ...]) -> None:
    content = path.read_bytes()
    for secret in secrets:
        content = content.replace(secret.encode("utf-8"), b"<redacted>")
    path.write_bytes(content)


def _terminate_process_group(process: subprocess.Popen[bytes], grace: float) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    if process.poll() is None:
        process.wait()


class ProcessRunner:
    def __init__(self, workspaces: WorkspaceManager):
        self.workspaces = workspaces

    def _identity(
        self,
        executable: str,
        workspace: OwnedWorkspace,
        version_arguments: Sequence[str],
        timeout_seconds: float,
    ) -> ExecutableIdentity:
        candidate = Path(executable)
        if candidate.is_absolute():
            path = candidate.resolve()
        elif os.sep in executable:
            path = (workspace.path / candidate).resolve()
        else:
            located = shutil.which(executable)
            path = Path(located or executable).resolve()
        located = (
            os.fspath(path) if path.is_file() and os.access(path, os.X_OK) else None
        )
        digest = _digest(path) if path.is_file() else None
        version = None
        if located is not None and version_arguments:
            probe_root = workspace.path.parent.parent / "probes"
            probe_root.mkdir(parents=True, exist_ok=True)
            probe_path = Path(
                tempfile.mkdtemp(prefix="executable-version-", dir=probe_root)
            )
            self.workspaces._owned_paths.add(probe_path.resolve(strict=True))
            try:
                probe = subprocess.Popen(
                    [located, *version_arguments],
                    cwd=probe_path,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    start_new_session=True,
                )
                try:
                    stdout, _ = probe.communicate(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    _terminate_process_group(probe, min(1.0, timeout_seconds))
                    stdout, _ = probe.communicate()
                version = stdout.decode("utf-8", errors="replace").strip() or None
            except OSError:
                version = None
        return ExecutableIdentity(path, digest, version)

    def run(
        self,
        argv: Sequence[str],
        *,
        workspace: OwnedWorkspace,
        timeout_seconds: float = 300.0,
        version_arguments: Sequence[str] = (),
        secrets: Iterable[str] = (),
        outputs: Sequence[OutputDeclaration] = (),
        accepted_exit_codes: frozenset[int] = frozenset({0}),
    ) -> ProcessResult:
        if not argv or any(not isinstance(argument, str) for argument in argv):
            raise ValueError("argv must be a non-empty sequence of strings")
        if timeout_seconds <= 0:
            raise ValueError("timeout must be positive")
        if not accepted_exit_codes:
            raise ValueError("at least one accepted exit code is required")
        try:
            owned_path = workspace.path.resolve(strict=True)
        except OSError:
            owned_path = workspace.path
        if not workspace.path.is_dir() or owned_path not in self.workspaces._owned_paths:
            raise ValueError("runner requires a live workspace owned by its manager")

        stdout_path = workspace.path / "stdout.log"
        stderr_path = workspace.path / "stderr.log"
        declared = tuple(outputs)
        protected = tuple(value for value in secrets if value)
        preexisting = {
            declaration.path
            for declaration in declared
            if (workspace.path / declaration.path).exists()
        }
        executable = self._identity(
            argv[0], workspace, version_arguments, timeout_seconds
        )
        started_wall = datetime.now(UTC)
        started = time.monotonic()
        exit_code: int | None = None
        failure: InternalFailure | None = None
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    list(argv),
                    cwd=workspace.path,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    start_new_session=True,
                )
                try:
                    exit_code = process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    _terminate_process_group(process, min(1.0, timeout_seconds))
                    exit_code = process.returncode
                    failure = InternalFailure(
                        FailureKind.TIMEOUT, "process exceeded its timeout"
                    )
        except OSError as error:
            stdout_path.touch(exist_ok=True)
            stderr_path.touch(exist_ok=True)
            failure = InternalFailure(FailureKind.SPAWN, str(error))
        _redact_log(stdout_path, protected)
        _redact_log(stderr_path, protected)

        artifacts: list[OutputArtifact] = []
        if failure is None and exit_code not in accepted_exit_codes:
            failure = InternalFailure(
                FailureKind.NONZERO_EXIT, f"unaccepted process exit status {exit_code}"
            )
        if failure is None:
            for declaration in declared:
                path = workspace.path / declaration.path
                if declaration.path in preexisting:
                    failure = InternalFailure(
                        FailureKind.OUTPUT_STALE,
                        f"declared output existed before this invocation: {declaration.path}",
                    )
                    break
                if not path.is_file():
                    failure = InternalFailure(
                        FailureKind.OUTPUT_MISSING,
                        f"declared output is missing: {declaration.path}",
                    )
                    break
                try:
                    valid = (
                        declaration.validator(path)
                        if declaration.validator is not None
                        else True
                    )
                except Exception:
                    valid = False
                if not valid:
                    failure = InternalFailure(
                        FailureKind.OUTPUT_MALFORMED,
                        f"declared output is malformed: {declaration.path}",
                    )
                    break
                artifacts.append(
                    OutputArtifact(
                        declaration.path,
                        declaration.kind,
                        str(path.stat().st_size),
                        _digest(path),
                    )
                )

        ended = time.monotonic()
        ended_wall = datetime.now(UTC)
        return ProcessResult(
            ProcessStatus.SUCCEEDED if failure is None else ProcessStatus.FAILED,
            executable,
            _redact(argv, protected),
            started_wall.isoformat(),
            ended_wall.isoformat(),
            ended - started,
            exit_code,
            failure,
            stdout_path,
            stderr_path,
            tuple(artifacts),
        )
