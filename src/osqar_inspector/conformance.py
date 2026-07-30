"""External process conformance driver.

Console streams are retained only as human diagnostics.  Protocol decisions are
made exclusively from the caller-owned result file.
"""

from __future__ import annotations

import base64
import json
import math
import os
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .process_protocol import ProcessProtocolError, validate_process_result

DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_CONSOLE_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ConformanceRun:
    result: dict[str, Any]
    exit_code: int
    stdout: bytes
    stderr: bytes


def _same_directory(descriptor: int, path: Path) -> bool:
    try:
        current = path.stat(follow_symlinks=False)
    except OSError:
        return False
    anchored = os.fstat(descriptor)
    return (
        stat.S_ISDIR(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and (current.st_dev, current.st_ino) == (anchored.st_dev, anchored.st_ino)
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_supervised(
    argv: Sequence[str], *, cwd: Path | None, timeout_seconds: float
) -> tuple[int, bytes, bytes]:
    max_report_bytes = 2 * (4 * ((MAX_CONSOLE_BYTES + 2) // 3)) + 4096
    with tempfile.TemporaryFile() as report:
        supervisor_argv = [
            sys.executable,
            os.fspath(Path(__file__).with_name("_process_supervisor.py")),
            str(report.fileno()),
            str(timeout_seconds),
            str(MAX_CONSOLE_BYTES),
            "--",
            *argv,
        ]
        try:
            process = subprocess.Popen(
                supervisor_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=os.environ.copy(),
                cwd=cwd,
                start_new_session=True,
                pass_fds=(report.fileno(),),
            )
        except OSError as error:
            raise ProcessProtocolError("process supervisor could not be started") from error
        try:
            process.wait(timeout=float(timeout_seconds) + 5.0)
        except subprocess.TimeoutExpired as error:
            _kill_process_group(process)
            process.wait()
            raise ProcessProtocolError("process supervisor timed out") from error
        if process.returncode != 0:
            raise ProcessProtocolError("process supervisor failed")
        report.seek(0)
        content = report.read(max_report_bytes + 1)
    if len(content) > max_report_bytes:
        raise ProcessProtocolError("process supervisor report exceeds the size limit")
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProcessProtocolError("process supervisor returned an invalid report") from error
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise ProcessProtocolError("process supervisor returned an invalid report")
    kind = value["kind"]
    if kind == "start-error":
        raise ProcessProtocolError("process could not be started")
    if kind == "timeout":
        raise ProcessProtocolError("process timed out")
    if kind != "completed" or set(value) != {
        "kind",
        "returncode",
        "stderr",
        "stdout",
    }:
        raise ProcessProtocolError("process supervisor could not clean up descendants")
    if isinstance(value["returncode"], bool) or not isinstance(value["returncode"], int):
        raise ProcessProtocolError("process supervisor returned an invalid exit code")
    try:
        stdout = base64.b64decode(value["stdout"], validate=True)
        stderr = base64.b64decode(value["stderr"], validate=True)
    except (TypeError, ValueError) as error:
        raise ProcessProtocolError("process supervisor returned invalid diagnostics") from error
    if len(stdout) > MAX_CONSOLE_BYTES or len(stderr) > MAX_CONSOLE_BYTES:
        raise ProcessProtocolError("process supervisor exceeded the diagnostics limit")
    return value["returncode"], stdout, stderr


def run_protocol_command(
    argv: Sequence[str],
    *,
    command: str,
    result_file: Path,
    cwd: Path | None = None,
    expected_run_id: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ConformanceRun:
    """Run an exact argv and validate only its newly created machine result."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ProcessProtocolError("process timeout must be a finite positive number")
    base = Path(cwd).absolute() if cwd is not None else Path.cwd()
    effective_result = result_file if result_file.is_absolute() else base / result_file
    parent = effective_result.parent
    name = effective_result.name
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(parent, directory_flags)
    except OSError as error:
        raise ProcessProtocolError("owned result directory is unavailable") from error
    try:
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ProcessProtocolError("owned result file already exists")
        exit_code, stdout, stderr = _run_supervised(
            list(argv), cwd=cwd, timeout_seconds=float(timeout_seconds)
        )
        if not _same_directory(parent_descriptor, parent):
            raise ProcessProtocolError("owned result directory changed during execution")
        result_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(name, result_flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise ProcessProtocolError("process did not create a regular result file") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ProcessProtocolError("process did not create a regular result file")
            if metadata.st_size > MAX_RESULT_BYTES:
                raise ProcessProtocolError("process result exceeds the size limit")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(MAX_RESULT_BYTES + 1)
            if len(content) > MAX_RESULT_BYTES:
                raise ProcessProtocolError("process result exceeds the size limit")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)
    result = validate_process_result(
        command, content, exit_code, expected_run_id=expected_run_id
    )
    return ConformanceRun(result, exit_code, stdout, stderr)


@dataclass(frozen=True)
class InspectorDriver:
    """Reference caller for the exact ``osqar-inspector-run-v1`` argv."""

    executable: Path
    cwd: Path | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def _run(
        self,
        command: str,
        result_file: Path,
        arguments: Sequence[str],
        *,
        expected_run_id: str | None = None,
    ) -> ConformanceRun:
        return run_protocol_command(
            [os.fspath(self.executable), command, *arguments],
            command=command,
            result_file=result_file,
            cwd=self.cwd,
            expected_run_id=expected_run_id,
            timeout_seconds=self.timeout_seconds,
        )

    def capabilities(self, result_file: Path) -> ConformanceRun:
        return self._run(
            "capabilities",
            result_file,
            ["--protocol", "osqar-inspector-run-v1", "--result-file", os.fspath(result_file)],
        )

    def plan(
        self, project: Path, configuration: str, result_file: Path
    ) -> ConformanceRun:
        return self._run(
            "plan",
            result_file,
            [
                "--protocol",
                "osqar-inspector-run-v1",
                "--result-schema",
                "osqar.inspector.plan-process-result.v1",
                "--result-file",
                os.fspath(result_file),
                "--project",
                os.fspath(project),
                "--configuration",
                configuration,
            ],
        )

    def build(
        self,
        project: Path,
        configuration: str,
        result_file: Path,
        *,
        run_id: str,
    ) -> ConformanceRun:
        return self._run(
            "build",
            result_file,
            [
                "--protocol",
                "osqar-inspector-run-v1",
                "--result-schema",
                "osqar.inspector.build-process-result.v1",
                "--result-file",
                os.fspath(result_file),
                "--project",
                os.fspath(project),
                "--configuration",
                configuration,
                "--run-id",
                run_id,
            ],
            expected_run_id=run_id,
        )

    def verify(self, bundle: Path, result_file: Path) -> ConformanceRun:
        return self._run(
            "verify",
            result_file,
            [
                "--protocol",
                "osqar-inspector-run-v1",
                "--result-schema",
                "osqar.inspector.verify-process-result.v1",
                "--result-file",
                os.fspath(result_file),
                "--bundle",
                os.fspath(bundle),
            ],
        )
