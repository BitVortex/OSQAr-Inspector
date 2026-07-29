from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import pytest

import osqar_inspector.process_runner as process_runner_module
from osqar_inspector.process_runner import (
    FailureKind,
    ProcessRunner,
    ProcessStatus,
    WorkspaceManager,
)


def _script(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "producer.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_runs_argument_vector_in_owned_workspace_and_captures_logs(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    producer = _script(
        tmp_path,
        "from pathlib import Path\n"
        "import os, sys\n"
        "Path('producer-output.txt').write_text(os.getcwd(), encoding='utf-8')\n"
        "print('producer stdout')\n"
        "print('producer stderr', file=sys.stderr)\n",
    )
    manager = WorkspaceManager(project)
    runner = ProcessRunner(manager)

    with manager.run() as run:
        probe = run.probe("fake")
        stage = run.stage("docs")
        result = runner.run(
            [sys.executable, str(producer)],
            workspace=stage,
            version_arguments=("--version",),
        )

        assert run.path.parent != project
        assert not run.path.is_relative_to(project)
        assert probe.path != stage.path
        assert result.status is ProcessStatus.SUCCEEDED
        assert result.stdout_path.read_text(encoding="utf-8") == "producer stdout\n"
        assert result.stderr_path.read_text(encoding="utf-8") == "producer stderr\n"
        assert Path(
            (stage.path / "producer-output.txt").read_text(encoding="utf-8")
        ) == stage.path
        assert result.executable.path == Path(sys.executable).resolve()
        assert result.executable.version
        assert not (project / "producer-output.txt").exists()


def test_timeout_nonzero_and_spawn_failure_are_typed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    runner = ProcessRunner(WorkspaceManager(project))
    with runner.workspaces.run() as run:
        timeout = runner.run(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            workspace=run.stage("timeout"),
            timeout_seconds=0.05,
        )
        nonzero = runner.run(
            [sys.executable, "-c", "raise SystemExit(7)"],
            workspace=run.stage("nonzero"),
        )
        spawn = runner.run(
            [str(tmp_path / "does-not-exist")],
            workspace=run.stage("spawn"),
        )

    assert timeout.status is ProcessStatus.FAILED
    assert timeout.failure is not None
    assert timeout.failure.kind is FailureKind.TIMEOUT
    assert nonzero.exit_code == 7
    assert nonzero.failure is not None
    assert nonzero.failure.kind is FailureKind.NONZERO_EXIT
    assert spawn.exit_code is None
    assert spawn.failure is not None
    assert spawn.failure.kind is FailureKind.SPAWN


def test_shell_metacharacters_are_not_interpreted_and_secrets_are_redacted(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    secret = "token-super-secret"
    literal = f"; touch escaped ; ${secret}"
    runner = ProcessRunner(WorkspaceManager(project))
    with runner.workspaces.run() as run:
        stage = run.stage("literal")
        result = runner.run(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1])",
                literal,
            ],
            workspace=stage,
            secrets=(secret,),
        )

        assert result.status is ProcessStatus.SUCCEEDED
        assert (
            result.stdout_path.read_text(encoding="utf-8")
            == "; touch escaped ; $<redacted>\n"
        )
        assert not (stage.path / "escaped").exists()
        assert secret not in " ".join(result.redacted_argv)
        assert result.redacted_argv[-1] == "; touch escaped ; $<redacted>"


def test_cleanup_failure_is_diagnostic_and_preserves_primary_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manager = WorkspaceManager(project)
    runner = ProcessRunner(manager)
    with manager.run() as run:
        result = runner.run(
            [sys.executable, "-c", "pass"],
            workspace=run.stage("successful"),
        )

        def fail_cleanup(path: Path) -> None:
            raise OSError("simulated cleanup failure")

        monkeypatch.setattr(process_runner_module.shutil, "rmtree", fail_cleanup)

    assert result.status is ProcessStatus.SUCCEEDED
    assert run.cleanup_diagnostics[0].code == "workspace.cleanup_failed"


def test_runner_rejects_forged_workspace_under_its_base(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    base = tmp_path / "workspaces"
    manager = WorkspaceManager(project, base_directory=base)
    forged_path = base / "not-created-by-manager"
    forged_path.mkdir(parents=True)
    forged = process_runner_module.OwnedWorkspace(forged_path, "stages", "forged")

    with pytest.raises(ValueError, match="owned"):
        ProcessRunner(manager).run([sys.executable, "-c", "pass"], workspace=forged)


def test_timeout_terminates_sigterm_ignoring_descendants(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    runner = ProcessRunner(WorkspaceManager(project))
    child = (
        "import signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(0.25); Path('escaped-timeout').write_text('alive')"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
        "time.sleep(10)"
    )

    with runner.workspaces.run() as run:
        stage = run.stage("process-group")
        result = runner.run(
            [sys.executable, "-c", parent],
            workspace=stage,
            timeout_seconds=0.1,
        )
        time.sleep(0.35)
        assert not (stage.path / "escaped-timeout").exists()

    assert result.failure is not None
    assert result.failure.kind is FailureKind.TIMEOUT


def test_version_probe_cannot_satisfy_declared_stage_output(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    executable = _script(
        tmp_path,
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    Path('report.json').write_text('{}', encoding='utf-8')\n"
        "    print('fake-producer 1.0')\n",
    )
    executable.chmod(0o755)
    runner = ProcessRunner(WorkspaceManager(project))

    with runner.workspaces.run() as run:
        result = runner.run(
            [str(executable)],
            workspace=run.stage("producer"),
            version_arguments=("--version",),
            outputs=(process_runner_module.OutputDeclaration("report.json"),),
        )

    assert result.failure is not None
    assert result.failure.kind is FailureKind.OUTPUT_MISSING


def test_runner_owned_logs_cannot_be_declared_as_producer_outputs() -> None:
    for name in ("stdout.log", "stderr.log"):
        with pytest.raises(ValueError, match="runner-owned"):
            process_runner_module.OutputDeclaration(name)


def test_relative_executable_identity_is_resolved_in_stage_workspace(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    runner = ProcessRunner(WorkspaceManager(project))

    with runner.workspaces.run() as run:
        stage = run.stage("relative-executable")
        executable = stage.path / "producer"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        result = runner.run(["./producer"], workspace=stage)

        assert result.executable.path == executable.resolve()
        assert result.executable.sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()


def test_version_probe_timeout_terminates_descendants(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    executable = _script(
        tmp_path,
        "#!/usr/bin/env python3\n"
        "import subprocess, sys, time\n"
        "if '--version' in sys.argv:\n"
        "    child = \"import signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(.4); "
        "Path('escaped-version-probe').write_text('alive')\"\n"
        "    subprocess.Popen([sys.executable, '-c', child])\n"
        "    time.sleep(10)\n",
    )
    executable.chmod(0o755)
    runner = ProcessRunner(WorkspaceManager(project))

    with runner.workspaces.run() as run:
        result = runner.run(
            [str(executable)],
            workspace=run.stage("version-timeout"),
            version_arguments=("--version",),
            timeout_seconds=0.2,
        )
        time.sleep(0.5)
        assert not list(run.path.rglob("escaped-version-probe"))

    assert result.status is ProcessStatus.SUCCEEDED
