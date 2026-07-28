from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from osqar_inspector.adapters import ProducerAdapter
from osqar_inspector.process_runner import (
    OutputDeclaration,
    ProcessRunner,
    WorkspaceManager,
)
from osqar_inspector.stage_result import (
    StageDiagnostic,
    StagePolicy,
    StageStatus,
    create_stage_outcome,
    create_stage_result,
)


def test_success_result_has_stable_canonical_digest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manager = WorkspaceManager(project)
    runner = ProcessRunner(manager)

    def execute(run_name: str):
        with manager.run() as run:
            process = runner.run(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('out.json').write_text('{}')",
                ],
                workspace=run.stage(run_name),
                outputs=(OutputDeclaration("out.json", kind="report"),),
            )
            return create_stage_result(
                stage="documentation",
                adapter="fake-v1",
                policy=StagePolicy.REQUIRED,
                snapshot_id="snapshot:sha256:" + "a" * 64,
                process=process,
            )

    first = execute("one")
    second = execute("two")
    assert first.status is StageStatus.SUCCEEDED
    assert first.executable is not None
    assert first.outputs[0].path == "out.json"
    assert first.outputs[0].size == "2"
    assert first.identity_bytes == second.identity_bytes
    assert first.digest == second.digest
    assert str(tmp_path).encode() not in first.identity_bytes
    assert b"started_at" not in first.identity_bytes
    with pytest.raises(FrozenInstanceError):
        first.status = StageStatus.FAILED  # type: ignore[misc]


def test_zero_exit_with_missing_or_stale_output_fails(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manager = WorkspaceManager(project)
    runner = ProcessRunner(manager)
    with manager.run() as run:
        missing_process = runner.run(
            [sys.executable, "-c", "pass"],
            workspace=run.stage("missing"),
            outputs=(OutputDeclaration("report.json"),),
        )
        stale_workspace = run.stage("stale")
        (stale_workspace.path / "report.json").write_text("{}", encoding="utf-8")
        stale_process = runner.run(
            [sys.executable, "-c", "pass"],
            workspace=stale_workspace,
            outputs=(OutputDeclaration("report.json"),),
        )
        malformed_process = runner.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('report.json').write_text('bad')",
            ],
            workspace=run.stage("malformed"),
            outputs=(
                OutputDeclaration(
                    "report.json",
                    validator=lambda path: path.read_text(encoding="utf-8") == "{}",
                ),
            ),
        )

    for process in (missing_process, stale_process, malformed_process):
        result = create_stage_result(
            stage="coverage",
            adapter="fake-v1",
            policy=StagePolicy.REQUIRED,
            snapshot_id="snapshot:sha256:" + "b" * 64,
            process=process,
        )
        assert process.exit_code == 0
        assert result.status is StageStatus.FAILED
        assert result.diagnostics[0].code.startswith("process.output_")


def test_explicit_nonzero_acceptance_and_adapter_protocol_are_closed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    runner = ProcessRunner(WorkspaceManager(project))
    with runner.workspaces.run() as run:
        result = runner.run(
            [sys.executable, "-c", "raise SystemExit(3)"],
            workspace=run.stage("accepted"),
            accepted_exit_codes=frozenset({0, 3}),
        )
    assert create_stage_result(
        stage="lint",
        adapter="fake-v1",
        policy=StagePolicy.OPTIONAL,
        snapshot_id="snapshot:sha256:" + "c" * 64,
        process=result,
    ).status is StageStatus.SUCCEEDED
    assert ProducerAdapter.__abstractmethods__ == {
        "validate_declaration",
        "plan_declaration",
        "probe",
        "validate_capability",
        "plan_command",
        "execute",
        "collect",
        "normalize",
    }


def test_nonexecuted_stage_statuses_are_canonical() -> None:
    for status in (StageStatus.BLOCKED, StageStatus.SKIPPED, StageStatus.DEGRADED):
        result = create_stage_outcome(
            stage="coverage",
            adapter="generic-v1",
            status=status,
            policy=StagePolicy.OPTIONAL,
            snapshot_id="snapshot:sha256:" + "d" * 64,
            diagnostics=(
                StageDiagnostic("capability.unavailable", "capability unavailable"),
            ),
        )
        assert result.status is status
        assert status.value.encode() in result.identity_bytes


def test_identity_redacts_workspace_paths_embedded_in_arguments(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manager = WorkspaceManager(project)
    runner = ProcessRunner(manager)

    def execute(name: str):
        with manager.run() as run:
            stage = run.stage(name)
            argument = f"--output={stage.path / 'out.json'}"
            process = runner.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from pathlib import Path; "
                    "Path(sys.argv[1].split('=', 1)[1]).write_text('{}')",
                    argument,
                ],
                workspace=stage,
                outputs=(OutputDeclaration("out.json"),),
            )
            return create_stage_result(
                stage="documentation",
                adapter="fake-v1",
                policy=StagePolicy.REQUIRED,
                snapshot_id="snapshot:sha256:" + "e" * 64,
                process=process,
            )

    first = execute("first")
    second = execute("second")
    assert first.identity_bytes == second.identity_bytes
    assert str(tmp_path).encode() not in first.identity_bytes
