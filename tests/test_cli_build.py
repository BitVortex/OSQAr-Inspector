from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from test_cli_plan import _repository
from test_publication_recovery import FailAfterReplace, _changed_candidate

from osqar_inspector.cli import _prepare_publication_root, main
from osqar_inspector.publication import (
    PublicationState,
    publish_candidate,
    recover_publication_if_present,
)


def test_build_exits_zero_only_after_durable_publication(
    tmp_path: Path, capsys
) -> None:
    project = _repository(
        tmp_path,
        {
            "stages": {
                "doxygen": {"enabled": False, "required": False},
                "coverage": {"enabled": False, "required": False},
            }
        },
    )

    status = main(
        [
            "build",
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
            "--run-id",
            "cli-run",
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "osqar.inspector.publication-result.v1"
    assert result["state"] == "durable-success"
    assert result["run_id"] == "cli-run"
    publication_root = project / "build" / "osqar-inspector"
    assert (publication_root / "current").is_symlink()
    assert os.readlink(publication_root / "current") == result["release_path"]


def test_two_default_destination_builds_remain_clean_and_reuse_release(
    tmp_path: Path, capsys
) -> None:
    project = _repository(
        tmp_path,
        {
            "stages": {
                "doxygen": {"enabled": False, "required": False},
                "coverage": {"enabled": False, "required": False},
            }
        },
    )
    arguments = [
        "build",
        "--project",
        os.fspath(project),
        "--configuration",
        "inspector.json",
    ]

    first_status = main([*arguments, "--run-id", "first"])
    first = json.loads(capsys.readouterr().out)
    second_status = main([*arguments, "--run-id", "second"])
    second = json.loads(capsys.readouterr().out)

    assert first_status == second_status == 0
    assert first["state"] == second["state"] == "durable-success"
    assert first["bundle_id"] == second["bundle_id"]
    assert first["release_path"] == second["release_path"]
    releases = project / "build" / "osqar-inspector" / "releases"
    assert len(tuple(path for path in releases.iterdir() if not path.name.startswith("."))) == 1


def test_build_reconciles_current_before_starting_a_new_build(
    tmp_path: Path, capsys
) -> None:
    project = _repository(
        tmp_path,
        {
            "stages": {
                "doxygen": {"enabled": False, "required": False},
                "coverage": {"enabled": False, "required": False},
            }
        },
    )
    publication_root = project / "build" / "osqar-inspector"
    publication_root.mkdir(parents=True)
    first = publish_candidate(_changed_candidate(), publication_root, run_id="first")
    assert first.state is PublicationState.DURABLE_SUCCESS
    uncertain = publish_candidate(
        _changed_candidate(),
        publication_root,
        run_id="uncertain",
        operations=FailAfterReplace(),
    )
    assert uncertain.state is PublicationState.COMMIT_INDETERMINATE

    status = main(
        [
            "build",
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
            "--run-id",
            "must-not-start",
        ]
    )

    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert status == 0
    assert captured.err == ""
    assert result["state"] == "durable-success"
    assert result["run_id"] == "must-not-start"
    assert not (publication_root / "releases" / ".candidate-must-not-start").exists()


def test_concurrent_publication_root_initialization_is_idempotent(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    first_component = project / "build"
    barrier = threading.Barrier(2)
    original_mkdir = Path.mkdir

    def racing_mkdir(path: Path, *args, **kwargs) -> None:
        if path == first_component:
            barrier.wait(timeout=5)
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", racing_mkdir)

    def prepare() -> Path:
        return _prepare_publication_root(project, "build/osqar-inspector")

    with ThreadPoolExecutor(max_workers=2) as executor:
        roots = [executor.submit(prepare) for _ in range(2)]
        results = [future.result(timeout=10) for future in roots]

    assert results[0] == results[1] == project / "build" / "osqar-inspector"


def test_concurrent_startup_reconciliation_observers_converge(tmp_path: Path) -> None:
    publication_root = tmp_path / "publication"
    publication_root.mkdir()
    first = publish_candidate(_changed_candidate(), publication_root, run_id="first")
    assert first.state is PublicationState.DURABLE_SUCCESS
    uncertain = publish_candidate(
        _changed_candidate(),
        publication_root,
        run_id="uncertain",
        operations=FailAfterReplace(),
    )
    assert uncertain.state is PublicationState.COMMIT_INDETERMINATE

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(recover_publication_if_present, publication_root)
            for _ in range(2)
        ]
        results = [future.result(timeout=10) for future in futures]

    assert results == [None, None]
