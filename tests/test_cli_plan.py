from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from osqar_inspector.cli import main
from osqar_inspector.configuration import resolve_configuration
from osqar_inspector.plan import create_plan
from osqar_inspector.snapshot import capture_git_snapshot


def _git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout


def _repository(tmp_path: Path, configuration: dict[str, object] | None = None) -> Path:
    repo = tmp_path / "project"
    subprocess.run(
        ["git", "init", os.fspath(repo)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    _git(repo, "config", "user.name", "Plan Tests")
    _git(repo, "config", "user.email", "plan@example.invalid")
    (repo / "Doxyfile").write_text("PROJECT_NAME = fixture\n", encoding="utf-8")
    value = {"schema": "osqar.inspector.config.v1"}
    if configuration:
        value.update(configuration)
    (repo / "inspector.json").write_text(
        json.dumps(value, separators=(",", ":")), encoding="utf-8"
    )
    _git(repo, "add", "--all")
    _git(repo, "commit", "-m", "fixture")
    return repo


def test_plan_stdout_matches_contract_fixture(tmp_path: Path, capsys) -> None:
    project = _repository(tmp_path)
    controlled = (project / "inspector.json").read_bytes()
    configuration = resolve_configuration(controlled, "inspector.json")
    snapshot = capture_git_snapshot(
        project,
        include=configuration.value["project"]["include"],
        exclude=configuration.value["project"]["exclude"],
    )
    expected = create_plan(configuration, snapshot)

    status = main(
        [
            "plan",
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert captured.out.encode() == expected.plan_bytes + b"\n"
    assert captured.err == ""


def test_plan_accepts_repeatable_typed_json_value_overrides(tmp_path: Path, capsys) -> None:
    project = _repository(tmp_path)

    status = main(
        [
            "plan",
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
            "--override",
            '/doxygen/output="generated/api"',
            "--override",
            "/doxygen/warnings_as_errors=true",
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    value = json.loads(captured.out)
    assert value["configuration"]["overrides"] == [
        {"pointer": "/doxygen/output", "value": "generated/api"},
        {"pointer": "/doxygen/warnings_as_errors", "value": True},
    ]
    assert value["stages"][0]["expected_outputs"] == ["generated/api"]


def test_plan_accepts_pointer_and_json_as_separate_override_arguments(
    tmp_path: Path, capsys
) -> None:
    project = _repository(tmp_path)

    status = main(
        [
            "plan",
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
            "--override",
            "/doxygen/output",
            '"generated/api"',
        ]
    )

    assert status == 0
    value = json.loads(capsys.readouterr().out)
    assert value["configuration"]["overrides"] == [
        {"pointer": "/doxygen/output", "value": "generated/api"}
    ]


def test_plan_never_executes_probe_that_would_write_marker(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    project = _repository(tmp_path)
    marker = tmp_path / "probe-executed"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    producer = bin_dir / "doxygen"
    producer.write_text(
        "#!/bin/sh\nprintf probe > " + os.fspath(marker) + "\n",
        encoding="utf-8",
    )
    producer.chmod(0o755)
    monkeypatch.setenv("PATH", os.fspath(bin_dir) + os.pathsep + os.environ["PATH"])

    status = main(
        ["plan", "--project", os.fspath(project), "--configuration", "inspector.json"]
    )

    assert status == 0
    assert not marker.exists()
    assert json.loads(capsys.readouterr().out)["stages"][0]["capability"]["status"] == "unresolved"


def test_plan_creates_no_files_or_directories(tmp_path: Path, capsys) -> None:
    project = _repository(tmp_path)

    def inventory() -> tuple[tuple[str, int, str], ...]:
        return tuple(
            sorted(
                (
                    path.relative_to(tmp_path).as_posix(),
                    path.lstat().st_mtime_ns,
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    if path.is_file()
                    else "",
                )
                for path in tmp_path.rglob("*")
            )
        )

    before = inventory()
    status = main(
        ["plan", "--project", os.fspath(project), "--configuration", "inspector.json"]
    )
    after = inventory()

    assert status == 0
    assert after == before
    assert capsys.readouterr().err == ""
