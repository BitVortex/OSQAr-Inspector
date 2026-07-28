from __future__ import annotations

import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from osqar_inspector.doxygen_adapter import DoxygenAdapter
from osqar_inspector.process_runner import ProcessRunner, ProcessStatus, WorkspaceManager


def test_real_doxygen_fixture_maps_file_and_symbol(tmp_path: Path) -> None:
    executable = shutil.which("doxygen")
    if executable is None:
        if os.environ.get("CI"):
            pytest.fail("Doxygen is required in CI for the real-producer integration lane")
        pytest.skip("Doxygen is explicitly unavailable in this developer environment")

    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "snapshot"
    (source / "src").mkdir(parents=True)
    (source / "Doxyfile").write_text("PROJECT_NAME = integration-fixture\n", encoding="utf-8")
    (source / "src" / "sample.c").write_text(
        "/** Add two integers. */\nint add(int a, int b) { return a + b; }\n",
        encoding="utf-8",
    )
    snapshot = SimpleNamespace(
        snapshot_id="snapshot:sha256:" + "b" * 64,
        files=(
            {"path": "Doxyfile", "kind": "file"},
            {"path": "src/sample.c", "kind": "file"},
        ),
    )
    config = {
        "doxygen": {
            "configuration": "Doxyfile",
            "output": "build/doxygen",
            "warnings_as_errors": False,
        }
    }
    manager = WorkspaceManager(project, base_directory=tmp_path / "owned")
    adapter = DoxygenAdapter(
        runner=ProcessRunner(manager),
        snapshot_root=source,
        selected_paths=("Doxyfile", "src/sample.c"),
        executable=executable,
        timeout_seconds=30,
    )

    with manager.run() as run:
        capability = adapter.probe(config, run.probe("doxygen"))
        assert adapter.validate_capability(config, capability) == ()
        declaration = adapter.plan_declaration(config, snapshot)
        command = adapter.plan_command(declaration, capability, run.stage("doxygen"))
        process = adapter.execute(command)
        assert process.status is ProcessStatus.SUCCEEDED, process.failure
        output = adapter.collect(process, command.workspace)
        normalized = adapter.normalize(output, snapshot)

    assert any(item.entity_kind == "file" and item.source_path == "src/sample.c" for item in normalized.mappings)
    assert any(item.entity_kind == "function" and item.qualified_name.endswith("add") for item in normalized.mappings)
