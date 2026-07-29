from __future__ import annotations

import hashlib
import stat
import textwrap
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from osqar_inspector.doxygen_adapter import DoxygenAdapter, DoxygenAdapterError
from osqar_inspector.process_runner import (
    FailureKind,
    OwnedWorkspace,
    ProcessRunner,
    ProcessStatus,
    WorkspaceManager,
)

SNAPSHOT_ID = "snapshot:sha256:" + "a" * 64


def _snapshot(*paths: str) -> SimpleNamespace:
    return SimpleNamespace(
        snapshot_id=SNAPSHOT_ID,
        files=tuple({"path": path, "kind": "file"} for path in paths),
    )


def _producer(tmp_path: Path, *, version: str = "1.9.8", mode: str = "valid") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"fake-doxygen-{mode}"
    script = f'''#!/usr/bin/env python3
import sys
import time
from pathlib import Path

if "--version" in sys.argv:
    print({version!r})
    raise SystemExit(0)

mode = {mode!r}
if mode == "timeout":
    time.sleep(10)
if mode == "nonzero":
    raise SystemExit(7)
if mode == "missing":
    raise SystemExit(0)

config = Path(sys.argv[1]).read_text(encoding="utf-8")
required = ("@INCLUDE =", "GENERATE_HTML = YES", "GENERATE_XML = YES", "GENERATE_TAGFILE =")
if not all(item in config for item in required):
    raise SystemExit(8)
root = Path("output")
(root / "html").mkdir(parents=True, exist_ok=True)
(root / "xml").mkdir(parents=True, exist_ok=True)
(root / "html" / "index.html").write_bytes(b"<html><body>index</body></html>")
(root / "html" / "sample.html").write_bytes(
    b"<html><body><a id='a1'>add</a></body></html>\\x00producer-byte"
)
index = "<doxygenindex><compound kind='file' refid='file_sample'><name>src/sample.c</name>" \\
        "<member kind='function' refid='func_add'><name>add</name></member>" \\
        "</compound></doxygenindex>"
compound = "<doxygen><compounddef kind='file' id='file_sample'>" \\
           "<compoundname>src/sample.c</compoundname><location file='src/sample.c' line='1'/>" \\
           "<sectiondef><memberdef kind='function' id='func_add'>" \\
           "<name>add</name><qualifiedname>add</qualifiedname><argsstring>(int a, int b)</argsstring>" \\
           "<location file='src/sample.c' line='2' column='1'/>" \\
           "</memberdef></sectiondef></compounddef></doxygen>"
tag = "<tagfile><compound kind='file'><name>src/sample.c</name><filename>sample.html</filename>" \\
      "<member kind='function'><name>add</name><anchorfile>sample.html</anchorfile>" \\
      "<anchor>a1</anchor><arglist>(int a, int b)</arglist></member>" \\
      "</compound></tagfile>"
if mode == "malformed":
    index = "<doxygenindex>"
if mode == "duplicate":
    compound = compound.replace("</sectiondef>", "<memberdef kind='function' id='func_add'><name>other</name><qualifiedname>other</qualifiedname><location file='src/sample.c' line='3'/></memberdef></sectiondef>")
if mode == "ambiguous":
    tag = tag.replace("</compound></tagfile>", "<member kind='function'><name>add</name><anchorfile>sample.html</anchorfile><anchor>a1</anchor><arglist>(int a, int b)</arglist></member></compound></tagfile>")
if mode == "signature-mismatch":
    tag = tag.replace("(int a, int b)", "(double value)")
if mode == "unindexed-detail":
    index = index.replace("<member kind='function' refid='func_add'><name>add</name></member>", "")
(root / "xml" / "index.xml").write_text(index, encoding="utf-8")
(root / "xml" / "file_sample.xml").write_text(compound, encoding="utf-8")
(root / "doxygen.tag").write_text(tag, encoding="utf-8")
'''
    path.write_text(textwrap.dedent(script), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _adapter(tmp_path: Path, executable: Path, *, timeout: float = 2.0):
    project = tmp_path / "project"
    project.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "snapshot"
    (source / "src").mkdir(parents=True, exist_ok=True)
    (source / "src" / "sample.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    (source / "Doxyfile").write_text("PROJECT_NAME = fixture\n", encoding="utf-8")
    manager = WorkspaceManager(project, base_directory=tmp_path / "owned")
    adapter = DoxygenAdapter(
        runner=ProcessRunner(manager),
        snapshot_root=source,
        selected_paths=("Doxyfile", "src/sample.c"),
        executable=str(executable),
        timeout_seconds=timeout,
    )
    return adapter, manager


def _run(tmp_path: Path, mode: str):
    executable = _producer(tmp_path, mode=mode)
    adapter, manager = _adapter(tmp_path, executable)
    config = {"doxygen": {"configuration": "Doxyfile", "output": "build/doxygen", "warnings_as_errors": False}}
    snapshot = _snapshot("Doxyfile", "src/sample.c")
    with manager.run() as run:
        capability = adapter.probe(config, run.probe("doxygen"))
        plan = adapter.plan_declaration(config, snapshot)
        command = adapter.plan_command(plan, capability, run.stage("doxygen"))
        process = adapter.execute(command)
        if process.status is ProcessStatus.FAILED:
            return process
        output = adapter.collect(process, command.workspace)
        return adapter.normalize(output, snapshot)


def test_fake_doxygen_emits_valid_artifacts_and_mappings(tmp_path: Path) -> None:
    result = _run(tmp_path, "valid")

    assert [artifact.path for artifact in result.artifacts] == sorted(
        (artifact.path for artifact in result.artifacts), key=str.encode
    )
    payload = next(item for item in result.artifacts if item.path == "html/sample.html")
    producer_bytes = b"<html><body><a id='a1'>add</a></body></html>\x00producer-byte"
    assert payload.sha256 == hashlib.sha256(producer_bytes).hexdigest()
    assert payload.size == str(len(producer_bytes))
    assert {mapping.refid for mapping in result.mappings} == {"file_sample", "func_add"}
    symbol = next(item for item in result.mappings if item.refid == "func_add")
    assert symbol.qualified_name == "add"
    assert symbol.source_path == "src/sample.c"
    assert symbol.line == "2"
    assert symbol.column == "1"
    assert symbol.html_anchor == "a1"
    assert symbol.html_artifact_id == payload.artifact_id
    assert all(mapping.snapshot_id == SNAPSHOT_ID for mapping in result.mappings)


def test_declarative_adapter_binds_to_orchestrator_runtime(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()
    manager = WorkspaceManager(project, base_directory=tmp_path / "owned")
    declaration_adapter = DoxygenAdapter(executable="controlled-doxygen", timeout_seconds=7)

    runtime_adapter = declaration_adapter.bind_runtime(
        workspaces=manager,
        snapshot_root=snapshot_root,
        selected_paths=("Doxyfile", "src/sample.c"),
    )

    assert runtime_adapter is not declaration_adapter
    assert runtime_adapter.runner is not None
    assert runtime_adapter.runner.workspaces is manager
    assert runtime_adapter.snapshot_root == snapshot_root
    assert runtime_adapter.selected_paths == frozenset({"Doxyfile", "src/sample.c"})
    assert runtime_adapter.executable == "controlled-doxygen"
    assert runtime_adapter.timeout_seconds == 7
    assert declaration_adapter.runner is None


def test_declaration_is_pure_and_generated_config_enforces_resolved_policy(
    tmp_path: Path,
) -> None:
    config = {
        "doxygen": {
            "configuration": "Doxyfile",
            "output": "build/doxygen",
            "warnings_as_errors": True,
        }
    }
    snapshot = _snapshot("Doxyfile", "src/sample.c")
    before = tuple(tmp_path.iterdir())
    declaration_adapter = DoxygenAdapter()
    diagnostics, requirement = declaration_adapter.validate_declaration(config)
    declaration = declaration_adapter.plan_declaration(config, snapshot)
    assert tuple(tmp_path.iterdir()) == before
    assert diagnostics == ()
    assert requirement.version_constraint == ">=1.9"
    invalid = {
        "doxygen": {
            **config["doxygen"],
            "output": "build//doxygen",
        }
    }
    assert declaration_adapter.validate_declaration(invalid)[0][0].code == "doxygen.declaration_invalid"

    executable = _producer(tmp_path, mode="valid")
    adapter, manager = _adapter(tmp_path, executable)
    (tmp_path / "outside-config").write_text("PROJECT_NAME = forbidden\n", encoding="utf-8")
    (tmp_path / "snapshot" / "excluded.conf").write_text(
        "PROJECT_NAME = excluded\n", encoding="utf-8"
    )
    with manager.run() as run:
        capability = adapter.probe(config, run.probe("doxygen"))
        with pytest.raises(DoxygenAdapterError) as escaped:
            adapter.plan_command(
                replace(declaration, required_inputs=("../outside-config",)),
                capability,
                run.stage("escaped"),
            )
        assert escaped.value.code == "doxygen.declaration_invalid"
        with pytest.raises(DoxygenAdapterError) as excluded:
            adapter.plan_command(
                replace(declaration, required_inputs=("excluded.conf",)),
                capability,
                run.stage("excluded"),
            )
        assert excluded.value.code == "doxygen.input_not_selected"
        forged_path = tmp_path / "forged-workspace"
        forged_path.mkdir()
        with pytest.raises(DoxygenAdapterError) as forged:
            adapter.plan_command(
                declaration,
                capability,
                OwnedWorkspace(forged_path, "stages", "forged"),
            )
        assert forged.value.code == "doxygen.workspace_not_owned"
        assert not (forged_path / "Doxyfile.inspector").exists()
        command = adapter.plan_command(declaration, capability, run.stage("doxygen"))
        generated = (command.workspace.path / "Doxyfile.inspector").read_text(encoding="utf-8")
    assert "@INCLUDE =" in generated
    assert "WARN_AS_ERROR = YES" in generated


def test_missing_incompatible_timeout_and_nonzero_are_typed(tmp_path: Path) -> None:
    missing, missing_manager = _adapter(tmp_path / "missing-case", tmp_path / "absent")
    config = {"doxygen": {"configuration": "Doxyfile", "output": "build/doxygen", "warnings_as_errors": False}}
    with missing_manager.run() as run, pytest.raises(DoxygenAdapterError) as caught:
        missing.probe(config, run.probe("doxygen"))
    assert caught.value.code == "doxygen.capability_missing"

    incompatible_executable = _producer(tmp_path, version="1.8.20", mode="old")
    incompatible, incompatible_manager = _adapter(tmp_path / "old-case", incompatible_executable)
    with incompatible_manager.run() as run:
        capability = incompatible.probe(config, run.probe("doxygen"))
    assert incompatible.validate_capability(config, capability)[0].code == "doxygen.capability_incompatible"

    timeout = _run(tmp_path / "timeout-case", "timeout")
    assert timeout.failure is not None and timeout.failure.kind is FailureKind.TIMEOUT
    nonzero = _run(tmp_path / "nonzero-case", "nonzero")
    assert nonzero.failure is not None and nonzero.failure.kind is FailureKind.NONZERO_EXIT


def test_missing_stale_and_malformed_outputs_fail(tmp_path: Path) -> None:
    missing = _run(tmp_path / "missing-output", "missing")
    assert missing.failure is not None and missing.failure.kind is FailureKind.OUTPUT_MISSING

    executable = _producer(tmp_path / "stale-output", mode="valid")
    adapter, manager = _adapter(tmp_path / "stale-output", executable)
    config = {"doxygen": {"configuration": "Doxyfile", "output": "build/doxygen", "warnings_as_errors": False}}
    snapshot = _snapshot("Doxyfile", "src/sample.c")
    with manager.run() as run:
        capability = adapter.probe(config, run.probe("doxygen"))
        plan = adapter.plan_declaration(config, snapshot)
        command = adapter.plan_command(plan, capability, run.stage("doxygen"))
        stale = command.workspace.path / "output" / "xml" / "index.xml"
        stale.parent.mkdir(parents=True)
        stale.write_text("<doxygenindex/>", encoding="utf-8")
        process = adapter.execute(command)
    assert process.failure is not None and process.failure.kind is FailureKind.OUTPUT_STALE

    malformed = _run(tmp_path / "malformed-output", "malformed")
    assert malformed.failure is not None and malformed.failure.kind is FailureKind.OUTPUT_MALFORMED


def test_any_preexisting_file_in_collected_output_tree_is_stale(tmp_path: Path) -> None:
    executable = _producer(tmp_path, mode="valid")
    adapter, manager = _adapter(tmp_path, executable)
    config = {
        "doxygen": {
            "configuration": "Doxyfile",
            "output": "build/doxygen",
            "warnings_as_errors": True,
        }
    }
    declaration = adapter.plan_declaration(config, _snapshot("Doxyfile", "src/sample.c"))
    with manager.run() as run:
        capability = adapter.probe(config, run.probe("doxygen"))
        workspace = run.stage("doxygen")
        command = adapter.plan_command(declaration, capability, workspace)
        stale = workspace.path / "output" / "html" / "stale.css"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"stale producer payload")
        result = adapter.execute(command)
    assert result.failure is not None
    assert result.failure.kind is FailureKind.OUTPUT_STALE


def test_duplicate_refid_and_ambiguous_target_fail(tmp_path: Path) -> None:
    for mode, code in (("duplicate", "doxygen.duplicate_refid"), ("ambiguous", "doxygen.ambiguous_target")):
        with pytest.raises(DoxygenAdapterError) as caught:
            _run(tmp_path / mode, mode)
        assert caught.value.code == code


def test_signature_mismatch_and_unindexed_detail_fail(tmp_path: Path) -> None:
    for mode, code in (
        ("signature-mismatch", "doxygen.target_missing"),
        ("unindexed-detail", "doxygen.unindexed_refid"),
    ):
        with pytest.raises(DoxygenAdapterError) as caught:
            _run(tmp_path / mode, mode)
        assert caught.value.code == code
