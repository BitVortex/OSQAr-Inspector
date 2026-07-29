from __future__ import annotations

import copy
import hashlib
import os
import stat
import textwrap
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from osqar_inspector.adapters import (
    Capability,
    CapabilityRequirements,
    CommandPlan,
    DeclarativeStagePlan,
)
from osqar_inspector.configuration import canonical_json, resolve_configuration
from osqar_inspector.coverage_adapter import (
    CoverageAdapter,
    CoverageArtifact,
    CoverageOutput,
    CoverageProvenance,
    CoverageSidecarArtifact,
)
from osqar_inspector.doxygen_adapter import DoxygenAdapter
from osqar_inspector.orchestrator import OrchestrationError, create_candidate
from osqar_inspector.plan import create_plan
from osqar_inspector.process_runner import (
    CleanupDiagnostic,
    ExecutableIdentity,
    FailureKind,
    InternalFailure,
    OutputArtifact,
    OutputDeclaration,
    ProcessResult,
    ProcessStatus,
    WorkspaceManager,
)
from osqar_inspector.snapshot import GitSnapshot
from osqar_inspector.stage_result import StageStatus
from osqar_inspector.verify import _validate_run_report


def _snapshot_from_files(contents: dict[str, bytes]) -> GitSnapshot:
    files = tuple(
        {
            "path": path,
            "kind": "file",
            "mode": "100644",
            "size": str(len(content)),
            "identity": {"sha256": hashlib.sha256(content).hexdigest()},
        }
        for path, content in sorted(contents.items(), key=lambda item: item[0].encode())
    )
    identity = {
        "schema": "osqar.inspector.snapshot.v1",
        "source": {
            "kind": "git-clean",
            "object_format": "sha1",
            "commit": "1" * 40,
            "tree": "2" * 40,
        },
        "policy": {"include": [], "exclude": []},
        "files": list(files),
    }
    snapshot_id = "snapshot:sha256:" + hashlib.sha256(
        canonical_json({"kind": "snapshot", "identity": identity})
    ).hexdigest()
    manifest = {
        **identity,
        "snapshot_id": snapshot_id,
        "metadata": {"inspector_version": "test"},
    }
    return GitSnapshot(
        manifest,
        canonical_json(manifest),
        snapshot_id,
        files,
        tuple(sorted(contents.items(), key=lambda item: item[0].encode())),
    )


def _snapshot() -> GitSnapshot:
    return _snapshot_from_files({"source.txt": b"source\n"})


def _configuration() -> Any:
    return resolve_configuration(
        b"""{
          "schema":"osqar.inspector.config.v1",
          "stages":{
            "doxygen":{"enabled":true,"required":true},
            "coverage":{"enabled":true,"required":false}
          },
          "coverage":{"report":"source.txt"}
        }""",
        "inspector.json",
    )


def _coverage_configuration() -> Any:
    return resolve_configuration(
        b"""{
          "schema":"osqar.inspector.config.v1",
          "stages":{
            "doxygen":{"enabled":false,"required":false},
            "coverage":{"enabled":true,"required":true}
          },
          "coverage":{"report":"reports/coverage/index.html"}
        }""",
        "inspector.json",
    )


def _doxygen_configuration() -> Any:
    return resolve_configuration(
        b'''{
          "schema":"osqar.inspector.config.v1",
          "stages":{
            "doxygen":{"enabled":true,"required":true},
            "coverage":{"enabled":false,"required":false}
          },
          "doxygen":{"warnings_as_errors":true}
        }''',
        "inspector.json",
    )


def _controlled_doxygen(tmp_path: Path) -> Path:
    executable = tmp_path / "controlled-doxygen"
    executable.write_text(
        textwrap.dedent(
            '''#!/usr/bin/env python3
import sys
from pathlib import Path
if "--version" in sys.argv:
    print("1.9.8")
    raise SystemExit(0)
config = Path(sys.argv[1]).read_text(encoding="utf-8")
if not all(item in config for item in ("@INCLUDE =", "GENERATE_HTML = YES", "GENERATE_XML = YES", "GENERATE_TAGFILE =", "WARN_AS_ERROR = YES")):
    raise SystemExit(8)
root = Path("output")
(root / "html").mkdir(parents=True)
(root / "xml").mkdir(parents=True)
(root / "html" / "index.html").write_bytes(b"<html>index</html>")
(root / "html" / "sample.html").write_bytes(b"<html><a id='a1'>add</a></html>")
(root / "xml" / "index.xml").write_text("<doxygenindex><compound kind='file' refid='file_sample'><name>src/sample.c</name><member kind='function' refid='func_add'><name>add</name></member></compound></doxygenindex>", encoding="utf-8")
(root / "xml" / "file_sample.xml").write_text("<doxygen><compounddef kind='file' id='file_sample'><compoundname>src/sample.c</compoundname><location file='src/sample.c' line='1'/><sectiondef><memberdef kind='function' id='func_add'><name>add</name><qualifiedname>add</qualifiedname><argsstring>(int a, int b)</argsstring><location file='src/sample.c' line='2' column='1'/></memberdef></sectiondef></compounddef></doxygen>", encoding="utf-8")
(root / "doxygen.tag").write_text("<tagfile><compound kind='file'><name>src/sample.c</name><filename>sample.html</filename><member kind='function'><name>add</name><anchorfile>sample.html</anchorfile><anchor>a1</anchor><arglist>(int a, int b)</arglist></member></compound></tagfile>", encoding="utf-8")
'''
        ),
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


@dataclass
class FakeAdapter:
    stage: str
    events: list[str]
    dependencies: tuple[str, ...] = ("snapshot",)
    process_status: ProcessStatus = ProcessStatus.SUCCEEDED
    capability_valid: bool = True
    mutation_root: Path | None = None
    omit_outputs: bool = False
    required_inputs: tuple[str, ...] = ()
    normalize_error: bool = False
    execute_error: bool = False
    malformed_process_outputs: bool = False
    execute_error_message: str = "controlled adapter execution error"
    expected_output_paths: tuple[str, ...] = ()
    logical_output_paths: tuple[str, ...] | None = None
    command_output_paths: tuple[str, ...] | None = None
    malformed_process_variant: str | None = None
    mutate_log_during_collect: bool = False
    replace_evidence_during_collect: str | None = None

    observed_output_paths: tuple[str, ...] = ()
    normalized_output: Any | None = None
    declaration_calls: int = 0
    collect_calls: int = 0
    normalize_calls: int = 0
    reject_redeclaration: bool = False

    def validate_declaration(self, config: Any):
        return (), CapabilityRequirements(f"{self.stage}-tool", ">=1")

    def plan_declaration(self, config: Any, snapshot: Any):
        self.declaration_calls += 1
        if self.reject_redeclaration and self.declaration_calls > 1:
            raise RuntimeError("declaration must not be re-evaluated")
        return DeclarativeStagePlan(
            self.stage,
            f"fake.{self.stage}.v1",
            self.dependencies,
            self.required_inputs,
            ("tool",),
            (
                self.logical_output_paths
                if self.logical_output_paths is not None
                else self.expected_output_paths or (f"{self.stage}.out",)
            ),
            f"stages/{self.stage}",
        )

    def probe(self, config: Any, workspace: Any):
        self.events.append(f"probe:{self.stage}")
        return Capability(f"{self.stage}-tool", "1.0")

    def validate_capability(self, config: Any, capability: Capability):
        if self.capability_valid:
            return ()
        from osqar_inspector.adapters import Diagnostic

        return (Diagnostic("capability.incompatible", "controlled incompatibility"),)

    def plan_command(self, plan: Any, capability: Any, workspace: Any):
        self.events.append(f"plan:{self.stage}")
        self._workspace = workspace
        paths = (
            self.command_output_paths
            if self.command_output_paths is not None
            else self.expected_output_paths or (f"{self.stage}.out",)
        )
        return CommandPlan(
            (capability.executable,),
            outputs=tuple(
                OutputDeclaration(path, "artifact", lambda candidate: candidate.is_file())
                for path in paths
            ),
        )

    def execute(self, command_plan: Any):
        self.events.append(f"execute:{self.stage}")
        if self.execute_error:
            raise RuntimeError(self.execute_error_message)
        expected = (
            self.command_output_paths
            if self.command_output_paths is not None
            else self.expected_output_paths or (f"{self.stage}.out",)
        )
        observed = self.observed_output_paths or expected
        outputs: tuple[OutputArtifact, ...] = ()
        if not self.omit_outputs:
            materialized = []
            for path in observed:
                content = b"x"
                candidate = self._workspace.path.joinpath(*path.split("/"))
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_bytes(content)
                materialized.append(
                    OutputArtifact(
                        path,
                        "artifact",
                        str(len(content)),
                        hashlib.sha256(content).hexdigest(),
                    )
                )
            outputs = tuple(materialized)
        stdout = self._workspace.path / "stdout.log"
        stderr = self._workspace.path / "stderr.log"
        stdout.write_bytes(b"controlled stdout\n")
        stderr.write_bytes(b"")
        failure = (
            None
            if self.process_status is ProcessStatus.SUCCEEDED
            else InternalFailure(FailureKind.NONZERO_EXIT, "controlled failure")
        )
        executable = self._workspace.path / "controlled-executable"
        executable.write_bytes(b"controlled executable\n")
        result = ProcessResult(
            self.process_status,
            ExecutableIdentity(
                executable.resolve(),
                hashlib.sha256(executable.read_bytes()).hexdigest(),
                "1.0",
            ),
            command_plan.argv,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
            1.0,
            0 if failure is None else 1,
            failure,
            stdout,
            stderr,
            outputs,
        )
        if self.malformed_process_variant == "detached-log":
            detached = self._workspace.path.parent / "detached.log"
            detached.write_bytes(b"detached evidence\n")
            stdout.unlink()
            stdout.symlink_to(detached)
        elif self.malformed_process_variant == "invalid-timestamp":
            result = replace(result, started_at="not-a-timestamp")
        elif self.malformed_process_variant == "succeeded-nonzero":
            result = replace(result, exit_code=9)
        elif self.malformed_process_variant == "duplicate-output":
            result = replace(result, outputs=outputs + outputs[:1])
        elif self.malformed_process_variant in {
            "missing-output",
            "symlink-output",
            "substituted-output",
        }:
            candidate = self._workspace.path.joinpath(*outputs[0].path.split("/"))
            if self.malformed_process_variant == "missing-output":
                candidate.unlink()
            elif self.malformed_process_variant == "symlink-output":
                detached = self._workspace.path.parent / "detached-output"
                detached.write_bytes(b"detached output\n")
                candidate.unlink()
                candidate.symlink_to(detached)
            else:
                candidate.write_bytes(b"substituted")
        elif self.malformed_process_variant == "missing-executable-digest":
            result = replace(
                result,
                executable=replace(result.executable, sha256=None),
            )
        elif self.malformed_process_variant == "duration-mismatch":
            result = replace(result, duration_seconds=100.0)
        elif self.malformed_process_variant == "nonzero-failure-zero":
            result = replace(
                result,
                status=ProcessStatus.FAILED,
                exit_code=0,
                failure=InternalFailure(
                    FailureKind.NONZERO_EXIT, "incoherent nonzero failure"
                ),
            )
        elif self.malformed_process_variant == "empty-argv":
            result = replace(result, redacted_argv=())
        elif self.malformed_process_variant == "hardlink-log":
            detached = self._workspace.path.parent / "hardlinked-log"
            detached.write_bytes(stdout.read_bytes())
            stdout.unlink()
            os.link(detached, stdout)
        elif self.malformed_process_variant == "hardlink-output":
            if not outputs:
                raise AssertionError("hardlink-output fixture requires an observed output")
            candidate = self._workspace.path.joinpath(*outputs[0].path.split("/"))
            detached = self._workspace.path.parent / "hardlinked-output"
            detached.write_bytes(candidate.read_bytes())
            candidate.unlink()
            os.link(detached, candidate)
        return replace(result, outputs=None) if self.malformed_process_outputs else result

    def collect(self, process_result: Any, workspace: Any):
        self.collect_calls += 1
        self.events.append(f"collect:{self.stage}")
        if self.mutate_log_during_collect:
            detached = workspace.path.parent / "post-validation-detached.log"
            detached.write_bytes(b"post-validation detached log\n")
            process_result.stdout_path.unlink()
            process_result.stdout_path.symlink_to(detached)
        elif self.replace_evidence_during_collect == "log":
            content = process_result.stdout_path.read_bytes()
            process_result.stdout_path.unlink()
            process_result.stdout_path.write_bytes(content)
        elif self.replace_evidence_during_collect == "output":
            path = workspace.path.joinpath(*process_result.outputs[0].path.split("/"))
            content = path.read_bytes()
            path.unlink()
            path.write_bytes(content)
        return object()

    def normalize(self, producer_output: Any, snapshot: Any):
        self.normalize_calls += 1
        self.events.append(f"normalize:{self.stage}")
        if self.normalize_error:
            raise ValueError("controlled malformed output")
        if self.mutation_root is not None:
            materialized = next(self.mutation_root.rglob("snapshot/source.txt"))
            materialized.write_bytes(b"mutated\n")
        return self.normalized_output


class RuntimeBindingAdapter(FakeAdapter):
    bound_snapshot_root: Path | None = None
    bound_adapter: FakeAdapter | None = None

    def bind_runtime(
        self,
        *,
        workspaces: WorkspaceManager,
        snapshot_root: Path,
        selected_paths: tuple[str, ...],
        configuration: Any,
        snapshot: GitSnapshot,
    ) -> FakeAdapter:
        assert workspaces.owns  # shared manager is provided, not a detached workspace
        assert configuration.value["schema"] == "osqar.inspector.config.v1"
        assert snapshot.snapshot_id.startswith("snapshot:sha256:")
        assert selected_paths == ("source.txt",)
        assert (snapshot_root / "source.txt").read_bytes() == b"source\n"
        self.bound_snapshot_root = snapshot_root
        self.events.append(f"bind:{self.stage}")
        return self.bound_adapter or self



def test_required_and_optional_stages_execute_in_plan_order(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }
    plan = create_plan(configuration, snapshot, adapters)

    result = create_candidate(
        configuration,
        snapshot,
        plan,
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    assert [item.stage for item in result.stage_results] == ["coverage", "doxygen"]
    assert events == [
        "probe:coverage",
        "plan:coverage",
        "execute:coverage",
        "collect:coverage",
        "normalize:coverage",
        "probe:doxygen",
        "plan:doxygen",
        "execute:doxygen",
        "collect:doxygen",
        "normalize:doxygen",
    ]
    assert all(item.status is StageStatus.SUCCEEDED for item in result.stage_results)


def test_runtime_adapter_is_bound_to_orchestrator_snapshot(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    doxygen = RuntimeBindingAdapter("doxygen", events)
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": doxygen,
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    assert result.candidate_ready is True
    assert doxygen.bound_snapshot_root is not None
    assert "bind:doxygen" in events


def test_runtime_bound_declaration_must_equal_sealed_stage(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    doxygen = RuntimeBindingAdapter("doxygen", events)
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": doxygen,
    }
    plan = create_plan(configuration, snapshot, adapters)
    bound = FakeAdapter(
        "doxygen",
        events,
        required_inputs=("missing-after-bind.txt",),
        logical_output_paths=("different-after-bind.out",),
    )
    doxygen.bound_adapter = bound

    result = create_candidate(
        configuration,
        snapshot,
        plan,
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.BLOCKED
    assert required.diagnostics[0].code == "stage.binding_mismatch"
    assert "probe:doxygen" not in events
    assert "execute:doxygen" not in events
    assert bound.collect_calls == 0
    assert bound.normalize_calls == 0
    assert result.candidate_ready is False


def test_real_coverage_adapter_ingests_materialized_snapshot_in_owned_stage(
    tmp_path: Path,
) -> None:
    report = b"<!doctype html><html><body>coverage</body></html>\n"
    configuration = _coverage_configuration()
    snapshot = _snapshot_from_files(
        {
            "reports/coverage/index.html": report,
            "src/example.c": b"int example(void) { return 0; }\n",
        }
    )
    adapter = CoverageAdapter()
    adapters = {"coverage": adapter}

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    assert result.candidate_ready is True, result.stage_results
    assert result.stage_results[0].status is StageStatus.SUCCEEDED
    assert dict(result.payloads)["artifacts/coverage/index.html"] == report
    assert b'"required_stage_decision":"satisfied"' in result.run_report


def test_real_doxygen_adapter_is_closed_through_orchestrator(tmp_path: Path) -> None:
    configuration = _doxygen_configuration()
    snapshot = _snapshot_from_files(
        {
            "Doxyfile": b"PROJECT_NAME = controlled\n",
            "src/sample.c": b"int add(int a, int b) { return a + b; }\n",
        }
    )
    adapter = DoxygenAdapter(executable=str(_controlled_doxygen(tmp_path)))
    adapters = {"doxygen": adapter}

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path),
    )

    payloads = dict(result.payloads)
    stage = result.stage_results[0]
    assert result.candidate_ready is True
    assert stage.status is StageStatus.SUCCEEDED
    assert payloads["artifacts/api/html/sample.html"] == b"<html><a id='a1'>add</a></html>"
    assert any(node.kind.value == "api-page" for node in result.graph.nodes)
    assert stage.stdout_path is not None and stage.stdout_path.as_posix() in payloads
    assert all(output.path in payloads for output in stage.outputs)
    graph_paths = {node.path: node.node_id for node in result.graph.nodes if node.path}
    expected_graph_paths = {
        "artifacts/api/doxygen.tag",
        "artifacts/api/xml/index.xml",
        "artifacts/api/xml/file_sample.xml",
        *(output.path for output in stage.outputs),
    }
    assert expected_graph_paths <= graph_paths.keys()
    linked_targets = {
        edge.target for edge in result.graph.edges if edge.kind.value == "links-to"
    }
    assert {graph_paths[path] for path in expected_graph_paths} <= linked_targets


def test_coverage_sidecar_exact_bytes_are_retained(tmp_path: Path) -> None:
    events: list[str] = []
    content = b'{"controlled":"exact bytes"}\n'
    sidecar_sha256 = hashlib.sha256(content).hexdigest()
    sidecar = CoverageSidecarArtifact(
        "coverage-sidecar:sha256:"
        + hashlib.sha256(
            canonical_json(
                {
                    "kind": "mapping",
                    "path": "evidence/coverage-map.json",
                    "sha256": sidecar_sha256,
                }
            )
        ).hexdigest(),
        "mapping",
        "evidence/coverage-map.json",
        sidecar_sha256,
        len(content),
        content,
    )
    report = b"coverage\n"
    report_sha256 = hashlib.sha256(report).hexdigest()
    report_tree_sha256 = hashlib.sha256(
        canonical_json(
            {
                "entries": [
                    {
                        "path": "index.html",
                        "sha256": report_sha256,
                        "size": str(len(report)),
                    }
                ],
                "kind": "coverage-report-tree",
                "schema": "osqar.inspector.coverage-report-tree.v1",
            }
        )
    ).hexdigest()
    output = CoverageOutput(
        "index.html",
        report_tree_sha256,
        (
            CoverageArtifact(
                "coverage-artifact:sha256:"
                + hashlib.sha256(
                    canonical_json(
                        {
                            "path": "index.html",
                            "report_tree_sha256": report_tree_sha256,
                        }
                    )
                ).hexdigest(),
                "index.html",
                report_sha256,
                len(report),
                report,
                True,
            ),
        ),
        (sidecar,),
        (),
        CoverageProvenance.UNKNOWN_ORIGIN,
        True,
        False,
        (),
    )
    configuration = _coverage_configuration()
    snapshot = _snapshot()
    adapter = FakeAdapter("coverage", events, normalized_output=output)

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, {"coverage": adapter}),
        {"coverage": adapter},
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    retained_path = "artifacts/coverage-sidecars/mapping/evidence/coverage-map.json"
    assert dict(result.payloads)[retained_path] == content
    nodes = [node for node in result.graph.nodes if node.kind.value == "coverage-sidecar"]
    assert len(nodes) == 1
    assert nodes[0].path == retained_path
    assert nodes[0].sha256 == sidecar_sha256
    assert b"evidence/coverage-map.json" in dict(result.payloads)["navigation/index.html"]
    assert any(
        edge.kind.value == "links-to" and edge.target == nodes[0].node_id
        for edge in result.graph.edges
    )


def test_permitted_optional_degradation_is_visible_in_outputs(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter(
            "coverage", events, process_status=ProcessStatus.FAILED
        ),
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    assert result.stage_results[0].status is StageStatus.DEGRADED
    assert b'"degraded":["coverage"]' in result.run_report
    index = dict(result.payloads)["navigation/index.html"]
    assert b"coverage" in index and b"degraded" in index


def test_optional_normalization_failure_degrades_with_diagnostic(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events, normalize_error=True),
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    optional = next(item for item in result.stage_results if item.stage == "coverage")
    assert optional.status is StageStatus.DEGRADED
    assert optional.diagnostics[0].code == "process.output_malformed"
    assert b'"degraded":["coverage"]' in result.run_report
    assert result.candidate_ready is True


def test_required_capability_failure_blocks_producer_and_candidate(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events, capability_valid=False),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.BLOCKED
    assert "execute:doxygen" not in events
    assert result.candidate_ready is False
    assert b'"required_stage_decision":"blocked"' in result.run_report


def test_failed_dependency_is_not_executed(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter(
            "coverage", events, process_status=ProcessStatus.FAILED
        ),
        "doxygen": FakeAdapter("doxygen", events, dependencies=("coverage",)),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    dependent = next(item for item in result.stage_results if item.stage == "doxygen")
    assert dependent.status is StageStatus.BLOCKED
    assert "probe:doxygen" not in events
    assert "execute:doxygen" not in events


def test_snapshot_mutation_blocks_candidate(tmp_path: Path) -> None:
    events: list[str] = []
    project = tmp_path / "project"
    project.mkdir()
    workspace_base = tmp_path / "workspaces"
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events, mutation_root=workspace_base),
    }

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            configuration,
            snapshot,
            create_plan(configuration, snapshot, adapters),
            adapters,
            WorkspaceManager(project, base_directory=workspace_base),
        )

    assert failure.value.code == "orchestration.snapshot_mutated"


def test_required_zero_exit_missing_output_blocks_candidate(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events, omit_outputs=True),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.exit_code == 0
    assert required.status is StageStatus.FAILED
    assert required.internal_failure == "output_missing"
    assert result.candidate_ready is False


def test_required_partial_output_set_blocks_candidate(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter(
            "doxygen",
            events,
            expected_output_paths=("doxygen.html", "doxygen.xml"),
            observed_output_paths=("doxygen.html",),
        ),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.FAILED
    assert required.internal_failure == "output_missing"
    assert result.candidate_ready is False


def test_empty_logical_outputs_still_require_exact_command_outputs(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter(
            "doxygen",
            events,
            logical_output_paths=(),
            command_output_paths=("doxygen.html", "doxygen.xml"),
            observed_output_paths=("doxygen.html",),
        ),
    }

    plan = create_plan(configuration, snapshot, adapters)
    assert next(stage for stage in plan.value["stages"] if stage["id"] == "doxygen")[
        "expected_outputs"
    ] == []
    result = create_candidate(
        configuration,
        snapshot,
        plan,
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.FAILED
    assert required.internal_failure == "output_missing"
    assert result.candidate_ready is False


def test_candidate_retains_closed_stage_and_log_evidence(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    payloads = dict(result.payloads)
    assert "reports/artifact-graph.json" in payloads
    for stage in result.stage_results:
        assert stage.stdout_path is not None and not stage.stdout_path.is_absolute()
        assert stage.stderr_path is not None and not stage.stderr_path.is_absolute()
        assert stage.stdout_path.as_posix() in payloads
        assert stage.stderr_path.as_posix() in payloads
        assert payloads[f"reports/stages/{stage.stage}.json"] == stage.identity_bytes
        for output in stage.outputs:
            assert output.path in payloads
            assert str(len(payloads[output.path])) == output.size
            assert hashlib.sha256(payloads[output.path]).hexdigest() == output.sha256


@pytest.mark.parametrize("binding", ("value", "canonical", "identity", "identity_bytes"))
def test_configuration_bindings_must_be_internally_coherent_before_execution(
    tmp_path: Path, binding: str
) -> None:
    events: list[str] = []
    configuration = _configuration()
    if binding == "value":
        value = copy.deepcopy(configuration.value)
        value["coverage"]["report"] = "forged/report.html"
        forged = replace(configuration, value=value)
    elif binding == "canonical":
        forged = replace(configuration, canonical=b"{}")
    elif binding == "identity":
        identity = copy.deepcopy(configuration.identity)
        identity["resolved"]["sha256"] = "0" * 64
        forged = replace(configuration, identity=identity)
    else:
        forged = replace(configuration, identity_bytes=b"{}")
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            forged,
            snapshot,
            create_plan(forged, snapshot, adapters),
            adapters,
            WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
        )

    assert failure.value.code == "orchestration.configuration_mismatch"
    assert events == []


def test_controlled_input_identity_must_match_retained_configuration_bytes(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    identity = copy.deepcopy(configuration.identity)
    identity["controlled_input"]["sha256"] = "0" * 64
    forged = replace(
        configuration,
        identity=identity,
        identity_bytes=canonical_json(identity),
    )
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            forged,
            snapshot,
            create_plan(forged, snapshot, adapters),
            adapters,
            WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
        )

    assert failure.value.code == "orchestration.configuration_mismatch"
    assert events == []



def test_optional_duplicate_process_outputs_degrade_before_semantic_use(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    coverage = FakeAdapter(
        "coverage",
        events,
        observed_output_paths=("coverage.out", "coverage.out"),
    )
    adapters = {
        "coverage": coverage,
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    optional = next(item for item in result.stage_results if item.stage == "coverage")
    assert optional.status is StageStatus.DEGRADED
    assert optional.diagnostics[0].code == "stage.process_result_invalid"
    assert coverage.collect_calls == 0
    assert coverage.normalize_calls == 0
    assert result.candidate_ready is True


class CleanupFailingWorkspaceManager(WorkspaceManager):
    @contextmanager
    def run(self):
        with super().run() as run:
            yield run
        run._cleanup_diagnostics.append(
            CleanupDiagnostic("workspace.cleanup_failed", "controlled cleanup failure")
        )


def test_cleanup_failure_blocks_return_of_candidate(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            configuration,
            snapshot,
            create_plan(configuration, snapshot, adapters),
            adapters,
            CleanupFailingWorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
        )

    assert failure.value.code == "orchestration.workspace_cleanup_failed"


def test_statically_blocked_required_stage_never_executes(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": RuntimeBindingAdapter(
            "doxygen", events, required_inputs=("missing-input.txt",)
        ),
    }
    plan = create_plan(configuration, snapshot, adapters)
    assert plan.blocked is True

    result = create_candidate(
        configuration,
        snapshot,
        plan,
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.BLOCKED
    assert "bind:doxygen" not in events
    assert "probe:doxygen" not in events
    assert "execute:doxygen" not in events
    assert result.candidate_ready is False


def test_adapter_execution_exception_becomes_canonical_required_failure(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter(
            "doxygen",
            events,
            execute_error=True,
            execute_error_message="execute exploded\nwith control\ttext",
        ),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.BLOCKED
    assert required.diagnostics[0].code == "stage.execution_failed"
    _validate_run_report(result.run_report)
    assert result.candidate_ready is False


def test_malformed_optional_process_result_becomes_canonical_degradation(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter(
            "coverage", events, malformed_process_outputs=True
        ),
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    optional = next(item for item in result.stage_results if item.stage == "coverage")
    assert optional.status is StageStatus.DEGRADED
    assert optional.diagnostics[0].code == "stage.process_result_invalid"
    assert result.candidate_ready is True


@pytest.mark.parametrize(
    "variant",
    (
        "detached-log",
        "invalid-timestamp",
        "succeeded-nonzero",
        "missing-executable-digest",
        "duration-mismatch",
        "nonzero-failure-zero",
        "empty-argv",
        "hardlink-log",
        "hardlink-output",
    ),
)
def test_malformed_required_process_evidence_blocks_before_field_use(
    tmp_path: Path,
    variant: str,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter(
            "doxygen", events, malformed_process_variant=variant
        ),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.BLOCKED
    assert required.diagnostics[0].code == "stage.process_result_invalid"
    assert result.candidate_ready is False


@pytest.mark.parametrize(
    "variant",
    ("duplicate-output", "missing-output", "symlink-output", "substituted-output"),
)
def test_malformed_output_is_rejected_before_semantic_callbacks(
    tmp_path: Path,
    variant: str,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    doxygen = FakeAdapter("doxygen", events, malformed_process_variant=variant)
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": doxygen,
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.BLOCKED
    assert required.diagnostics[0].code == "stage.process_result_invalid"
    assert doxygen.collect_calls == 0
    assert doxygen.normalize_calls == 0
    assert result.candidate_ready is False


def test_callback_evidence_mutation_is_rejected_and_detached_bytes_are_not_retained(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    doxygen = FakeAdapter("doxygen", events, mutate_log_during_collect=True)
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": doxygen,
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    assert required.status is StageStatus.FAILED
    assert required.diagnostics[0].code == "process.output_malformed"
    assert doxygen.collect_calls == 1
    assert doxygen.normalize_calls == 1
    assert required.stdout_path is not None
    retained = dict(result.payloads)[required.stdout_path.as_posix()]
    assert retained == b"controlled stdout\n"
    assert b"post-validation detached" not in retained
    assert result.candidate_ready is False


@pytest.mark.parametrize("target", ("log", "output"))
def test_same_byte_callback_replacement_changes_identity_and_fails_stage(
    tmp_path: Path,
    target: str,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    doxygen = FakeAdapter(
        "doxygen",
        events,
        replace_evidence_during_collect=target,
    )
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": doxygen,
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    required = next(item for item in result.stage_results if item.stage == "doxygen")
    payloads = dict(result.payloads)
    assert required.status is StageStatus.FAILED
    assert required.diagnostics[0].code == "process.output_malformed"
    assert required.stdout_path is not None
    assert payloads[required.stdout_path.as_posix()] == b"controlled stdout\n"
    assert required.outputs and payloads[required.outputs[0].path] == b"x"
    assert result.candidate_ready is False


def test_failed_optional_undeclared_output_is_not_retained(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    coverage = FakeAdapter(
        "coverage",
        events,
        process_status=ProcessStatus.FAILED,
        observed_output_paths=("rogue.out",),
    )
    adapters = {
        "coverage": coverage,
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    optional = next(item for item in result.stage_results if item.stage == "coverage")
    assert optional.status is StageStatus.DEGRADED
    assert optional.outputs == ()
    assert coverage.collect_calls == 0
    assert coverage.normalize_calls == 0
    assert all("rogue.out" not in path for path, _ in result.payloads)
    assert result.candidate_ready is True


def test_plan_must_match_configuration_snapshot_and_adapters(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }
    plan = create_plan(configuration, snapshot, adapters)
    forged = replace(
        plan,
        value={**plan.value, "plan_digest": "0" * 64},
    )

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            configuration,
            snapshot,
            forged,
            adapters,
            WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
        )

    assert failure.value.code == "orchestration.plan_mismatch"
    assert events == []


def test_self_consistent_forged_plan_semantics_are_rejected(tmp_path: Path) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }
    plan = create_plan(configuration, snapshot, adapters)
    value = copy.deepcopy(plan.value)
    value["stages"][0]["policy"] = "required"
    identity = {key: item for key, item in value.items() if key != "plan_digest"}
    value["plan_digest"] = hashlib.sha256(
        canonical_json({"kind": "plan", "identity": identity})
    ).hexdigest()
    forged = replace(plan, value=value, plan_bytes=canonical_json(value))

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            configuration,
            snapshot,
            forged,
            adapters,
            WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
        )

    assert failure.value.code == "orchestration.plan_mismatch"
    assert events == []


def test_declaration_revalidation_exception_fails_closed_before_execution(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events, reject_redeclaration=True),
        "doxygen": FakeAdapter("doxygen", events, reject_redeclaration=True),
    }
    plan = create_plan(configuration, snapshot, adapters)

    with pytest.raises(OrchestrationError) as failure:
        create_candidate(
            configuration,
            snapshot,
            plan,
            adapters,
            WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
        )

    assert failure.value.code == "orchestration.plan_validation_failed"
    assert events == []


def test_orchestrator_output_never_claims_successful_publication(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    configuration = _configuration()
    snapshot = _snapshot()
    adapters = {
        "coverage": FakeAdapter("coverage", events),
        "doxygen": FakeAdapter("doxygen", events),
    }

    result = create_candidate(
        configuration,
        snapshot,
        create_plan(configuration, snapshot, adapters),
        adapters,
        WorkspaceManager(tmp_path.mkdir(exist_ok=True) or tmp_path),
    )

    _validate_run_report(result.run_report)
    assert result.candidate_ready is True
    assert result.publication_state == "not-attempted"
    assert result.publication_result is None
    assert b"durable-success" not in result.run_report
