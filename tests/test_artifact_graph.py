from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from osqar_inspector.artifact_graph import (
    GRAPH_SCHEMA,
    ArtifactEdge,
    ArtifactGraph,
    ArtifactGraphError,
    ArtifactNode,
    EdgeKind,
    NodeKind,
    ProducerLog,
    RenderedNavigationArtifact,
    add_rendered_navigation,
    build_artifact_graph,
    validate_artifact_graph,
)
from osqar_inspector.configuration import canonical_json
from osqar_inspector.coverage_adapter import (
    CoverageArtifact,
    CoverageOutput,
    CoverageProvenance,
    CoverageRelation,
)
from osqar_inspector.doxygen_adapter import (
    DoxygenArtifactRecord,
    DoxygenMappingRecord,
    DoxygenNormalizedOutput,
)
from osqar_inspector.stage_result import (
    StageResult,
    StagePolicy,
    StageStatus,
    create_stage_outcome,
    create_stage_result,
)
from osqar_inspector.process_runner import (
    ExecutableIdentity,
    FailureKind,
    InternalFailure,
    ProcessResult,
    ProcessStatus,
)
from osqar_inspector.snapshot import GitSnapshot


API_CONTENT = b'<a id="run">api producer bytes</a>\n'
COVERAGE_CONTENT = b'<a id="line-2">coverage producer bytes</a>\n'


def _snapshot(*paths: str) -> GitSnapshot:
    files = tuple(
        {
            "path": path,
            "kind": "file",
            "mode": "100644",
            "size": str(len(path.encode())),
            "identity": {"sha256": hashlib.sha256(path.encode()).hexdigest()},
        }
        for path in paths
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
        tuple((path, path.encode()) for path in paths),
    )


def _rehashed_snapshot(snapshot: GitSnapshot, manifest: dict[str, Any]) -> GitSnapshot:
    identity = {
        "schema": manifest["schema"],
        "source": manifest["source"],
        "policy": manifest["policy"],
        "files": manifest["files"],
    }
    snapshot_id = "snapshot:sha256:" + hashlib.sha256(
        canonical_json({"kind": "snapshot", "identity": identity})
    ).hexdigest()
    committed = {**manifest, "snapshot_id": snapshot_id}
    return replace(
        snapshot,
        manifest=committed,
        manifest_bytes=canonical_json(committed),
        snapshot_id=snapshot_id,
        files=tuple(committed["files"]),
    )


SNAPSHOT_ID = _snapshot("src/widget.c").snapshot_id


def _api(*, duplicate_name: bool = False, content: bytes = API_CONTENT) -> DoxygenNormalizedOutput:
    page_digest = hashlib.sha256(content).hexdigest()
    page_path = "html/widget.html"
    artifact_id = "artifact:sha256:" + hashlib.sha256(
        canonical_json({"kind": "doxygen-payload", "path": page_path, "sha256": page_digest})
    ).hexdigest()
    page = DoxygenArtifactRecord(
        "osqar.inspector.doxygen-artifact.v1",
        artifact_id,
        page_path,
        "api-page",
        "18",
        page_digest,
    )
    mappings = [
        DoxygenMappingRecord(
            "osqar.inspector.doxygen-mapping.v1",
            SNAPSHOT_ID,
            "widget_run_1",
            "function",
            "widget_run",
            "src/widget.c",
            "2",
            "1",
            page.artifact_id,
            "run",
        )
    ]
    if duplicate_name:
        mappings.append(replace(mappings[0], refid="widget_run_2", html_anchor="run-2"))
    return DoxygenNormalizedOutput((page,), tuple(mappings))


def _coverage(*, symbol: str | None = "widget_run") -> CoverageOutput:
    content = COVERAGE_CONTENT
    report_tree_sha256 = hashlib.sha256(
        canonical_json(
            {
                "entries": [
                    {
                        "path": "index.html",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size": str(len(content)),
                    }
                ],
                "kind": "coverage-report-tree",
                "schema": "osqar.inspector.coverage-report-tree.v1",
            }
        )
    ).hexdigest()
    artifact_path = "index.html"
    artifact_id = "coverage-artifact:sha256:" + hashlib.sha256(
        canonical_json({"path": artifact_path, "report_tree_sha256": report_tree_sha256})
    ).hexdigest()
    artifact = CoverageArtifact(
        artifact_id,
        artifact_path,
        hashlib.sha256(content).hexdigest(),
        len(content),
        content,
        True,
    )
    relation_identity = {
        "fragment": "line-2",
        "line": 2,
        "report_artifact_id": artifact.artifact_id,
        "report_path": artifact.path,
        "snapshot_id": SNAPSHOT_ID,
        "source_path": "src/widget.c",
        "symbol": symbol,
    }
    relation = CoverageRelation(
        "coverage-relation:sha256:"
        + hashlib.sha256(canonical_json(relation_identity)).hexdigest(),
        artifact.artifact_id,
        artifact.path,
        "line-2",
        "src/widget.c",
        2,
        symbol,
    )
    return CoverageOutput(
        entry_point="index.html",
        report_tree_sha256=report_tree_sha256,
        artifacts=(artifact,),
        sidecars=(),
        relations=(relation,),
        provenance=CoverageProvenance.EXTERNALLY_ATTESTED,
        mapping_valid=True,
        attestation_valid=True,
        diagnostics=(),
    )


def _stage(stage: str, status: StageStatus = StageStatus.SKIPPED):
    return create_stage_outcome(
        stage=stage,
        adapter=f"builtin.{stage}.v1",
        status=status,
        policy=StagePolicy.OPTIONAL,
        snapshot_id=SNAPSHOT_ID,
    )


def _successful_stage(stage: str) -> StageResult:
    return _stage_record(stage, StageStatus.SUCCEEDED)


def _stage_record(stage: str, status: StageStatus) -> StageResult:
    if status not in {StageStatus.SUCCEEDED, StageStatus.FAILED}:
        return _stage(stage, status)
    failure = (
        None
        if status is StageStatus.SUCCEEDED
        else InternalFailure(FailureKind.NONZERO_EXIT, "synthetic failure")
    )
    process = ProcessResult(
        status=(
            ProcessStatus.SUCCEEDED
            if status is StageStatus.SUCCEEDED
            else ProcessStatus.FAILED
        ),
        executable=ExecutableIdentity(Path("/usr/bin/synthetic"), "2" * 64, "synthetic 1"),
        redacted_argv=("synthetic",),
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:01Z",
        duration_seconds=1.0,
        exit_code=0 if status is StageStatus.SUCCEEDED else 1,
        failure=failure,
        stdout_path=Path("/tmp/synthetic/stdout.log"),
        stderr_path=Path("/tmp/synthetic/stderr.log"),
        outputs=(),
    )
    return create_stage_result(
        stage=stage,
        adapter=f"builtin.{stage}.v1",
        policy=StagePolicy.OPTIONAL,
        snapshot_id=SNAPSHOT_ID,
        process=process,
    )


def test_builds_deterministic_graph_from_api_and_coverage_records() -> None:
    first = build_artifact_graph(
        _snapshot("src/widget.c"),
        api_output=_api(),
        coverage_output=_coverage(),
        stage_results=(_successful_stage("coverage"), _successful_stage("doxygen")),
    )
    second = build_artifact_graph(
        _snapshot("src/widget.c"),
        api_output=_api(),
        coverage_output=_coverage(),
        stage_results=(_successful_stage("doxygen"), _successful_stage("coverage")),
    )

    assert first.schema == GRAPH_SCHEMA
    assert first.identity_bytes == second.identity_bytes
    assert first.graph_id == second.graph_id
    assert [node.node_id for node in first.nodes] == sorted(
        (node.node_id for node in first.nodes), key=str.encode
    )
    assert [edge.edge_id for edge in first.edges] == sorted(
        (edge.edge_id for edge in first.edges), key=str.encode
    )
    assert {node.kind for node in first.nodes} >= {
        NodeKind.SNAPSHOT,
        NodeKind.SOURCE_FILE,
        NodeKind.SYMBOL,
        NodeKind.API_PAGE,
        NodeKind.COVERAGE_REPORT,
        NodeKind.STAGE_RESULT,
    }
    assert {edge.kind for edge in first.edges} >= {
        EdgeKind.DESCRIBES_SNAPSHOT,
        EdgeKind.DOCUMENTS_SOURCE,
        EdgeKind.DOCUMENTS_SYMBOL,
        EdgeKind.COVERS_SOURCE,
        EdgeKind.COVERS_SYMBOL,
        EdgeKind.GENERATED_BY_STAGE,
    }
    assert all(node.node_id.startswith(f"{node.kind.value}:sha256:") for node in first.nodes)
    symbol = next(node for node in first.nodes if node.kind is NodeKind.SYMBOL)
    assert symbol.fragment == "run"
    assert symbol.path == "artifacts/api/html/widget.html"
    assert b"/tmp/" not in first.identity_bytes


def test_symbol_relation_degrades_only_to_unique_exact_source() -> None:
    graph = build_artifact_graph(
        _snapshot("src/widget.c"),
        coverage_output=_coverage(symbol="unavailable_symbol"),
    )
    coverage_node = next(node for node in graph.nodes if node.kind is NodeKind.COVERAGE_REPORT)
    related = [edge for edge in graph.edges if edge.source == coverage_node.node_id]
    assert any(edge.kind is EdgeKind.COVERS_SOURCE for edge in related)
    assert not any(edge.kind is EdgeKind.COVERS_SYMBOL for edge in related)


def test_rejects_duplicate_missing_and_ambiguous_relations() -> None:
    with pytest.raises(ArtifactGraphError) as ambiguous:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=_api(duplicate_name=True),
            coverage_output=_coverage(),
        )
    assert ambiguous.value.code == "artifact_graph.ambiguous_relation"

    valid = build_artifact_graph(_snapshot("src/widget.c"))
    node = valid.nodes[0]
    duplicate = ArtifactGraph(
        schema=valid.schema,
        graph_id=valid.graph_id,
        snapshot_id=valid.snapshot_id,
        nodes=(node, node),
        edges=(),
        identity_bytes=valid.identity_bytes,
    )
    with pytest.raises(ArtifactGraphError) as duplicate_error:
        validate_artifact_graph(duplicate)
    assert duplicate_error.value.code == "artifact_graph.duplicate_node_id"

    missing_edge = ArtifactEdge(
        edge_id="edge:sha256:" + "f" * 64,
        kind=EdgeKind.LINKS_TO,
        source=node.node_id,
        target="node:sha256:" + "0" * 64,
    )
    missing = replace(valid, edges=(missing_edge,))
    with pytest.raises(ArtifactGraphError) as missing_error:
        validate_artifact_graph(missing)
    assert missing_error.value.code == "artifact_graph.missing_endpoint"

    wrong = ArtifactNode(
        node_id="node:sha256:" + "1" * 64,
        kind=NodeKind.SOURCE_FILE,
        label="wrong",
        path="src/wrong.c",
        fragment=None,
        sha256="1" * 64,
        provenance=None,
        stage_status=None,
    )
    invalid_kind = replace(
        valid,
        nodes=tuple(sorted((*valid.nodes, wrong), key=lambda item: item.node_id.encode())),
        edges=(
            ArtifactEdge(
                edge_id="edge:sha256:" + "2" * 64,
                kind=EdgeKind.DOCUMENTS_SYMBOL,
                source=node.node_id,
                target=wrong.node_id,
            ),
        ),
    )
    with pytest.raises(ArtifactGraphError) as kind_error:
        validate_artifact_graph(invalid_kind)
    assert kind_error.value.code == "artifact_graph.invalid_edge_kind"

    coverage = _coverage()
    duplicated_relations = replace(
        coverage, relations=(coverage.relations[0], coverage.relations[0])
    )
    with pytest.raises(ArtifactGraphError) as duplicated_relation:
        build_artifact_graph(
            _snapshot("src/widget.c"), coverage_output=duplicated_relations
        )
    assert duplicated_relation.value.code == "artifact_graph.duplicate_edge_id"


@pytest.mark.parametrize(
    "log",
    (
        ProducerLog("doxygen", "stdout.log", "not-a-digest", 1),
        ProducerLog("doxygen", "stdout.log", "1" * 64, -1),
        ProducerLog("doxygen", cast(str, 7), "1" * 64, 1),
    ),
)
def test_rejects_invalid_producer_log_identity(log: ProducerLog) -> None:
    with pytest.raises(ArtifactGraphError):
        build_artifact_graph(
            _snapshot("src/widget.c"),
            stage_results=(_successful_stage("doxygen"),),
            producer_logs=(log,),
        )


@pytest.mark.parametrize(
    "status",
    (StageStatus.SKIPPED, StageStatus.BLOCKED, StageStatus.DEGRADED),
)
def test_rejects_logs_for_nonexecuted_stage_outcomes(status: StageStatus) -> None:
    with pytest.raises(ArtifactGraphError) as caught:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            stage_results=(_stage("doxygen", status),),
            producer_logs=(ProducerLog("doxygen", "stdout.log", "1" * 64, 1),),
        )
    assert caught.value.code == "artifact_graph.stage_output_mismatch"


def test_rejects_malformed_doxygen_mapping_primitives_and_navigation_path() -> None:
    api = _api()
    with pytest.raises(ArtifactGraphError) as mapping_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(
                api,
                mappings=(
                    replace(
                        api.mappings[0],
                        qualified_name=cast(str, 7),
                        html_anchor=cast(str, 9),
                    ),
                ),
            ),
        )
    assert mapping_error.value.code == "artifact_graph.invalid_identity"

    duplicate_mapping = replace(api.mappings[0], qualified_name="other")
    with pytest.raises(ArtifactGraphError) as duplicate_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(
                api, mappings=(api.mappings[0], duplicate_mapping)
            ),
        )
    assert duplicate_error.value.code == "artifact_graph.duplicate_node_id"

    valid = build_artifact_graph(_snapshot("src/widget.c"), api_output=api)
    symbol = next(node for node in valid.nodes if node.kind is NodeKind.SYMBOL)
    symbol_preimage = json.loads(symbol.identity_json or "{}")
    symbol_preimage["identity"]["refid"] = 7
    malformed_identity_json = canonical_json(symbol_preimage).decode("utf-8")
    malformed_symbol = replace(
        symbol,
        identity_json=malformed_identity_json,
        identity_sha256=hashlib.sha256(
            malformed_identity_json.encode("utf-8")
        ).hexdigest(),
    )
    with pytest.raises(ArtifactGraphError) as symbol_error:
        validate_artifact_graph(
            replace(
                valid,
                nodes=tuple(
                    malformed_symbol if node.node_id == symbol.node_id else node
                    for node in valid.nodes
                ),
            )
        )
    assert symbol_error.value.code == "artifact_graph.invalid_identity"

    graph = build_artifact_graph(_snapshot("src/widget.c"))
    with pytest.raises(ArtifactGraphError) as navigation_error:
        add_rendered_navigation(
            graph,
            (
                RenderedNavigationArtifact(
                    cast(str, 7), "1" * 64, 1, (graph.nodes[0].node_id,)
                ),
            ),
        )
    assert navigation_error.value.code == "artifact_graph.invalid_path"

    with pytest.raises(ArtifactGraphError) as targets_error:
        add_rendered_navigation(
            graph,
            (
                RenderedNavigationArtifact(
                    "navigation/index.html",
                    "1" * 64,
                    1,
                    cast(tuple[str, ...], 7),
                ),
            ),
        )
    assert targets_error.value.code == "artifact_graph.invalid_identity"


def test_rejects_unrecognized_doxygen_record_schemas() -> None:
    api = _api()
    with pytest.raises(ArtifactGraphError) as artifact_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(
                api,
                artifacts=(replace(api.artifacts[0], schema="future-artifact-schema"),),
            ),
        )
    assert artifact_error.value.code == "artifact_graph.unsupported_schema"

    with pytest.raises(ArtifactGraphError) as mapping_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(
                api,
                mappings=(replace(api.mappings[0], schema="future-mapping-schema"),),
            ),
        )
    assert mapping_error.value.code == "artifact_graph.unsupported_schema"

    with pytest.raises(ArtifactGraphError) as kind_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(
                api,
                artifacts=(replace(api.artifacts[0], kind="future-kind"),),
            ),
        )
    assert kind_error.value.code == "artifact_graph.unsupported_kind"


def test_rejects_forged_adapter_native_identities() -> None:
    api = _api()
    with pytest.raises(ArtifactGraphError) as api_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(
                api,
                artifacts=(replace(api.artifacts[0], artifact_id="artifact:sha256:" + "0" * 64),),
            ),
        )
    assert api_error.value.code == "artifact_graph.identity_mismatch"

    coverage = _coverage()
    with pytest.raises(ArtifactGraphError) as relation_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            coverage_output=replace(
                coverage,
                relations=(
                    replace(
                        coverage.relations[0],
                        relation_id="coverage-relation:sha256:" + "0" * 64,
                    ),
                ),
            ),
        )
    assert relation_error.value.code == "artifact_graph.identity_mismatch"


def test_rejects_forged_stage_result_and_malformed_edge_profiles() -> None:
    stage = _successful_stage("doxygen")
    with pytest.raises(ArtifactGraphError) as stage_error:
        build_artifact_graph(
            _snapshot("src/widget.c"), stage_results=(replace(stage, adapter="forged"),)
        )
    assert stage_error.value.code == "artifact_graph.identity_mismatch"

    valid = build_artifact_graph(
        _snapshot("src/widget.c"), coverage_output=_coverage()
    )
    coverage_edge = next(edge for edge in valid.edges if edge.kind is EdgeKind.COVERS_SOURCE)
    malformed_relation = replace(coverage_edge, line=0)
    with pytest.raises(ArtifactGraphError) as relation_error:
        validate_artifact_graph(
            replace(valid, edges=tuple(
                malformed_relation if edge.edge_id == coverage_edge.edge_id else edge
                for edge in valid.edges
            ))
        )
    assert relation_error.value.code == "artifact_graph.invalid_relation"

    structural = next(edge for edge in valid.edges if edge.kind is EdgeKind.DESCRIBES_SNAPSHOT)
    malformed_structural = replace(structural, relation_id="coverage-relation:sha256:" + "1" * 64)
    with pytest.raises(ArtifactGraphError) as structural_error:
        validate_artifact_graph(
            replace(valid, edges=tuple(
                malformed_structural if edge.edge_id == structural.edge_id else edge
                for edge in valid.edges
            ))
        )
    assert structural_error.value.code == "artifact_graph.invalid_relation"


def test_rejects_coverage_kind_and_native_relation_forgery() -> None:
    coverage = _coverage()
    with pytest.raises(ArtifactGraphError) as entry_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            coverage_output=replace(
                coverage,
                artifacts=(replace(coverage.artifacts[0], entry_point=False),),
            ),
        )
    assert entry_error.value.code == "artifact_graph.identity_mismatch"

    invalid_path = replace(coverage.artifacts[0], path=cast(str, 7))
    with pytest.raises(ArtifactGraphError) as path_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            coverage_output=replace(coverage, artifacts=(invalid_path,)),
        )
    assert path_error.value.code == "artifact_graph.invalid_path"

    forged_relation = replace(coverage.relations[0], report_path="forged.html")
    forged_identity = {
        "fragment": forged_relation.fragment,
        "line": forged_relation.line,
        "report_artifact_id": forged_relation.report_artifact_id,
        "report_path": forged_relation.report_path,
        "snapshot_id": SNAPSHOT_ID,
        "source_path": forged_relation.source_path,
        "symbol": forged_relation.symbol,
    }
    forged_relation = replace(
        forged_relation,
        relation_id="coverage-relation:sha256:"
        + hashlib.sha256(canonical_json(forged_identity)).hexdigest(),
    )
    with pytest.raises(ArtifactGraphError) as path_error:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            coverage_output=replace(coverage, relations=(forged_relation,)),
        )
    assert path_error.value.code == "artifact_graph.identity_mismatch"

    valid = build_artifact_graph(_snapshot("src/widget.c"), coverage_output=coverage)
    coverage_node = next(
        node for node in valid.nodes if node.kind is NodeKind.COVERAGE_REPORT
    )
    forged_node = replace(coverage_node, kind=NodeKind.COVERAGE_PAGE)
    with pytest.raises(ArtifactGraphError) as kind_error:
        validate_artifact_graph(
            replace(
                valid,
                nodes=tuple(
                    forged_node if node.node_id == coverage_node.node_id else node
                    for node in valid.nodes
                ),
            )
        )
    assert kind_error.value.code == "artifact_graph.identity_mismatch"

    relation_edge = next(edge for edge in valid.edges if edge.kind is EdgeKind.COVERS_SOURCE)
    stale_native = replace(relation_edge, fragment="forged-fragment")
    with pytest.raises(ArtifactGraphError) as relation_error:
        validate_artifact_graph(
            replace(
                valid,
                edges=tuple(
                    stale_native if edge.edge_id == relation_edge.edge_id else edge
                    for edge in valid.edges
                ),
            )
        )
    assert relation_error.value.code == "artifact_graph.invalid_relation"


@pytest.mark.parametrize(
    ("kind", "changes"),
    (
        (NodeKind.SOURCE_FILE, {"fragment": "unsupported"}),
        (NodeKind.API_PAGE, {"stage_status": "succeeded"}),
        (NodeKind.SYMBOL, {"provenance": "unknown-origin"}),
        (NodeKind.PRODUCER_LOG, {"label": "forged.log"}),
    ),
)
def test_validator_rejects_fields_outside_closed_node_profiles(
    kind: NodeKind, changes: dict[str, str]
) -> None:
    valid = build_artifact_graph(
        _snapshot("src/widget.c"),
        api_output=_api(),
        stage_results=(_successful_stage("doxygen"),),
        producer_logs=(ProducerLog("doxygen", "stdout.log", "1" * 64, 7),),
    )
    target = next(node for node in valid.nodes if node.kind is kind)
    forged = replace(target, **changes)
    with pytest.raises(ArtifactGraphError) as caught:
        validate_artifact_graph(
            replace(
                valid,
                nodes=tuple(
                    forged if node.node_id == target.node_id else node
                    for node in valid.nodes
                ),
            )
        )
    assert caught.value.code == "artifact_graph.identity_mismatch"


def test_validator_rejects_stale_graph_identity_after_node_mutation() -> None:
    snapshot = _snapshot("src/widget.c")
    valid_snapshot_graph = build_artifact_graph(snapshot)
    for malformed_snapshot_id in (cast(str, 7), "bad\nsnapshot", ""):
        with pytest.raises(ArtifactGraphError) as graph_snapshot_error:
            validate_artifact_graph(
                replace(valid_snapshot_graph, snapshot_id=malformed_snapshot_id)
            )
        assert graph_snapshot_error.value.code == "artifact_graph.invalid_identity"

    forged_manifest = {**snapshot.manifest, "snapshot_id": "not-a-snapshot-id"}
    with pytest.raises(ArtifactGraphError) as snapshot_error:
        build_artifact_graph(
            replace(
                snapshot,
                snapshot_id="not-a-snapshot-id",
                manifest=forged_manifest,
                manifest_bytes=canonical_json(forged_manifest),
            )
        )
    assert snapshot_error.value.code == "artifact_graph.identity_mismatch"

    valid = build_artifact_graph(snapshot)
    mutated = replace(
        valid,
        nodes=tuple(
            replace(node, label="mutated") if node.kind is NodeKind.SNAPSHOT else node
            for node in valid.nodes
        ),
    )

    with pytest.raises(ArtifactGraphError) as caught:
        validate_artifact_graph(mutated)

    assert caught.value.code == "artifact_graph.identity_mismatch"


def test_validator_recomputes_snapshot_node_identity_preimage() -> None:
    valid = build_artifact_graph(_snapshot("src/widget.c"))
    changed_snapshot_id = "snapshot:sha256:" + "9" * 64
    changed_nodes = tuple(
        replace(node, label=changed_snapshot_id)
        if node.kind is NodeKind.SNAPSHOT
        else node
        for node in valid.nodes
    )
    identity = json.loads(valid.identity_bytes)
    identity["snapshot_id"] = changed_snapshot_id
    for record in identity["nodes"]:
        if record["kind"] == NodeKind.SNAPSHOT.value:
            record["label"] = changed_snapshot_id
    identity_bytes = canonical_json(identity)
    forged = replace(
        valid,
        graph_id="artifact-graph:sha256:" + hashlib.sha256(identity_bytes).hexdigest(),
        snapshot_id=changed_snapshot_id,
        nodes=changed_nodes,
        identity_bytes=identity_bytes,
    )

    with pytest.raises(ArtifactGraphError) as caught:
        validate_artifact_graph(forged)

    assert caught.value.code == "artifact_graph.identity_mismatch"


def test_validator_rejects_kind_specific_semantic_forgery_after_outer_rehash() -> None:
    valid = build_artifact_graph(
        _snapshot("src/widget.c"),
        api_output=_api(),
        coverage_output=_coverage(),
        stage_results=(_successful_stage("coverage"), _successful_stage("doxygen")),
        producer_logs=(ProducerLog("doxygen", "stdout.log", "1" * 64, 7),),
    )
    stage_graph = build_artifact_graph(
        _snapshot("src/widget.c"),
        stage_results=(_successful_stage("doxygen"),),
    )
    stage_node = next(
        node for node in stage_graph.nodes if node.kind is NodeKind.STAGE_RESULT
    )
    for malformed_stage in (cast(str, 7), "bad\nlabel", ""):
        with pytest.raises(ArtifactGraphError) as stage_label_error:
            validate_artifact_graph(
                replace(
                    stage_graph,
                    nodes=tuple(
                        replace(stage_node, label=malformed_stage)
                        if node.node_id == stage_node.node_id
                        else node
                        for node in stage_graph.nodes
                    ),
                )
            )
        assert stage_label_error.value.code == "artifact_graph.invalid_identity"

    mutations = {
        NodeKind.SOURCE_FILE: {"path": "/forged/source.c", "label": "/forged/source.c"},
        NodeKind.STAGE_RESULT: {"stage_status": "forged"},
        NodeKind.API_PAGE: {"path": "artifacts/api/forged.html", "label": "forged.html"},
        NodeKind.SYMBOL: {"label": "forged_symbol"},
        NodeKind.COVERAGE_REPORT: {"provenance": "forged"},
        NodeKind.PRODUCER_LOG: {"sha256": "f" * 64},
    }

    for kind, changes in mutations.items():
        target_node = next(node for node in valid.nodes if node.kind is kind)
        changed_node = replace(target_node, **changes)
        changed_nodes = tuple(
            changed_node if node.node_id == target_node.node_id else node for node in valid.nodes
        )
        identity = json.loads(valid.identity_bytes)
        for record in identity["nodes"]:
            if record["node_id"] == target_node.node_id:
                record.update(changes)
                break
        identity_bytes = canonical_json(identity)
        forged = replace(
            valid,
            graph_id="artifact-graph:sha256:" + hashlib.sha256(identity_bytes).hexdigest(),
            nodes=changed_nodes,
            identity_bytes=identity_bytes,
        )
        with pytest.raises(ArtifactGraphError) as caught:
            validate_artifact_graph(forged)
        assert caught.value.code in {
            "artifact_graph.identity_mismatch",
            "artifact_graph.invalid_digest",
            "artifact_graph.invalid_path",
        }


def test_validator_rejects_duplicate_forged_and_unknown_edge_kinds() -> None:
    valid = build_artifact_graph(_snapshot("src/widget.c"))
    edge = valid.edges[0]

    with pytest.raises(ArtifactGraphError) as duplicate:
        validate_artifact_graph(replace(valid, edges=(edge, edge)))
    assert duplicate.value.code == "artifact_graph.duplicate_edge_id"

    forged = replace(edge, edge_id="edge:sha256:" + "f" * 64)
    with pytest.raises(ArtifactGraphError) as forged_error:
        validate_artifact_graph(replace(valid, edges=(forged,)))
    assert forged_error.value.code == "artifact_graph.identity_mismatch"

    unknown = replace(edge, kind=cast(EdgeKind, "future-edge"))
    with pytest.raises(ArtifactGraphError) as unknown_error:
        validate_artifact_graph(replace(valid, edges=(unknown,)))
    assert unknown_error.value.code == "artifact_graph.invalid_edge_kind"


@pytest.mark.parametrize(
    "status",
    (StageStatus.SKIPPED, StageStatus.DEGRADED, StageStatus.BLOCKED),
)
def test_rejects_producer_output_for_non_succeeded_stage(status: StageStatus) -> None:
    with pytest.raises(ArtifactGraphError) as caught:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=_api(),
            stage_results=(_stage("doxygen", status),),
        )

    assert caught.value.code == "artifact_graph.stage_output_mismatch"


def test_rejects_fully_rehashed_invalid_native_snapshot_profiles() -> None:
    snapshot = _snapshot("src/widget.c")
    mutations: list[dict[str, Any]] = []

    forged_source = json.loads(json.dumps(snapshot.manifest))
    forged_source["source"] = {
        "kind": "forged",
        "object_format": "bad",
        "commit": "x",
        "tree": "y",
    }
    mutations.append(forged_source)

    forged_policy = json.loads(json.dumps(snapshot.manifest))
    forged_policy["policy"] = {"include": ["other"], "exclude": []}
    mutations.append(forged_policy)

    for field, value in (("mode", "100600"), ("size", "01")):
        forged_file = json.loads(json.dumps(snapshot.manifest))
        forged_file["files"][0][field] = value
        mutations.append(forged_file)

    forged_digest = json.loads(json.dumps(snapshot.manifest))
    forged_digest["files"][0]["identity"]["sha256"] = "f" * 64
    mutations.append(forged_digest)

    for manifest in mutations:
        with pytest.raises(ArtifactGraphError) as caught:
            build_artifact_graph(_rehashed_snapshot(snapshot, manifest))
        assert caught.value.code in {
            "artifact_graph.identity_mismatch",
            "artifact_graph.invalid_identity",
        }

    with pytest.raises(ArtifactGraphError) as content_error:
        build_artifact_graph(replace(snapshot, _content=(("src/widget.c", b"forged"),)))
    assert content_error.value.code == "artifact_graph.identity_mismatch"


def test_rejects_duplicate_doxygen_semantic_target_with_distinct_refid() -> None:
    api = _api()
    duplicate = replace(api.mappings[0], refid="widget_run_2")
    with pytest.raises(ArtifactGraphError) as caught:
        build_artifact_graph(
            _snapshot("src/widget.c"),
            api_output=replace(api, mappings=(*api.mappings, duplicate)),
        )
    assert caught.value.code == "artifact_graph.duplicate_node_id"
