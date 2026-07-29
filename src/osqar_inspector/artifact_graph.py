"""Deterministic typed artifact graph over validated Inspector records."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, NoReturn, cast

from .configuration import canonical_json
from .coverage_adapter import REPORT_TREE_SCHEMA_ID, CoverageOutput, CoverageProvenance
from .doxygen_adapter import (
    ADAPTER_SELECTOR,
    ARTIFACT_SCHEMA,
    MAPPING_SCHEMA,
    DoxygenNormalizedOutput,
)
from .stage_result import SCHEMA_ID as STAGE_RESULT_SCHEMA_ID
from .stage_result import StagePolicy, StageResult, StageStatus
from .snapshot import GitSnapshot
from .snapshot import SCHEMA_ID as SNAPSHOT_SCHEMA_ID

GRAPH_SCHEMA = "osqar.inspector.artifact-graph.v1"


class NodeKind(str, Enum):
    SNAPSHOT = "snapshot"
    SOURCE_FILE = "source-file"
    SYMBOL = "symbol"
    API_PAGE = "api-page"
    COVERAGE_REPORT = "coverage-report"
    COVERAGE_PAGE = "coverage-page"
    COVERAGE_SUMMARY = "coverage-summary"
    PRODUCER_LOG = "producer-log"
    STAGE_RESULT = "stage-result"
    RENDERED_NAVIGATION_ARTIFACT = "rendered-navigation-artifact"


class EdgeKind(str, Enum):
    DESCRIBES_SNAPSHOT = "describes-snapshot"
    GENERATED_BY_STAGE = "generated-by-stage"
    DOCUMENTS_SOURCE = "documents-source"
    DOCUMENTS_SYMBOL = "documents-symbol"
    COVERS_SOURCE = "covers-source"
    COVERS_SYMBOL = "covers-symbol"
    HAS_LOG = "has-log"
    LINKS_TO = "links-to"


@dataclass
class ArtifactGraphError(ValueError):
    """Stable fail-closed graph construction or validation error."""

    code: str
    message: str
    identity: str | None = None

    def __str__(self) -> str:
        suffix = f" ({self.identity})" if self.identity is not None else ""
        return f"{self.code}: {self.message}{suffix}"


@dataclass(frozen=True)
class ArtifactNode:
    node_id: str
    kind: NodeKind
    label: str
    path: str | None
    fragment: str | None
    sha256: str | None
    provenance: str | None
    stage_status: str | None
    identity_sha256: str | None = None
    identity_json: str | None = None


@dataclass(frozen=True)
class ArtifactEdge:
    edge_id: str
    kind: EdgeKind
    source: str
    target: str
    relation_id: str | None = None
    fragment: str | None = None
    line: int | None = None
    symbol: str | None = None


@dataclass(frozen=True)
class ProducerLog:
    stage: str
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class RenderedNavigationArtifact:
    """Exact rendered navigation bytes and the graph nodes exposed by the page."""

    path: str
    sha256: str
    size: int
    target_ids: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactGraph:
    schema: str
    graph_id: str
    snapshot_id: str
    nodes: tuple[ArtifactNode, ...]
    edges: tuple[ArtifactEdge, ...]
    identity_bytes: bytes


def _fail(code: str, message: str, identity: str | None = None) -> NoReturn:
    raise ArtifactGraphError(code, message, identity)


def _identifier(prefix: str, value: dict[str, Any]) -> str:
    return f"{prefix}:sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _path(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _fail("artifact_graph.invalid_path", f"{field} is not a normalized relative path", value)
    return value


def _identity_text(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        _fail("artifact_graph.invalid_identity", f"{field} is not a canonical identity", str(value))
    return value


def _stage_identifier(value: Any, *, field: str = "stage") -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[a-z0-9]+(?:[._-][a-z0-9]+)*", value
    ) is None:
        _fail(
            "artifact_graph.invalid_identity",
            f"{field} is not a canonical stage identifier",
            str(value),
        )
    return value


def _valid_snapshot_id(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"snapshot:sha256:[0-9a-f]{64}", value
    ) is not None


def _validate_snapshot(snapshot: Any) -> GitSnapshot:
    """Reconstruct the complete native snapshot identity and content bindings."""

    if not isinstance(snapshot, GitSnapshot):
        _fail("artifact_graph.identity_mismatch", "snapshot has an invalid type")
    try:
        canonical_manifest = canonical_json(snapshot.manifest)
    except (TypeError, ValueError, RecursionError):
        _fail("artifact_graph.identity_mismatch", "snapshot manifest is not canonical JSON")
    if (
        not isinstance(snapshot.manifest, dict)
        or not isinstance(snapshot.manifest_bytes, bytes)
        or canonical_manifest != snapshot.manifest_bytes
        or set(snapshot.manifest) != {
            "files",
            "metadata",
            "policy",
            "schema",
            "snapshot_id",
            "source",
        }
        or snapshot.manifest.get("schema") != SNAPSHOT_SCHEMA_ID
        or snapshot.manifest.get("snapshot_id") != snapshot.snapshot_id
        or not isinstance(snapshot.files, tuple)
        or snapshot.manifest.get("files") != list(snapshot.files)
        or not isinstance(snapshot._content, tuple)
    ):
        _fail("artifact_graph.identity_mismatch", "snapshot manifest is inconsistent")

    source = snapshot.manifest.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"commit", "kind", "object_format", "tree"}
        or source.get("kind") != "git-clean"
        or source.get("object_format") not in {"sha1", "sha256"}
    ):
        _fail("artifact_graph.identity_mismatch", "snapshot source profile is invalid")
    object_length = 40 if source["object_format"] == "sha1" else 64
    if any(
        not isinstance(source.get(field), str)
        or re.fullmatch(rf"[0-9a-f]{{{object_length}}}", source[field]) is None
        for field in ("commit", "tree")
    ):
        _fail("artifact_graph.identity_mismatch", "snapshot Git identity is invalid")

    policy = snapshot.manifest.get("policy")
    if not isinstance(policy, dict) or set(policy) != {"exclude", "include"}:
        _fail("artifact_graph.identity_mismatch", "snapshot policy profile is invalid")
    normalized_policy: dict[str, list[str]] = {}
    for name in ("include", "exclude"):
        values = policy.get(name)
        if not isinstance(values, list):
            _fail("artifact_graph.identity_mismatch", "snapshot policy is not a path list")
        normalized = [_path(value, field=f"snapshot policy {name}") for value in values]
        if len(normalized) != len(set(normalized)) or normalized != sorted(
            normalized, key=str.encode
        ):
            _fail("artifact_graph.noncanonical_order", "snapshot policy is not canonical")
        normalized_policy[name] = normalized

    metadata = snapshot.manifest.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {"inspector_version"}:
        _fail("artifact_graph.identity_mismatch", "snapshot metadata profile is invalid")
    inspector_version = metadata.get("inspector_version")
    if not isinstance(inspector_version, str) or re.fullmatch(
        r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*", inspector_version
    ) is None:
        _fail("artifact_graph.identity_mismatch", "snapshot inspector version is invalid")

    files = snapshot.manifest["files"]
    if not isinstance(files, list) or len(files) != len(snapshot._content):
        _fail("artifact_graph.identity_mismatch", "snapshot file inventory is inconsistent")
    paths: list[str] = []
    modes: dict[str, str] = {}
    for record, content_record in zip(files, snapshot._content, strict=True):
        if (
            not isinstance(record, dict)
            or set(record) != {"identity", "kind", "mode", "path", "size"}
            or not isinstance(content_record, tuple)
            or len(content_record) != 2
        ):
            _fail("artifact_graph.identity_mismatch", "snapshot file record is invalid")
        path = _path(cast(str, record.get("path")), field="snapshot file path")
        content_path, content = content_record
        if content_path != path or not isinstance(content, bytes):
            _fail("artifact_graph.identity_mismatch", "snapshot content binding is invalid", path)
        kind = record.get("kind")
        mode = record.get("mode")
        if (kind, mode) not in {
            ("file", "100644"),
            ("file", "100755"),
            ("symlink", "120000"),
        }:
            _fail("artifact_graph.identity_mismatch", "snapshot file mode is invalid", path)
        size = record.get("size")
        if (
            not isinstance(size, str)
            or not size.isdecimal()
            or (len(size) > 1 and size.startswith("0"))
            or size != str(len(content))
        ):
            _fail("artifact_graph.identity_mismatch", "snapshot file size is invalid", path)
        record_identity = record.get("identity")
        required_identity = {"sha256"} if kind == "file" else {"sha256", "target"}
        if not isinstance(record_identity, dict) or set(record_identity) != required_identity:
            _fail("artifact_graph.identity_mismatch", "snapshot file identity is invalid", path)
        digest = record_identity.get("sha256")
        if not _valid_sha256(digest) or digest != hashlib.sha256(content).hexdigest():
            _fail("artifact_graph.identity_mismatch", "snapshot file digest is invalid", path)
        if kind == "symlink":
            try:
                target = content.decode("utf-8", "strict")
            except UnicodeDecodeError:
                _fail("artifact_graph.identity_mismatch", "snapshot symlink is not UTF-8", path)
            if record_identity.get("target") != target:
                _fail("artifact_graph.identity_mismatch", "snapshot symlink target is inconsistent", path)
            _path(target, field="snapshot symlink target")
        paths.append(path)
        modes[path] = cast(str, mode)

    if len(paths) != len(set(paths)) or paths != sorted(paths, key=str.encode):
        _fail("artifact_graph.noncanonical_order", "snapshot files are not canonical")
    for path in paths:
        included = not normalized_policy["include"] or any(
            path == root or path.startswith(root + "/")
            for root in normalized_policy["include"]
        )
        excluded = any(
            path == root or path.startswith(root + "/")
            for root in normalized_policy["exclude"]
        )
        if not included or excluded:
            _fail("artifact_graph.identity_mismatch", "snapshot file violates its policy", path)
    for record in files:
        if record["kind"] == "symlink":
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(record["path"]), record["identity"]["target"])
            )
            if modes.get(resolved) not in {"100644", "100755"}:
                _fail(
                    "artifact_graph.identity_mismatch",
                    "snapshot symlink does not resolve to a selected file",
                    record["path"],
                )

    identity = {
        "schema": snapshot.manifest["schema"],
        "source": source,
        "policy": policy,
        "files": files,
    }
    expected_id = _identifier("snapshot", {"kind": "snapshot", "identity": identity})
    if snapshot.snapshot_id != expected_id:
        _fail(
            "artifact_graph.identity_mismatch",
            "snapshot identifier does not match its native manifest",
            snapshot.snapshot_id,
        )
    return snapshot


def _validate_stage_result(result: StageResult) -> None:
    _stage_identifier(result.stage)
    if (
        result.schema != STAGE_RESULT_SCHEMA_ID
        or not isinstance(result.status, StageStatus)
        or not isinstance(result.policy, StagePolicy)
        or not isinstance(result.identity_bytes, bytes)
        or not _valid_sha256(result.digest)
        or hashlib.sha256(result.identity_bytes).hexdigest() != result.digest
    ):
        _fail("artifact_graph.identity_mismatch", "stage result identity is invalid", result.stage)
    try:
        identity = json.loads(result.identity_bytes)
    except (TypeError, ValueError, RecursionError):
        _fail("artifact_graph.identity_mismatch", "stage result identity is not JSON", result.stage)
    if canonical_json(identity) != result.identity_bytes or not isinstance(identity, dict):
        _fail("artifact_graph.identity_mismatch", "stage result identity is not canonical", result.stage)
    core = {
        "adapter": result.adapter,
        "policy": result.policy.value,
        "schema": STAGE_RESULT_SCHEMA_ID,
        "snapshot_id": result.snapshot_id,
        "stage": result.stage,
        "status": result.status.value,
    }
    if result.status in {StageStatus.SUCCEEDED, StageStatus.FAILED}:
        if result.executable is None or result.stdout_path is None:
            _fail("artifact_graph.identity_mismatch", "executed stage lacks process identity", result.stage)
        workspace = str(result.stdout_path.parent)
        stable_argv: list[str] = []
        for argument in result.redacted_argv:
            stable = argument.replace(workspace, "<workspace>")
            if stable.startswith("/"):
                stable = "<absolute>/" + stable.rsplit("/", 1)[-1]
            stable_argv.append(stable)
        expected_identity = {
            **core,
            "executable": {
                "name": result.executable.path.name,
                "sha256": result.executable.sha256,
                "version": result.executable.version,
            },
            "invocation": {
                "argv": stable_argv,
                "exit_code": result.exit_code,
                "internal_failure": result.internal_failure,
            },
            "outputs": [
                {
                    "kind": output.kind,
                    "path": output.path,
                    "sha256": output.sha256,
                    "size": output.size,
                }
                for output in result.outputs
            ],
        }
    else:
        expected_identity = {
            **core,
            "diagnostics": [
                {"code": diagnostic.code, "message": diagnostic.message}
                for diagnostic in result.diagnostics
            ],
        }
    if identity != expected_identity:
        _fail("artifact_graph.identity_mismatch", "stage result fields do not match identity", result.stage)


def _node(
    kind: NodeKind,
    identity: dict[str, Any],
    *,
    label: str,
    path: str | None = None,
    fragment: str | None = None,
    sha256: str | None = None,
    provenance: str | None = None,
    stage_status: str | None = None,
) -> ArtifactNode:
    identity_bytes = canonical_json({"identity": identity, "kind": kind.value})
    identity_sha256 = hashlib.sha256(identity_bytes).hexdigest()
    return ArtifactNode(
        f"{kind.value}:sha256:{identity_sha256}",
        kind,
        label,
        path,
        fragment,
        sha256,
        provenance,
        stage_status,
        identity_sha256,
        identity_bytes.decode("utf-8"),
    )


def _edge(
    kind: EdgeKind,
    source: str,
    target: str,
    *,
    relation_id: str | None = None,
    fragment: str | None = None,
    line: int | None = None,
    symbol: str | None = None,
) -> ArtifactEdge:
    identity = {
        "fragment": fragment,
        "kind": kind.value,
        "line": line,
        "relation_id": relation_id,
        "source": source,
        "symbol": symbol,
        "target": target,
    }
    return ArtifactEdge(
        _identifier("edge", identity), kind, source, target, relation_id, fragment, line, symbol
    )


def _node_record(node: ArtifactNode) -> dict[str, Any]:
    return {
        "fragment": node.fragment,
        "kind": node.kind.value,
        "identity_sha256": node.identity_sha256,
        "identity_json": node.identity_json,
        "label": node.label,
        "node_id": node.node_id,
        "path": node.path,
        "provenance": node.provenance,
        "sha256": node.sha256,
        "stage_status": node.stage_status,
    }


def _edge_record(edge: ArtifactEdge) -> dict[str, Any]:
    return {
        "edge_id": edge.edge_id,
        "fragment": edge.fragment,
        "kind": edge.kind.value,
        "line": edge.line,
        "relation_id": edge.relation_id,
        "source": edge.source,
        "symbol": edge.symbol,
        "target": edge.target,
    }


def _finalize(snapshot_id: str, nodes: Iterable[ArtifactNode], edges: Iterable[ArtifactEdge]) -> ArtifactGraph:
    ordered_nodes = tuple(sorted(nodes, key=lambda item: item.node_id.encode()))
    ordered_edges = tuple(sorted(edges, key=lambda item: item.edge_id.encode()))
    identity = {
        "edges": [_edge_record(item) for item in ordered_edges],
        "nodes": [_node_record(item) for item in ordered_nodes],
        "schema": GRAPH_SCHEMA,
        "snapshot_id": snapshot_id,
    }
    identity_bytes = canonical_json(identity)
    graph = ArtifactGraph(
        GRAPH_SCHEMA,
        "artifact-graph:sha256:" + hashlib.sha256(identity_bytes).hexdigest(),
        snapshot_id,
        ordered_nodes,
        ordered_edges,
        identity_bytes,
    )
    validate_artifact_graph(graph)
    return graph


def build_artifact_graph(
    snapshot: Any,
    *,
    api_output: DoxygenNormalizedOutput | None = None,
    coverage_output: CoverageOutput | None = None,
    stage_results: Iterable[StageResult] = (),
    producer_logs: Iterable[ProducerLog] = (),
) -> ArtifactGraph:
    """Build a closed graph only from adapter-validated exact identities."""

    snapshot = _validate_snapshot(snapshot)
    snapshot_id = snapshot.snapshot_id
    snapshot_node = _node(
        NodeKind.SNAPSHOT,
        {"snapshot_id": snapshot_id},
        label=snapshot_id,
    )
    nodes: list[ArtifactNode] = [snapshot_node]
    edges: list[ArtifactEdge] = []

    source_by_path: dict[str, ArtifactNode] = {}
    for record in snapshot.files:
        if record.get("kind") != "file":
            continue
        source_path = _path(record.get("path"), field="snapshot file path")
        digest = record.get("identity", {}).get("sha256")
        source = _node(
            NodeKind.SOURCE_FILE,
            {"path": source_path, "sha256": digest, "snapshot_id": snapshot_id},
            label=source_path,
            path=source_path,
            sha256=digest,
        )
        if source_path in source_by_path:
            _fail("artifact_graph.duplicate_node_id", "duplicate source identity", source_path)
        source_by_path[source_path] = source
        nodes.append(source)
        edges.append(_edge(EdgeKind.DESCRIBES_SNAPSHOT, source.node_id, snapshot_node.node_id))

    stage_by_name: dict[str, ArtifactNode] = {}
    stage_status_by_name: dict[str, str] = {}
    for result in sorted(
        stage_results,
        key=lambda item: _stage_identifier(item.stage).encode(),
    ):
        _validate_stage_result(result)
        if result.snapshot_id != snapshot_id:
            _fail("artifact_graph.snapshot_mismatch", "stage result names another snapshot", result.stage)
        if result.stage in stage_by_name:
            _fail("artifact_graph.duplicate_node_id", "duplicate stage result", result.stage)
        stage = _node(
            NodeKind.STAGE_RESULT,
            {
                "digest": result.digest,
                "snapshot_id": snapshot_id,
                "stage": result.stage,
                "status": result.status.value,
            },
            label=result.stage,
            sha256=result.digest,
            stage_status=result.status.value,
        )
        stage_by_name[result.stage] = stage
        stage_status_by_name[result.stage] = result.status.value
        nodes.append(stage)
        edges.append(_edge(EdgeKind.DESCRIBES_SNAPSHOT, stage.node_id, snapshot_node.node_id))

    api_by_artifact: dict[str, ArtifactNode] = {}
    api_mapping_refids: set[tuple[str, str]] = set()
    api_mapping_targets: set[tuple[str, str, str, str]] = set()
    symbols_by_source_and_name: dict[tuple[str, str], list[ArtifactNode]] = {}
    documented_sources: set[tuple[str, str]] = set()
    if api_output is not None:
        if stage_status_by_name.get("doxygen") not in {None, "succeeded"}:
            _fail(
                "artifact_graph.stage_output_mismatch",
                "Doxygen output cannot be attributed to a non-succeeded Doxygen stage",
                "doxygen",
            )
        for artifact in api_output.artifacts:
            if artifact.schema != ARTIFACT_SCHEMA:
                _fail("artifact_graph.unsupported_schema", "API artifact schema is unsupported")
            if artifact.kind not in {"api-page", "producer-machine-output", "producer-asset"}:
                _fail("artifact_graph.unsupported_kind", "API artifact kind is unsupported", artifact.kind)
            if artifact.kind != "api-page":
                continue
            path = _path(artifact.path, field="API artifact path")
            if (
                not _valid_sha256(artifact.sha256)
                or not isinstance(artifact.size, str)
                or not artifact.size.isdecimal()
            ):
                _fail("artifact_graph.invalid_digest", "API artifact metadata is invalid", path)
            expected_artifact_id = "artifact:sha256:" + hashlib.sha256(
                canonical_json(
                    {"kind": "doxygen-payload", "path": path, "sha256": artifact.sha256}
                )
            ).hexdigest()
            if artifact.artifact_id != expected_artifact_id:
                _fail("artifact_graph.identity_mismatch", "API artifact identity is invalid", path)
            api = _node(
                NodeKind.API_PAGE,
                {
                    "adapter": ADAPTER_SELECTOR,
                    "artifact_id": artifact.artifact_id,
                    "path": "artifacts/api/" + path,
                    "provenance": "verified-current-snapshot",
                    "sha256": artifact.sha256,
                    "snapshot_id": snapshot_id,
                },
                label=path,
                path="artifacts/api/" + path,
                sha256=artifact.sha256,
                provenance="verified-current-snapshot",
            )
            if artifact.artifact_id in api_by_artifact:
                _fail("artifact_graph.duplicate_node_id", "duplicate API artifact identity", artifact.artifact_id)
            api_by_artifact[artifact.artifact_id] = api
            nodes.append(api)
            edges.append(_edge(EdgeKind.DESCRIBES_SNAPSHOT, api.node_id, snapshot_node.node_id))
            if "doxygen" in stage_by_name:
                edges.append(_edge(EdgeKind.GENERATED_BY_STAGE, api.node_id, stage_by_name["doxygen"].node_id))

        for mapping in api_output.mappings:
            if mapping.schema != MAPPING_SCHEMA:
                _fail("artifact_graph.unsupported_schema", "API mapping schema is unsupported")
            refid = _identity_text(mapping.refid, field="API mapping refid")
            mapping_key = (snapshot_id, refid)
            if mapping_key in api_mapping_refids:
                _fail(
                    "artifact_graph.duplicate_node_id",
                    "duplicate API mapping identity",
                    refid,
                )
            api_mapping_refids.add(mapping_key)
            _identity_text(mapping.entity_kind, field="API mapping entity kind")
            qualified_name = _identity_text(
                mapping.qualified_name, field="API mapping qualified name"
            )
            source_path = _path(mapping.source_path, field="API mapping source path")
            _identity_text(mapping.html_artifact_id, field="API mapping artifact identity")
            if (
                not isinstance(mapping.html_anchor, str)
                or unicodedata.normalize("NFC", mapping.html_anchor) != mapping.html_anchor
                or any(
                    unicodedata.category(character) == "Cc"
                    for character in mapping.html_anchor
                )
            ):
                _fail(
                    "artifact_graph.invalid_identity",
                    "API mapping anchor is not canonical",
                    refid,
                )
            for field, value in (("line", mapping.line), ("column", mapping.column)):
                if value is not None and (
                    not isinstance(value, str)
                    or not value.isdecimal()
                    or value == "0"
                    or (len(value) > 1 and value.startswith("0"))
                ):
                    _fail(
                        "artifact_graph.invalid_identity",
                        f"API mapping {field} is not a positive canonical decimal",
                        refid,
                    )
            if mapping.snapshot_id != snapshot_id:
                _fail("artifact_graph.snapshot_mismatch", "API mapping names another snapshot", refid)
            target_key = (
                source_path,
                qualified_name,
                mapping.html_artifact_id,
                mapping.html_anchor,
            )
            if target_key in api_mapping_targets:
                _fail(
                    "artifact_graph.duplicate_node_id",
                    "duplicate API semantic target",
                    refid,
                )
            api_mapping_targets.add(target_key)
            api = api_by_artifact.get(mapping.html_artifact_id)
            source = source_by_path.get(source_path)
            if api is None or source is None:
                _fail("artifact_graph.missing_endpoint", "API mapping endpoint is absent", refid)
            symbol = _node(
                NodeKind.SYMBOL,
                {
                    "adapter": ADAPTER_SELECTOR,
                    "column": mapping.column,
                    "entity_kind": mapping.entity_kind,
                    "refid": refid,
                    "html_artifact_id": mapping.html_artifact_id,
                    "label": qualified_name,
                    "line": mapping.line,
                    "path": api.path,
                    "fragment": mapping.html_anchor,
                    "snapshot_id": snapshot_id,
                    "source_path": source_path,
                },
                label=qualified_name,
                path=api.path,
                fragment=mapping.html_anchor,
            )
            nodes.append(symbol)
            symbols_by_source_and_name.setdefault(
                (source_path, qualified_name), []
            ).append(symbol)
            source_relation = (api.node_id, source.node_id)
            if source_relation not in documented_sources:
                edges.append(_edge(EdgeKind.DOCUMENTS_SOURCE, *source_relation))
                documented_sources.add(source_relation)
            edges.append(_edge(EdgeKind.DOCUMENTS_SYMBOL, api.node_id, symbol.node_id))

    coverage_by_artifact: dict[str, ArtifactNode] = {}
    if coverage_output is not None:
        if stage_status_by_name.get("coverage") not in {None, "succeeded"}:
            _fail(
                "artifact_graph.stage_output_mismatch",
                "coverage output cannot be attributed to a non-succeeded coverage stage",
                "coverage",
            )
        ordered_coverage = tuple(
            sorted(
                coverage_output.artifacts,
                key=lambda item: _path(
                    item.path, field="coverage artifact path"
                ).encode(),
            )
        )
        if coverage_output.artifacts != ordered_coverage:
            _fail("artifact_graph.noncanonical_order", "coverage artifacts are not ordered")
        report_entry_point = _path(
            coverage_output.entry_point, field="coverage report entry point"
        )
        entry_artifacts = [
            artifact for artifact in ordered_coverage if artifact.path == report_entry_point
        ]
        if len(entry_artifacts) != 1 or any(
            artifact.entry_point != (artifact.path == report_entry_point)
            for artifact in ordered_coverage
        ):
            _fail(
                "artifact_graph.identity_mismatch",
                "coverage entry-point declaration is inconsistent with its artifacts",
                report_entry_point,
            )
        coverage_entries: list[dict[str, str]] = []
        for artifact in ordered_coverage:
            path = _path(artifact.path, field="coverage artifact path")
            digest = hashlib.sha256(artifact.content).hexdigest()
            if artifact.sha256 != digest or artifact.size != len(artifact.content):
                _fail("artifact_graph.identity_mismatch", "coverage artifact bytes are inconsistent", path)
            coverage_entries.append(
                {"path": path, "sha256": digest, "size": str(len(artifact.content))}
            )
        expected_tree_digest = hashlib.sha256(
            canonical_json(
                {
                    "entries": coverage_entries,
                    "kind": "coverage-report-tree",
                    "schema": REPORT_TREE_SCHEMA_ID,
                }
            )
        ).hexdigest()
        if coverage_output.report_tree_sha256 != expected_tree_digest:
            _fail("artifact_graph.identity_mismatch", "coverage report-tree identity is invalid")
        for artifact in coverage_output.artifacts:
            path = _path(artifact.path, field="coverage artifact path")
            if artifact.entry_point:
                kind = NodeKind.COVERAGE_REPORT
            elif path.endswith(".html"):
                kind = NodeKind.COVERAGE_PAGE
            else:
                kind = NodeKind.COVERAGE_SUMMARY
            coverage = _node(
                kind,
                {
                    "adapter_schema": REPORT_TREE_SCHEMA_ID,
                    "artifact_id": artifact.artifact_id,
                    "entry_point": artifact.entry_point,
                    "path": "artifacts/coverage/" + path,
                    "provenance": coverage_output.provenance.value,
                    "report_entry_point": report_entry_point,
                    "report_tree_sha256": coverage_output.report_tree_sha256,
                    "sha256": artifact.sha256,
                    "snapshot_id": snapshot_id,
                },
                label=path,
                path="artifacts/coverage/" + path,
                sha256=artifact.sha256,
                provenance=coverage_output.provenance.value,
            )
            if artifact.artifact_id in coverage_by_artifact:
                _fail("artifact_graph.duplicate_node_id", "duplicate coverage artifact identity", artifact.artifact_id)
            coverage_by_artifact[artifact.artifact_id] = coverage
            nodes.append(coverage)
            edges.append(_edge(EdgeKind.DESCRIBES_SNAPSHOT, coverage.node_id, snapshot_node.node_id))
            if "coverage" in stage_by_name:
                edges.append(_edge(EdgeKind.GENERATED_BY_STAGE, coverage.node_id, stage_by_name["coverage"].node_id))

        for relation in coverage_output.relations:
            relation_identity = {
                "fragment": relation.fragment,
                "line": relation.line,
                "report_artifact_id": relation.report_artifact_id,
                "report_path": relation.report_path,
                "snapshot_id": snapshot_id,
                "source_path": relation.source_path,
                "symbol": relation.symbol,
            }
            expected_relation_id = "coverage-relation:sha256:" + hashlib.sha256(
                canonical_json(relation_identity)
            ).hexdigest()
            if relation.relation_id != expected_relation_id:
                _fail(
                    "artifact_graph.identity_mismatch",
                    "coverage relation identity is invalid",
                    relation.relation_id,
                )
            coverage = coverage_by_artifact.get(relation.report_artifact_id)
            source = source_by_path.get(relation.source_path)
            if coverage is None or source is None:
                _fail("artifact_graph.missing_endpoint", "coverage relation endpoint is absent", relation.relation_id)
            if coverage.path != "artifacts/coverage/" + relation.report_path:
                _fail(
                    "artifact_graph.identity_mismatch",
                    "coverage relation report path does not match its artifact",
                    relation.relation_id,
                )
            edges.append(
                _edge(
                    EdgeKind.COVERS_SOURCE,
                    coverage.node_id,
                    source.node_id,
                    relation_id=relation.relation_id,
                    fragment=relation.fragment,
                    line=relation.line,
                    symbol=relation.symbol,
                )
            )
            if relation.symbol is not None:
                candidates = symbols_by_source_and_name.get(
                    (relation.source_path, relation.symbol), []
                )
                if len(candidates) > 1:
                    _fail(
                        "artifact_graph.ambiguous_relation",
                        "coverage symbol resolves to more than one validated API identity",
                        relation.relation_id,
                    )
                if len(candidates) == 1:
                    edges.append(
                        _edge(
                            EdgeKind.COVERS_SYMBOL,
                            coverage.node_id,
                            candidates[0].node_id,
                            relation_id=relation.relation_id,
                            fragment=relation.fragment,
                            line=relation.line,
                            symbol=relation.symbol,
                        )
                    )

    for log in sorted(
        producer_logs,
        key=lambda item: (
            _identity_text(item.stage, field="producer log stage").encode(),
            _path(item.path, field="producer log path").encode(),
        ),
    ):
        stage = stage_by_name.get(log.stage)
        if stage is None:
            _fail("artifact_graph.missing_endpoint", "producer log has no stage result", log.stage)
        if stage.stage_status not in {
            StageStatus.SUCCEEDED.value,
            StageStatus.FAILED.value,
        }:
            _fail(
                "artifact_graph.stage_output_mismatch",
                "producer log requires an executed stage result",
                log.stage,
            )
        path = _path(log.path, field="producer log path")
        if not _valid_sha256(log.sha256):
            _fail("artifact_graph.invalid_digest", "producer log digest is invalid", path)
        if isinstance(log.size, bool) or not isinstance(log.size, int) or log.size < 0:
            _fail("artifact_graph.invalid_size", "producer log size is invalid", path)
        log_node = _node(
            NodeKind.PRODUCER_LOG,
            {
                "path": path,
                "sha256": log.sha256,
                "size": str(log.size),
                "snapshot_id": snapshot_id,
                "stage": log.stage,
                "stage_node_id": stage.node_id,
            },
            label=path,
            path="artifacts/logs/" + path,
            sha256=log.sha256,
        )
        nodes.append(log_node)
        edges.append(_edge(EdgeKind.HAS_LOG, stage.node_id, log_node.node_id))
        edges.append(_edge(EdgeKind.DESCRIBES_SNAPSHOT, log_node.node_id, snapshot_node.node_id))

    if len(edges) != len({edge.edge_id for edge in edges}):
        _fail("artifact_graph.duplicate_edge_id", "duplicate edge identity")
    return _finalize(snapshot_id, nodes, edges)


def add_rendered_navigation(
    graph: ArtifactGraph,
    artifacts: Iterable[RenderedNavigationArtifact],
) -> ArtifactGraph:
    """Return a new graph binding exact navigation files to the nodes they expose."""

    validate_artifact_graph(graph)
    if any(node.kind is NodeKind.RENDERED_NAVIGATION_ARTIFACT for node in graph.nodes):
        _fail(
            "artifact_graph.navigation_already_present",
            "graph already contains rendered navigation artifacts",
        )
    nodes = list(graph.nodes)
    edges = list(graph.edges)
    by_id = {node.node_id for node in graph.nodes}
    snapshot = next(node for node in graph.nodes if node.kind is NodeKind.SNAPSHOT)
    seen_paths: set[str] = set()
    for artifact in sorted(
        artifacts,
        key=lambda item: _path(
            item.path, field="rendered navigation path"
        ).encode(),
    ):
        path = _path(artifact.path, field="rendered navigation path")
        if not isinstance(artifact.target_ids, tuple):
            _fail(
                "artifact_graph.invalid_identity",
                "rendered navigation targets must be a tuple",
                path,
            )
        if path in seen_paths:
            _fail("artifact_graph.duplicate_node_id", "duplicate rendered navigation path", path)
        seen_paths.add(path)
        if (
            isinstance(artifact.size, bool)
            or not isinstance(artifact.size, int)
            or artifact.size < 0
        ):
            _fail("artifact_graph.invalid_size", "rendered navigation size is invalid", path)
        if not _valid_sha256(artifact.sha256):
            _fail("artifact_graph.invalid_digest", "rendered navigation digest is invalid", path)
        navigation = _node(
            NodeKind.RENDERED_NAVIGATION_ARTIFACT,
            {
                "base_graph_id": graph.graph_id,
                "path": path,
                "sha256": artifact.sha256,
                "size": str(artifact.size),
                "snapshot_id": graph.snapshot_id,
            },
            label=path,
            path=path,
            sha256=artifact.sha256,
        )
        nodes.append(navigation)
        edges.append(
            _edge(EdgeKind.DESCRIBES_SNAPSHOT, navigation.node_id, snapshot.node_id)
        )
        targets = tuple(
            sorted(
                (
                    _identity_text(target, field="rendered navigation target")
                    for target in artifact.target_ids
                ),
                key=str.encode,
            )
        )
        if len(targets) != len(set(targets)):
            _fail("artifact_graph.duplicate_edge_id", "duplicate navigation target", path)
        for target in targets:
            if target not in by_id:
                _fail("artifact_graph.missing_endpoint", "navigation target is absent", target)
            edges.append(_edge(EdgeKind.LINKS_TO, navigation.node_id, target))
    return _finalize(graph.snapshot_id, nodes, edges)


_EDGE_ENDPOINTS: dict[EdgeKind, tuple[frozenset[NodeKind], frozenset[NodeKind]]] = {
    EdgeKind.DESCRIBES_SNAPSHOT: (
        frozenset(NodeKind) - {NodeKind.SNAPSHOT},
        frozenset({NodeKind.SNAPSHOT}),
    ),
    EdgeKind.GENERATED_BY_STAGE: (
        frozenset(
            {
                NodeKind.API_PAGE,
                NodeKind.COVERAGE_REPORT,
                NodeKind.COVERAGE_PAGE,
                NodeKind.COVERAGE_SUMMARY,
                NodeKind.PRODUCER_LOG,
            }
        ),
        frozenset({NodeKind.STAGE_RESULT}),
    ),
    EdgeKind.DOCUMENTS_SOURCE: (
        frozenset({NodeKind.API_PAGE}),
        frozenset({NodeKind.SOURCE_FILE}),
    ),
    EdgeKind.DOCUMENTS_SYMBOL: (
        frozenset({NodeKind.API_PAGE}),
        frozenset({NodeKind.SYMBOL}),
    ),
    EdgeKind.COVERS_SOURCE: (
        frozenset({NodeKind.COVERAGE_REPORT, NodeKind.COVERAGE_PAGE, NodeKind.COVERAGE_SUMMARY}),
        frozenset({NodeKind.SOURCE_FILE}),
    ),
    EdgeKind.COVERS_SYMBOL: (
        frozenset({NodeKind.COVERAGE_REPORT, NodeKind.COVERAGE_PAGE, NodeKind.COVERAGE_SUMMARY}),
        frozenset({NodeKind.SYMBOL}),
    ),
    EdgeKind.HAS_LOG: (
        frozenset({NodeKind.STAGE_RESULT}),
        frozenset({NodeKind.PRODUCER_LOG}),
    ),
    EdgeKind.LINKS_TO: (
        frozenset({NodeKind.RENDERED_NAVIGATION_ARTIFACT}),
        frozenset(NodeKind) - {NodeKind.RENDERED_NAVIGATION_ARTIFACT},
    ),
}


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _base_graph_id(graph: ArtifactGraph) -> str:
    nodes = tuple(
        node for node in graph.nodes if node.kind is not NodeKind.RENDERED_NAVIGATION_ARTIFACT
    )
    node_ids = {node.node_id for node in nodes}
    edges = tuple(
        edge for edge in graph.edges if edge.source in node_ids and edge.target in node_ids
    )
    content = canonical_json(
        {
            "edges": [_edge_record(item) for item in edges],
            "nodes": [_node_record(item) for item in nodes],
            "schema": GRAPH_SCHEMA,
            "snapshot_id": graph.snapshot_id,
        }
    )
    return "artifact-graph:sha256:" + hashlib.sha256(content).hexdigest()


def _expected_node_identity(
    node: ArtifactNode,
    identity: dict[str, Any],
    graph: ArtifactGraph,
    by_id: dict[str, ArtifactNode],
) -> dict[str, Any]:
    """Reconstruct a node identity from its typed semantic fields and adapter contracts."""

    if node.kind is NodeKind.SNAPSHOT:
        expected = {"snapshot_id": graph.snapshot_id}
        if any(
            value is not None
            for value in (
                node.path,
                node.fragment,
                node.sha256,
                node.provenance,
                node.stage_status,
            )
        ):
            _fail("artifact_graph.identity_mismatch", "snapshot node has invalid fields", node.node_id)
        return expected

    if not _valid_sha256(node.sha256) and node.kind not in {NodeKind.SYMBOL}:
        _fail("artifact_graph.invalid_digest", "node digest is invalid", node.node_id)

    if node.kind is NodeKind.SOURCE_FILE:
        if (
            node.path is None
            or node.label != node.path
            or node.fragment is not None
            or node.provenance is not None
            or node.stage_status is not None
        ):
            _fail("artifact_graph.identity_mismatch", "source fields are inconsistent", node.node_id)
        _path(node.path, field="source node path")
        return {"path": node.path, "sha256": node.sha256, "snapshot_id": graph.snapshot_id}

    if node.kind is NodeKind.STAGE_RESULT:
        _stage_identifier(node.label, field="stage-result label")
        if (
            node.sha256 is None
            or node.stage_status not in {status.value for status in StageStatus}
            or node.path is not None
            or node.fragment is not None
            or node.provenance is not None
        ):
            _fail("artifact_graph.identity_mismatch", "stage fields are incomplete", node.node_id)
        return {
            "digest": node.sha256,
            "snapshot_id": graph.snapshot_id,
            "stage": node.label,
            "status": node.stage_status,
        }

    if node.kind is NodeKind.API_PAGE:
        if node.path is None or not node.path.startswith("artifacts/api/"):
            _fail("artifact_graph.identity_mismatch", "API path is invalid", node.node_id)
        relative = _path(node.path.removeprefix("artifacts/api/"), field="API node path")
        artifact_id = "artifact:sha256:" + hashlib.sha256(
            canonical_json({"kind": "doxygen-payload", "path": relative, "sha256": node.sha256})
        ).hexdigest()
        if (
            node.label != relative
            or node.provenance != "verified-current-snapshot"
            or node.fragment is not None
            or node.stage_status is not None
        ):
            _fail("artifact_graph.identity_mismatch", "API fields are inconsistent", node.node_id)
        return {
            "adapter": ADAPTER_SELECTOR,
            "artifact_id": artifact_id,
            "path": node.path,
            "provenance": node.provenance,
            "sha256": node.sha256,
            "snapshot_id": graph.snapshot_id,
        }

    if node.kind is NodeKind.SYMBOL:
        required = {
            "adapter",
            "column",
            "entity_kind",
            "fragment",
            "html_artifact_id",
            "label",
            "line",
            "path",
            "refid",
            "snapshot_id",
            "source_path",
        }
        if set(identity) != required or identity.get("adapter") != ADAPTER_SELECTOR:
            _fail("artifact_graph.identity_mismatch", "symbol identity schema is invalid", node.node_id)
        if node.sha256 is not None or node.provenance is not None or node.stage_status is not None:
            _fail("artifact_graph.identity_mismatch", "symbol fields are inconsistent", node.node_id)
        _identity_text(identity.get("entity_kind"), field="symbol entity kind")
        _identity_text(identity.get("refid"), field="symbol refid")
        _identity_text(identity.get("html_artifact_id"), field="symbol API artifact identity")
        _identity_text(node.label, field="symbol label")
        if (
            not isinstance(node.fragment, str)
            or unicodedata.normalize("NFC", node.fragment) != node.fragment
            or any(
                unicodedata.category(character) == "Cc"
                for character in node.fragment
            )
        ):
            _fail(
                "artifact_graph.identity_mismatch",
                "symbol fragment is not canonical",
                node.node_id,
            )
        for field in ("line", "column"):
            value = identity.get(field)
            if value is not None and (
                not isinstance(value, str)
                or not value.isdecimal()
                or value == "0"
                or (len(value) > 1 and value.startswith("0"))
            ):
                _fail(
                    "artifact_graph.identity_mismatch",
                    f"symbol {field} is not a positive canonical decimal",
                    node.node_id,
                )
        source_path = identity["source_path"]
        if not isinstance(source_path, str):
            _fail("artifact_graph.identity_mismatch", "symbol source path is invalid", node.node_id)
        _path(source_path, field="symbol source path")
        sources = [candidate for candidate in by_id.values() if candidate.kind is NodeKind.SOURCE_FILE and candidate.path == source_path]
        apis = [candidate for candidate in by_id.values() if candidate.kind is NodeKind.API_PAGE and candidate.path == node.path]
        if len(sources) != 1 or len(apis) != 1:
            _fail("artifact_graph.missing_endpoint", "symbol semantic endpoint is absent", node.node_id)
        api_identity = json.loads(apis[0].identity_json or "{}").get("identity", {})
        if identity.get("html_artifact_id") != api_identity.get("artifact_id"):
            _fail("artifact_graph.identity_mismatch", "symbol API identity is inconsistent", node.node_id)
        expected = dict(identity)
        expected.update(
            {
                "adapter": ADAPTER_SELECTOR,
                "fragment": node.fragment,
                "html_artifact_id": api_identity.get("artifact_id"),
                "label": node.label,
                "path": node.path,
                "snapshot_id": graph.snapshot_id,
                "source_path": source_path,
            }
        )
        return expected

    if node.kind in {
        NodeKind.COVERAGE_REPORT,
        NodeKind.COVERAGE_PAGE,
        NodeKind.COVERAGE_SUMMARY,
    }:
        if node.path is None or not node.path.startswith("artifacts/coverage/"):
            _fail("artifact_graph.identity_mismatch", "coverage path is invalid", node.node_id)
        relative = _path(node.path.removeprefix("artifacts/coverage/"), field="coverage node path")
        tree_digest = identity.get("report_tree_sha256")
        if not _valid_sha256(tree_digest):
            _fail("artifact_graph.invalid_digest", "coverage tree digest is invalid", node.node_id)
        artifact_id = "coverage-artifact:sha256:" + hashlib.sha256(
            canonical_json({"path": relative, "report_tree_sha256": tree_digest})
        ).hexdigest()
        report_entry_point = identity.get("report_entry_point")
        if not isinstance(report_entry_point, str):
            _fail("artifact_graph.identity_mismatch", "coverage report entry point is invalid", node.node_id)
        report_entry_point = _path(
            report_entry_point, field="coverage report entry point"
        )
        entry_point = relative == report_entry_point
        if identity.get("entry_point") is not entry_point:
            _fail("artifact_graph.identity_mismatch", "coverage entry-point flag is invalid", node.node_id)
        expected_kind = (
            NodeKind.COVERAGE_REPORT
            if entry_point
            else NodeKind.COVERAGE_PAGE
            if relative.endswith(".html")
            else NodeKind.COVERAGE_SUMMARY
        )
        if (
            node.kind is not expected_kind
            or
            node.label != relative
            or node.provenance not in {state.value for state in CoverageProvenance}
            or node.fragment is not None
            or node.stage_status is not None
        ):
            _fail("artifact_graph.identity_mismatch", "coverage fields are inconsistent", node.node_id)
        return {
            "adapter_schema": REPORT_TREE_SCHEMA_ID,
            "artifact_id": artifact_id,
            "entry_point": entry_point,
            "path": node.path,
            "provenance": node.provenance,
            "report_entry_point": report_entry_point,
            "report_tree_sha256": tree_digest,
            "sha256": node.sha256,
            "snapshot_id": graph.snapshot_id,
        }

    if node.kind is NodeKind.PRODUCER_LOG:
        required = {"path", "sha256", "size", "snapshot_id", "stage", "stage_node_id"}
        if (
            set(identity) != required
            or node.path is None
            or not node.path.startswith("artifacts/logs/")
            or node.fragment is not None
            or node.provenance is not None
            or node.stage_status is not None
        ):
            _fail("artifact_graph.identity_mismatch", "producer log identity schema is invalid", node.node_id)
        relative = _path(node.path.removeprefix("artifacts/logs/"), field="producer log node path")
        if node.label != relative:
            _fail("artifact_graph.identity_mismatch", "producer log label is invalid", node.node_id)
        stage_node_id = identity.get("stage_node_id")
        stage = by_id.get(stage_node_id) if isinstance(stage_node_id, str) else None
        if stage is None or stage.kind is not NodeKind.STAGE_RESULT or stage.label != identity.get("stage"):
            _fail("artifact_graph.missing_endpoint", "producer log stage is absent", node.node_id)
        size = identity.get("size")
        if not isinstance(size, str) or not size.isdecimal():
            _fail("artifact_graph.invalid_size", "producer log size is invalid", node.node_id)
        return {
            "path": relative,
            "sha256": node.sha256,
            "size": size,
            "snapshot_id": graph.snapshot_id,
            "stage": stage.label,
            "stage_node_id": stage.node_id,
        }

    if node.kind is NodeKind.RENDERED_NAVIGATION_ARTIFACT:
        required = {"base_graph_id", "path", "sha256", "size", "snapshot_id"}
        if (
            set(identity) != required
            or node.path is None
            or node.label != node.path
            or node.fragment is not None
            or node.provenance is not None
            or node.stage_status is not None
        ):
            _fail("artifact_graph.identity_mismatch", "navigation identity schema is invalid", node.node_id)
        _path(node.path, field="navigation node path")
        size = identity.get("size")
        if not isinstance(size, str) or not size.isdecimal():
            _fail("artifact_graph.invalid_size", "navigation size is invalid", node.node_id)
        return {
            "base_graph_id": _base_graph_id(graph),
            "path": node.path,
            "sha256": node.sha256,
            "size": size,
            "snapshot_id": graph.snapshot_id,
        }

    _fail("artifact_graph.invalid_node_kind", "node kind is not recognized", node.node_id)


def validate_artifact_graph(graph: ArtifactGraph) -> None:
    """Validate closure, ordering, endpoint existence, and edge typing."""

    if graph.schema != GRAPH_SCHEMA:
        _fail("artifact_graph.unsupported_schema", f"schema must be {GRAPH_SCHEMA}")
    if not _valid_snapshot_id(graph.snapshot_id):
        _fail(
            "artifact_graph.invalid_identity",
            "graph snapshot identifier is invalid",
            str(graph.snapshot_id),
        )
    node_ids = [node.node_id for node in graph.nodes]
    if len(node_ids) != len(set(node_ids)):
        _fail("artifact_graph.duplicate_node_id", "node identifiers are not unique")
    if node_ids != sorted(node_ids, key=str.encode):
        _fail("artifact_graph.noncanonical_order", "nodes are not canonically ordered")
    edge_ids = [edge.edge_id for edge in graph.edges]
    if len(edge_ids) != len(set(edge_ids)):
        _fail("artifact_graph.duplicate_edge_id", "edge identifiers are not unique")
    if edge_ids != sorted(edge_ids, key=str.encode):
        _fail("artifact_graph.noncanonical_order", "edges are not canonically ordered")

    for node in graph.nodes:
        if not isinstance(node.kind, NodeKind):
            _fail("artifact_graph.invalid_node_kind", "node kind is not recognized", node.node_id)
    for edge in graph.edges:
        if not isinstance(edge.kind, EdgeKind):
            _fail("artifact_graph.invalid_edge_kind", "edge kind is not recognized", edge.edge_id)

    by_id = {node.node_id: node for node in graph.nodes}
    snapshots = [node for node in graph.nodes if node.kind is NodeKind.SNAPSHOT]
    if len(snapshots) != 1:
        _fail("artifact_graph.snapshot_cardinality", "graph must contain exactly one snapshot node")
    for edge in graph.edges:
        source = by_id.get(edge.source)
        target = by_id.get(edge.target)
        if source is None or target is None:
            _fail("artifact_graph.missing_endpoint", "edge endpoint is absent", edge.edge_id)
        allowed_source, allowed_target = _EDGE_ENDPOINTS[edge.kind]
        if source.kind not in allowed_source or target.kind not in allowed_target:
            _fail("artifact_graph.invalid_edge_kind", "edge kind is invalid for its endpoint kinds", edge.edge_id)

    snapshot = snapshots[0]
    if snapshot.label != graph.snapshot_id:
        _fail(
            "artifact_graph.identity_mismatch",
            "snapshot node is not bound to graph.snapshot_id",
            snapshot.node_id,
        )
    for node in graph.nodes:
        if node.identity_json is None:
            _fail(
                "artifact_graph.identity_mismatch",
                "node lacks its canonical identity preimage",
                node.node_id,
            )
        try:
            identity_preimage = json.loads(node.identity_json)
            identity_bytes = canonical_json(identity_preimage)
        except (TypeError, ValueError, RecursionError):
            _fail(
                "artifact_graph.identity_mismatch",
                "node identity preimage is not canonical JSON",
                node.node_id,
            )
        if (
            identity_bytes.decode("utf-8") != node.identity_json
            or not isinstance(identity_preimage, dict)
            or set(identity_preimage) != {"identity", "kind"}
            or identity_preimage["kind"] != node.kind.value
            or not isinstance(identity_preimage["identity"], dict)
        ):
            _fail(
                "artifact_graph.identity_mismatch",
                "node identity preimage does not match its kind",
                node.node_id,
            )
        expected_identity_sha256 = hashlib.sha256(identity_bytes).hexdigest()
        expected_node_id = f"{node.kind.value}:sha256:{expected_identity_sha256}"
        if node.identity_sha256 != expected_identity_sha256:
            _fail(
                "artifact_graph.identity_mismatch",
                "node identity digest does not match its preimage",
                node.node_id,
            )
        if node.kind is NodeKind.SNAPSHOT and identity_preimage["identity"] != {
            "snapshot_id": graph.snapshot_id
        }:
            _fail(
                "artifact_graph.identity_mismatch",
                "snapshot identity preimage is not bound to graph.snapshot_id",
                node.node_id,
            )
        if node.kind is not NodeKind.SNAPSHOT and identity_preimage["identity"].get(
            "snapshot_id"
        ) != graph.snapshot_id:
            _fail(
                "artifact_graph.identity_mismatch",
                "node identity preimage is not scoped to graph.snapshot_id",
                node.node_id,
            )
        expected_identity = _expected_node_identity(
            node, identity_preimage["identity"], graph, by_id
        )
        if identity_preimage["identity"] != expected_identity:
            _fail(
                "artifact_graph.identity_mismatch",
                "node identity preimage does not match typed semantic fields",
                node.node_id,
            )
        if node.node_id != expected_node_id:
            _fail(
                "artifact_graph.identity_mismatch",
                "node identifier does not match its committed identity",
                node.node_id,
            )
    symbols = [node for node in graph.nodes if node.kind is NodeKind.SYMBOL]
    symbol_identities = [
        json.loads(node.identity_json or "{}")["identity"] for node in symbols
    ]
    symbol_refids = [
        (identity["snapshot_id"], identity["refid"]) for identity in symbol_identities
    ]
    if len(symbol_refids) != len(set(symbol_refids)):
        _fail(
            "artifact_graph.duplicate_node_id",
            "Doxygen mapping identities are not unique",
        )
    symbol_targets = [
        (
            identity["source_path"],
            identity["label"],
            identity["html_artifact_id"],
            identity["fragment"],
        )
        for identity in symbol_identities
    ]
    if len(symbol_targets) != len(set(symbol_targets)):
        _fail(
            "artifact_graph.duplicate_node_id",
            "Doxygen semantic targets are not unique",
        )
    coverage_nodes = [
        node
        for node in graph.nodes
        if node.kind
        in {
            NodeKind.COVERAGE_REPORT,
            NodeKind.COVERAGE_PAGE,
            NodeKind.COVERAGE_SUMMARY,
        }
    ]
    if coverage_nodes:
        report_entry_points = {
            json.loads(node.identity_json or "{}")["identity"]["report_entry_point"]
            for node in coverage_nodes
        }
        report_tree_digests = {
            json.loads(node.identity_json or "{}")["identity"]["report_tree_sha256"]
            for node in coverage_nodes
        }
        reports = [node for node in coverage_nodes if node.kind is NodeKind.COVERAGE_REPORT]
        if (
            len(report_entry_points) != 1
            or len(report_tree_digests) != 1
            or len(reports) != 1
            or reports[0].path
            != "artifacts/coverage/" + next(iter(report_entry_points))
        ):
            _fail(
                "artifact_graph.identity_mismatch",
                "coverage graph does not have one coherent report entry point",
            )
    for edge in graph.edges:
        relation_edge = edge.kind in {EdgeKind.COVERS_SOURCE, EdgeKind.COVERS_SYMBOL}
        if relation_edge:
            if (
                not isinstance(edge.relation_id, str)
                or not edge.relation_id.startswith("coverage-relation:sha256:")
                or not _valid_sha256(edge.relation_id.removeprefix("coverage-relation:sha256:"))
            ):
                _fail(
                    "artifact_graph.invalid_relation",
                    "coverage edge relation identity is invalid",
                    edge.edge_id,
                )
            if edge.fragment is not None:
                _identity_text(edge.fragment, field="coverage relation fragment")
            if edge.symbol is not None:
                _identity_text(edge.symbol, field="coverage relation symbol")
            if edge.line is not None and (
                isinstance(edge.line, bool) or not isinstance(edge.line, int) or edge.line < 1
            ):
                _fail(
                    "artifact_graph.invalid_relation",
                    "coverage relation line is invalid",
                    edge.edge_id,
                )
            report = by_id[edge.source]
            report_identity = json.loads(report.identity_json or "{}").get("identity", {})
            if report.path is None or not report.path.startswith("artifacts/coverage/"):
                _fail("artifact_graph.invalid_relation", "coverage report path is invalid", edge.edge_id)
            target = by_id[edge.target]
            if edge.kind is EdgeKind.COVERS_SOURCE:
                source_path = target.path
            else:
                symbol_identity = json.loads(target.identity_json or "{}").get("identity", {})
                source_path = symbol_identity.get("source_path")
                if edge.symbol != target.label:
                    _fail(
                        "artifact_graph.invalid_relation",
                        "coverage symbol edge does not identify its target symbol",
                        edge.edge_id,
                    )
            native_identity = {
                "fragment": edge.fragment,
                "line": edge.line,
                "report_artifact_id": report_identity.get("artifact_id"),
                "report_path": report.path.removeprefix("artifacts/coverage/"),
                "snapshot_id": graph.snapshot_id,
                "source_path": source_path,
                "symbol": edge.symbol,
            }
            expected_relation_id = "coverage-relation:sha256:" + hashlib.sha256(
                canonical_json(native_identity)
            ).hexdigest()
            if edge.relation_id != expected_relation_id:
                _fail(
                    "artifact_graph.invalid_relation",
                    "coverage edge metadata does not match its native relation identity",
                    edge.edge_id,
                )
        elif (
            edge.relation_id is not None
            or edge.fragment is not None
            or edge.line is not None
            or edge.symbol is not None
        ):
            _fail(
                "artifact_graph.invalid_relation",
                "structural edge carries relation metadata",
                edge.edge_id,
            )
        expected_edge_id = _identifier(
            "edge",
            {
                "fragment": edge.fragment,
                "kind": edge.kind.value,
                "line": edge.line,
                "relation_id": edge.relation_id,
                "source": edge.source,
                "symbol": edge.symbol,
                "target": edge.target,
            },
        )
        if edge.edge_id != expected_edge_id:
            _fail(
                "artifact_graph.identity_mismatch",
                "edge identifier does not match its endpoints",
                edge.edge_id,
            )
    expected_identity_bytes = canonical_json(
        {
            "edges": [_edge_record(item) for item in graph.edges],
            "nodes": [_node_record(item) for item in graph.nodes],
            "schema": GRAPH_SCHEMA,
            "snapshot_id": graph.snapshot_id,
        }
    )
    expected_graph_id = (
        "artifact-graph:sha256:"
        + hashlib.sha256(expected_identity_bytes).hexdigest()
    )
    if graph.identity_bytes != expected_identity_bytes or graph.graph_id != expected_graph_id:
        _fail(
            "artifact_graph.identity_mismatch",
            "graph identity does not match canonical graph content",
            graph.graph_id,
        )
