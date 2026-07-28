"""Byte-preserving ingestion of independently mapped coverage report trees."""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, NoReturn

from .adapters import CapabilityRequirements, DeclarativeStagePlan, Diagnostic
from .configuration import ConfigurationError, _overrides, canonical_json, parse_json
from .snapshot import GitSnapshot

MAP_SCHEMA_ID = "osqar.inspector.coverage-map.v1"
ATTESTATION_SCHEMA_ID = "osqar.inspector.coverage-attestation.v1"
REPORT_TREE_SCHEMA_ID = "osqar.inspector.coverage-report-tree.v1"
_HEX = frozenset("0123456789abcdef")


@dataclass
class CoverageError(ValueError):
    """A stable fail-closed coverage-ingestion error."""

    code: str
    message: str
    path: str | None = None

    def __str__(self) -> str:
        suffix = f" ({self.path})" if self.path is not None else ""
        return f"{self.code}: {self.message}{suffix}"


class CoverageProvenance(str, Enum):
    VERIFIED_CURRENT_SNAPSHOT = "verified-current-snapshot"
    EXTERNALLY_ATTESTED = "externally-attested"
    UNKNOWN_ORIGIN = "unknown-origin"


@dataclass(frozen=True)
class CoverageArtifact:
    artifact_id: str
    path: str
    sha256: str
    size: int
    content: bytes
    entry_point: bool


@dataclass(frozen=True)
class CoverageSidecarArtifact:
    artifact_id: str
    kind: str
    path: str
    sha256: str
    size: int
    content: bytes


@dataclass(frozen=True)
class CoverageRelation:
    relation_id: str
    report_artifact_id: str
    report_path: str
    fragment: str | None
    source_path: str
    line: int | None
    symbol: str | None


@dataclass(frozen=True)
class CoverageOutput:
    entry_point: str
    report_tree_sha256: str
    artifacts: tuple[CoverageArtifact, ...]
    sidecars: tuple[CoverageSidecarArtifact, ...]
    relations: tuple[CoverageRelation, ...]
    provenance: CoverageProvenance
    mapping_valid: bool
    attestation_valid: bool
    diagnostics: tuple[str, ...]


def _fail(code: str, message: str, path: str | None = None) -> NoReturn:
    raise CoverageError(code, message, path)


def _path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("coverage.invalid_path", f"{field} must be a non-empty relative path")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _fail("coverage.invalid_path", f"{field} is not valid UTF-8", value)
    if (
        value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _fail("coverage.invalid_path", f"{field} escapes or violates the v1 path profile", value)
    return value


def _closed(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("coverage.invalid_sidecar", f"{field} must contain exactly {sorted(keys)}")
    return value


def _identity(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        _fail("coverage.invalid_sidecar", f"{field} must be a non-empty identity string")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        _fail("coverage.invalid_sidecar", f"{field} must be a lowercase SHA-256 digest")
    return value


def _configuration_identity_digest(value: Any) -> str:
    def identity_object(raw: Any, keys: set[str], field: str) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != keys:
            _fail(
                "coverage.invalid_configuration_identity",
                f"{field} must contain exactly {sorted(keys)}",
            )
        return raw

    identity = identity_object(
        value,
        {"controlled_input", "defaults", "overrides", "resolved", "schema"},
        "configuration identity",
    )
    controlled = identity_object(
        identity["controlled_input"], {"path", "sha256", "size"}, "controlled_input"
    )
    _path(controlled["path"], field="configuration_identity.controlled_input.path")
    _digest(controlled["sha256"], "configuration_identity.controlled_input.sha256")
    size = controlled["size"]
    if not isinstance(size, str) or not size or (size != "0" and (size[0] == "0" or not size.isdecimal())):
        _fail(
            "coverage.invalid_configuration_identity",
            "controlled_input.size must be a canonical decimal byte count",
        )
    defaults = identity_object(identity["defaults"], {"id", "sha256"}, "defaults")
    _identity(defaults["id"], "configuration_identity.defaults.id")
    _digest(defaults["sha256"], "configuration_identity.defaults.sha256")
    resolved = identity_object(identity["resolved"], {"sha256"}, "resolved")
    _digest(resolved["sha256"], "configuration_identity.resolved.sha256")
    schema = identity_object(identity["schema"], {"id", "sha256"}, "schema")
    if schema["id"] != "osqar.inspector.config.v1":
        _fail(
            "coverage.invalid_configuration_identity",
            "configuration identity has an unsupported schema identifier",
        )
    _digest(schema["sha256"], "configuration_identity.schema.sha256")
    overrides = identity["overrides"]
    if not isinstance(overrides, list):
        _fail("coverage.invalid_configuration_identity", "overrides must be an array")
    for index, override in enumerate(overrides):
        record = identity_object(override, {"pointer", "value"}, f"overrides[{index}]")
        _identity(record["pointer"], f"configuration_identity.overrides[{index}].pointer")
    try:
        accepted_overrides = _overrides(overrides)
        canonical_overrides = [
            {"pointer": pointer, "value": override_value}
            for pointer, _, override_value in accepted_overrides
        ]
        if canonical_json(overrides) != canonical_json(canonical_overrides):
            _fail(
                "coverage.invalid_configuration_identity",
                "overrides must be sorted in canonical JSON Pointer order",
            )
        return hashlib.sha256(canonical_json(identity)).hexdigest()
    except ConfigurationError:
        _fail(
            "coverage.invalid_configuration_identity",
            "configuration identity contains invalid override data or is not canonicalizable",
        )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular(
    root: Path, relative_path: str, *, display_path: str | None = None
) -> bytes:
    logical_path = display_path or relative_path
    directory_descriptors: list[int] = []
    descriptor: int | None = None
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        current_directory = os.open(root, directory_flags)
        directory_descriptors.append(current_directory)
        components = PurePosixPath(relative_path).parts
        if not components:
            _fail("coverage.input_unreadable", "coverage input must name a file", logical_path)
        for component in components[:-1]:
            current_directory = os.open(
                component,
                directory_flags,
                dir_fd=current_directory,
            )
            directory_descriptors.append(current_directory)
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=current_directory,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail("coverage.unsupported_entry", "coverage inputs must be regular files", logical_path)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read()
        after = os.fstat(descriptor)
        path_after = os.stat(
            components[-1], dir_fd=current_directory, follow_symlinks=False
        )
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or _metadata_identity(after) != _metadata_identity(path_after)
            or len(content) != after.st_size
        ):
            _fail("coverage.input_changed", "coverage input changed while it was read", logical_path)
        return content
    except CoverageError:
        raise
    except OSError as error:
        _fail("coverage.input_unreadable", str(error), logical_path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)


def _rooted_path(root: Path, logical_path: str) -> Path:
    """Resolve a lexical input path without permitting symlinked ancestors."""
    current = root
    components = PurePosixPath(logical_path).parts
    try:
        root_metadata = current.lstat()
        if stat.S_ISLNK(root_metadata.st_mode):
            _fail("coverage.path_symlink", "ingestion input root must not be a symlink")
        if not stat.S_ISDIR(root_metadata.st_mode):
            _fail("coverage.input_unreadable", "ingestion input root must be a directory")
        for index, component in enumerate(components):
            current /= component
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                _fail(
                    "coverage.path_symlink",
                    "coverage input paths must not contain symlinks",
                    "/".join(components[: index + 1]),
                )
            if index < len(components) - 1 and not stat.S_ISDIR(metadata.st_mode):
                _fail(
                    "coverage.input_unreadable",
                    "coverage input path ancestor is not a directory",
                    "/".join(components[: index + 1]),
                )
        return current
    except CoverageError:
        raise
    except OSError as error:
        _fail("coverage.input_unreadable", str(error), logical_path)


def _scan_report_tree(
    report_root: Path,
) -> tuple[tuple[str, Path, tuple[int, int, int, int, int, int]], ...]:
    try:
        root_stat = report_root.lstat()
    except OSError as error:
        _fail("coverage.report_unreadable", str(error))
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        _fail("coverage.report_not_directory", "configured report parent must be a real directory")

    files: list[tuple[str, Path, tuple[int, int, int, int, int, int]]] = []
    pending: list[tuple[Path, str]] = [(report_root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            _fail("coverage.report_unreadable", str(error), prefix or None)
        for entry in entries:
            logical = f"{prefix}/{entry.name}" if prefix else entry.name
            _path(logical, field="report path")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                _fail("coverage.report_unreadable", str(error), logical)
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((Path(entry.path), logical))
            elif stat.S_ISREG(metadata.st_mode):
                files.append((logical, Path(entry.path), _metadata_identity(metadata)))
            else:
                _fail("coverage.unsupported_entry", "report tree permits directories and regular files only", logical)

    files.sort(key=lambda item: item[0].encode())
    return tuple(files)


def _inventory(
    input_root: Path, report_root_logical: PurePosixPath, entry_point: str
) -> tuple[tuple[CoverageArtifact, ...], str]:
    report_root = _rooted_path(input_root, report_root_logical.as_posix())
    before = _scan_report_tree(report_root)
    if not before:
        _fail("coverage.empty_report", "report tree contains no files")
    payloads = [
        (
            logical,
            _read_regular(
                input_root,
                (report_root_logical / PurePosixPath(logical)).as_posix(),
                display_path=logical,
            ),
        )
        for logical, _, _ in before
    ]
    after = _scan_report_tree(report_root)
    before_identity = tuple((logical, metadata) for logical, _, metadata in before)
    after_identity = tuple((logical, metadata) for logical, _, metadata in after)
    if before_identity != after_identity:
        _fail("coverage.report_tree_changed", "report tree changed during ingestion")
    paths = {path for path, _ in payloads}
    if entry_point not in paths:
        _fail("coverage.entry_point_missing", "configured entry point is absent from report tree", entry_point)
    entries = [
        {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": str(len(content)),
        }
        for path, content in payloads
    ]
    tree_sha256 = hashlib.sha256(
        canonical_json(
            {
                "entries": entries,
                "kind": "coverage-report-tree",
                "schema": REPORT_TREE_SCHEMA_ID,
            }
        )
    ).hexdigest()
    artifacts = tuple(
        CoverageArtifact(
            artifact_id="coverage-artifact:sha256:"
            + hashlib.sha256(
                canonical_json({"path": path, "report_tree_sha256": tree_sha256})
            ).hexdigest(),
            path=path,
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            content=content,
            entry_point=path == entry_point,
        )
        for path, content in payloads
    )
    return artifacts, tree_sha256


def _parse_sidecar(
    root: Path, configured_path: str, *, kind: str
) -> tuple[dict[str, Any], CoverageSidecarArtifact]:
    logical = _path(configured_path, field="sidecar path")
    _rooted_path(root, logical)
    content = _read_regular(root, logical)
    try:
        value = parse_json(content)
    except ConfigurationError as error:
        _fail("coverage.invalid_sidecar_json", error.message, logical)
    if not isinstance(value, dict):
        _fail("coverage.invalid_sidecar", "sidecar must be an object", logical)
    digest = hashlib.sha256(content).hexdigest()
    artifact = CoverageSidecarArtifact(
        artifact_id="coverage-sidecar:sha256:"
        + hashlib.sha256(
            canonical_json({"kind": kind, "path": logical, "sha256": digest})
        ).hexdigest(),
        kind=kind,
        path=logical,
        sha256=digest,
        size=len(content),
        content=content,
    )
    return value, artifact


def _report_binding(value: Any, *, field: str) -> tuple[str, str]:
    report = _closed(value, {"entry_point", "tree_sha256"}, field)
    return (
        _path(report["entry_point"], field=f"{field}.entry_point"),
        _digest(report["tree_sha256"], f"{field}.tree_sha256"),
    )


def _mapping_relations(
    value: dict[str, Any],
    *,
    artifacts: tuple[CoverageArtifact, ...],
    snapshot: GitSnapshot,
    entry_point: str,
    tree_sha256: str,
) -> tuple[CoverageRelation, ...]:
    mapping = _closed(value, {"schema", "report", "relations"}, "mapping")
    if mapping["schema"] != MAP_SCHEMA_ID:
        _fail("coverage.unsupported_mapping_schema", f"mapping schema must be {MAP_SCHEMA_ID}")
    bound_entry, bound_digest = _report_binding(mapping["report"], field="mapping.report")
    if (bound_entry, bound_digest) != (entry_point, tree_sha256):
        _fail("coverage.mapping_report_mismatch", "mapping does not bind the exact report tree")
    raw_relations = mapping["relations"]
    if not isinstance(raw_relations, list):
        _fail("coverage.invalid_sidecar", "mapping.relations must be an array")

    artifact_by_path = {artifact.path: artifact for artifact in artifacts}
    selected_sources = {
        record["path"]
        for record in snapshot.files
        if record.get("kind") == "file"
    }
    source_content = dict(snapshot._content)
    result: list[CoverageRelation] = []
    seen: set[bytes] = set()
    for index, raw in enumerate(raw_relations):
        relation = _closed(
            raw,
            {"fragment", "line", "report_path", "source_path", "symbol"},
            f"mapping.relations[{index}]",
        )
        report_path = _path(relation["report_path"], field="relation.report_path")
        artifact = artifact_by_path.get(report_path)
        if artifact is None:
            _fail("coverage.report_target_missing", "mapping report target is absent", report_path)
        source_path = _path(relation["source_path"], field="relation.source_path")
        if source_path not in selected_sources:
            basename_matches = [
                path for path in selected_sources if PurePosixPath(path).name == source_path
            ]
            if len(basename_matches) > 1:
                _fail("coverage.ambiguous_source", "source basename is ambiguous and cannot be inferred", source_path)
            _fail("coverage.source_missing", "mapping source is not an exact selected snapshot path", source_path)
        line = relation["line"]
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            _fail("coverage.invalid_sidecar", "relation.line must be a positive integer or null")
        if line is not None:
            content = source_content.get(source_path)
            if content is None:
                _fail("coverage.snapshot_inconsistent", "selected source bytes are unavailable", source_path)
            line_count = content.count(b"\n") + int(bool(content) and not content.endswith(b"\n"))
            if line > line_count:
                _fail("coverage.source_line_missing", "mapping line is outside the selected source", source_path)
        fragment = relation["fragment"]
        if fragment is not None:
            fragment = _identity(fragment, "relation.fragment")
        symbol = relation["symbol"]
        if symbol is not None:
            symbol = _identity(symbol, "relation.symbol")
        identity = {
            "fragment": fragment,
            "line": line,
            "report_artifact_id": artifact.artifact_id,
            "report_path": report_path,
            "snapshot_id": snapshot.snapshot_id,
            "source_path": source_path,
            "symbol": symbol,
        }
        identity_bytes = canonical_json(identity)
        if identity_bytes in seen:
            _fail("coverage.duplicate_relation", "mapping contains a duplicate relation")
        seen.add(identity_bytes)
        result.append(
            CoverageRelation(
                relation_id="coverage-relation:sha256:" + hashlib.sha256(identity_bytes).hexdigest(),
                report_artifact_id=artifact.artifact_id,
                report_path=report_path,
                fragment=fragment,
                source_path=source_path,
                line=line,
                symbol=symbol,
            )
        )
    result.sort(key=lambda item: item.relation_id.encode())
    return tuple(result)


def _attestation_matches(
    value: dict[str, Any],
    *,
    snapshot_id: str,
    configuration_identity_sha256: str,
    entry_point: str,
    tree_sha256: str,
) -> tuple[bool, tuple[str, ...]]:
    attestation = _closed(
        value,
        {
            "schema",
            "report",
            "snapshot_id",
            "configuration_identity_sha256",
            "producer",
            "test_selection_identity",
            "test_result_identity",
            "instrumentation_identity",
            "coverage_data_identity",
        },
        "attestation",
    )
    if attestation["schema"] != ATTESTATION_SCHEMA_ID:
        _fail("coverage.unsupported_attestation_schema", f"attestation schema must be {ATTESTATION_SCHEMA_ID}")
    bound_entry, bound_digest = _report_binding(attestation["report"], field="attestation.report")
    producer = _closed(attestation["producer"], {"name", "version"}, "attestation.producer")
    _identity(producer["name"], "attestation.producer.name")
    _identity(producer["version"], "attestation.producer.version")
    _identity(attestation["snapshot_id"], "attestation.snapshot_id")
    _digest(
        attestation["configuration_identity_sha256"],
        "attestation.configuration_identity_sha256",
    )
    for field in (
        "test_selection_identity",
        "test_result_identity",
        "instrumentation_identity",
        "coverage_data_identity",
    ):
        _identity(attestation[field], f"attestation.{field}")

    if (bound_entry, bound_digest) != (entry_point, tree_sha256):
        _fail(
            "coverage.attestation_report_mismatch",
            "attestation does not bind the exact report tree",
        )
    diagnostics: list[str] = []
    if attestation["snapshot_id"] != snapshot_id:
        diagnostics.append("coverage.attestation_snapshot_mismatch")
    if attestation["configuration_identity_sha256"] != configuration_identity_sha256:
        diagnostics.append("coverage.attestation_configuration_mismatch")
    return not diagnostics, tuple(diagnostics)


class CoverageAdapter:
    """Ingest a configured report tree without executing a coverage producer."""

    def validate_declaration(
        self, config: Mapping[str, Any]
    ) -> tuple[tuple[Diagnostic, ...], CapabilityRequirements]:
        coverage = config.get("coverage")
        report = coverage.get("report") if isinstance(coverage, Mapping) else None
        diagnostics = (
            ()
            if report is not None
            else (
                Diagnostic(
                    "plan.coverage_report_required",
                    "enabled coverage ingestion requires coverage.report",
                ),
            )
        )
        return diagnostics, CapabilityRequirements(None)

    def plan_declaration(
        self, config: Mapping[str, Any], snapshot: GitSnapshot
    ) -> DeclarativeStagePlan:
        del snapshot
        coverage = config["coverage"]
        inputs = tuple(
            value
            for value in (
                coverage["report"],
                coverage["mapping"],
                coverage["attestation"],
            )
            if value is not None
        )
        return DeclarativeStagePlan(
            stage="coverage",
            selector="builtin.coverage-ingest.v1",
            dependencies=("snapshot",),
            required_inputs=inputs,
            invocation=("{inspector.executable}", "ingest-coverage"),
            expected_outputs=("artifacts/coverage",),
            workspace="stages/coverage",
        )

    def ingest(
        self,
        config: Mapping[str, Any],
        snapshot: GitSnapshot,
        input_root: str | os.PathLike[str],
        *,
        configuration_identity: Mapping[str, Any],
    ) -> CoverageOutput:
        coverage = config.get("coverage")
        if not isinstance(coverage, Mapping):
            _fail("coverage.invalid_configuration", "coverage configuration is required")
        if set(coverage) != {"report", "mapping", "attestation"}:
            _fail("coverage.invalid_configuration", "coverage configuration must be closed")
        configured_report = _path(coverage["report"], field="coverage.report")
        configuration_identity_sha256 = _configuration_identity_digest(
            configuration_identity
        )
        report_project_path = PurePosixPath(configured_report)
        entry_point = report_project_path.name
        report_root_logical = report_project_path.parent
        sidecar_paths: dict[str, str] = {}
        for kind in ("mapping", "attestation"):
            configured_sidecar = coverage[kind]
            if configured_sidecar is None:
                continue
            logical = _path(configured_sidecar, field=f"coverage.{kind}")
            sidecar = PurePosixPath(logical)
            root_parts = report_root_logical.parts
            if not root_parts or sidecar.parts[: len(root_parts)] == root_parts:
                _fail(
                    "coverage.sidecar_in_report_tree",
                    "mapping and attestation sidecars must be outside the report tree",
                    logical,
                )
            sidecar_paths[kind] = logical
        root = Path(input_root)
        artifacts, tree_sha256 = _inventory(root, report_root_logical, entry_point)

        sidecars: list[CoverageSidecarArtifact] = []
        mapping_path = sidecar_paths.get("mapping")
        if mapping_path is None:
            relations: tuple[CoverageRelation, ...] = ()
            mapping_valid = False
        else:
            mapping_value, mapping_artifact = _parse_sidecar(
                root, mapping_path, kind="mapping"
            )
            sidecars.append(mapping_artifact)
            relations = _mapping_relations(
                mapping_value,
                artifacts=artifacts,
                snapshot=snapshot,
                entry_point=entry_point,
                tree_sha256=tree_sha256,
            )
            mapping_valid = True

        diagnostics: tuple[str, ...] = ()
        attestation_path = sidecar_paths.get("attestation")
        if attestation_path is None:
            attestation_valid = False
        else:
            attestation_value, attestation_artifact = _parse_sidecar(
                root, attestation_path, kind="attestation"
            )
            sidecars.append(attestation_artifact)
            attestation_valid, diagnostics = _attestation_matches(
                attestation_value,
                snapshot_id=snapshot.snapshot_id,
                configuration_identity_sha256=configuration_identity_sha256,
                entry_point=entry_point,
                tree_sha256=tree_sha256,
            )
        final_artifacts, final_tree_sha256 = _inventory(
            root, report_root_logical, entry_point
        )
        if final_tree_sha256 != tree_sha256 or final_artifacts != artifacts:
            _fail(
                "coverage.report_tree_changed",
                "report tree changed during ingestion",
            )
        provenance = (
            CoverageProvenance.EXTERNALLY_ATTESTED
            if attestation_valid
            else CoverageProvenance.UNKNOWN_ORIGIN
        )
        return CoverageOutput(
            entry_point=entry_point,
            report_tree_sha256=tree_sha256,
            artifacts=artifacts,
            sidecars=tuple(sorted(sidecars, key=lambda item: item.kind.encode())),
            relations=relations,
            provenance=provenance,
            mapping_valid=mapping_valid,
            attestation_valid=attestation_valid,
            diagnostics=diagnostics,
        )
