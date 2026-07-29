"""Owned Doxygen execution and fail-closed machine-readable mapping ingestion."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from .adapters import (
    Capability,
    CapabilityRequirements,
    CommandPlan,
    DeclarativeStagePlan,
    Diagnostic,
    ProducerAdapter,
)
from .configuration import canonical_json
from .process_runner import (
    FailureKind,
    OutputDeclaration,
    OwnedWorkspace,
    ProcessResult,
    ProcessRunner,
    ProcessStatus,
    WorkspaceManager,
)

ARTIFACT_SCHEMA = "osqar.inspector.doxygen-artifact.v1"
MAPPING_SCHEMA = "osqar.inspector.doxygen-mapping.v1"
ADAPTER_SELECTOR = "builtin.doxygen.v1"
_VERSION = re.compile(r"(?<![0-9])([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")


@dataclass
class DoxygenAdapterError(Exception):
    """A typed, fail-closed Doxygen adapter error."""

    code: str
    message: str
    path: str | None = None

    def __str__(self) -> str:
        suffix = f" ({self.path})" if self.path is not None else ""
        return f"{self.code}: {self.message}{suffix}"


@dataclass(frozen=True)
class DoxygenCommandPlan(CommandPlan):
    workspace: OwnedWorkspace | None = None
    timeout_seconds: float = 300.0


@dataclass(frozen=True)
class ProducerFile:
    path: str
    content: bytes
    size: str
    sha256: str


@dataclass(frozen=True)
class DoxygenProducerOutput:
    files: tuple[ProducerFile, ...]
    snapshot_root: Path


@dataclass(frozen=True)
class DoxygenArtifactRecord:
    schema: str
    artifact_id: str
    path: str
    kind: str
    size: str
    sha256: str


@dataclass(frozen=True)
class DoxygenMappingRecord:
    schema: str
    snapshot_id: str
    refid: str
    entity_kind: str
    qualified_name: str
    source_path: str
    line: str | None
    column: str | None
    html_artifact_id: str
    html_anchor: str


@dataclass(frozen=True)
class DoxygenNormalizedOutput:
    artifacts: tuple[DoxygenArtifactRecord, ...]
    mappings: tuple[DoxygenMappingRecord, ...]


@dataclass(frozen=True)
class _Entity:
    refid: str
    kind: str
    qualified_name: str
    source_path: str
    line: str | None
    column: str | None
    compound_name: str
    member_name: str | None
    args: str | None


@dataclass(frozen=True)
class _Target:
    compound_name: str
    kind: str
    member_name: str | None
    args: str | None
    html_path: str
    anchor: str


class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        identities = {
            value
            for name, value in attrs
            if value is not None
            and (
                name.lower() == "id"
                or (tag.lower() == "a" and name.lower() == "name")
            )
        }
        self.values.extend(sorted(identities, key=str.encode))


def _fail(code: str, message: str, path: str | None = None) -> NoReturn:
    raise DoxygenAdapterError(code, message, path)


def _xml(path: Path, root_name: str) -> bool:
    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError):
        return False
    return root.tag == root_name


def _html(path: Path) -> bool:
    try:
        parser = _Anchors()
        parser.feed(path.read_text(encoding="utf-8"))
        parser.close()
    except (OSError, UnicodeError):
        return False
    return True


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    match = _VERSION.search(value)
    if match is None:
        return None
    return tuple(int(part or "0") for part in match.groups())  # type: ignore[return-value]


def _safe_path(value: str, *, code: str) -> str:
    if not isinstance(value, str):
        _fail(code, "producer path is not a string")
    if unicodedata.normalize("NFC", value) != value or "\\" in value or value.startswith("/"):
        _fail(code, "producer path is not a normalized relative path", value)
    parts = PurePosixPath(value).parts
    if (
        not value
        or PurePosixPath(value).as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        _fail(code, "producer path is not a normalized relative path", value)
    if any(unicodedata.category(character) == "Cc" for character in value):
        _fail(code, "producer path contains a control character", value)
    return value


def _source_path(value: str, snapshot_root: Path, selected: set[str]) -> str:
    if "\\" in value or "\x00" in value:
        _fail("doxygen.invalid_source_path", "source path is not supported", value)
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            normalized = candidate.resolve(strict=False).relative_to(snapshot_root.resolve(strict=True))
        except (OSError, ValueError):
            _fail("doxygen.source_outside_snapshot", "source location is outside the snapshot", value)
        result = normalized.as_posix()
    else:
        result = PurePosixPath(value).as_posix()
    result = _safe_path(result, code="doxygen.invalid_source_path")
    if result not in selected:
        _fail(
            "doxygen.source_target_missing",
            "source location does not name an exact selected snapshot path; filename inference is forbidden",
            result,
        )
    return result


def _text(element: ET.Element, name: str) -> str:
    child = element.find(name)
    return "" if child is None or child.text is None else child.text.strip()


def _arguments(value: str | None) -> str:
    return "" if value is None else " ".join(value.split())


class DoxygenAdapter(ProducerAdapter):
    """Doxygen v1 adapter; declaration methods are pure, runtime methods are owned."""

    def __init__(
        self,
        *,
        runner: ProcessRunner | None = None,
        snapshot_root: Path | None = None,
        selected_paths: Iterable[str] | None = None,
        executable: str = "doxygen",
        timeout_seconds: float = 300.0,
    ) -> None:
        if not executable or "\x00" in executable:
            raise ValueError("Doxygen executable must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("Doxygen timeout must be positive")
        self.runner = runner
        self.snapshot_root = snapshot_root
        self.selected_paths = (
            None
            if selected_paths is None
            else frozenset(
                _safe_path(path, code="doxygen.declaration_invalid")
                for path in selected_paths
            )
        )
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def bind_runtime(
        self,
        *,
        workspaces: WorkspaceManager,
        snapshot_root: Path,
        selected_paths: Iterable[str],
        configuration: Any | None = None,
        snapshot: Any | None = None,
    ) -> DoxygenAdapter:
        """Bind pure adapter settings to the orchestrator-owned runtime context."""

        del configuration, snapshot
        return DoxygenAdapter(
            runner=ProcessRunner(workspaces),
            snapshot_root=snapshot_root,
            selected_paths=selected_paths,
            executable=self.executable,
            timeout_seconds=self.timeout_seconds,
        )

    def validate_declaration(
        self, config: Mapping[str, Any]
    ) -> tuple[tuple[Diagnostic, ...], CapabilityRequirements]:
        doxygen = config.get("doxygen")
        diagnostics: list[Diagnostic] = []
        if not isinstance(doxygen, Mapping):
            diagnostics.append(Diagnostic("doxygen.declaration_invalid", "doxygen configuration must be an object"))
        else:
            for field in ("configuration", "output"):
                value = doxygen.get(field)
                try:
                    _safe_path(value, code="doxygen.declaration_invalid")
                except DoxygenAdapterError as error:
                    diagnostics.append(Diagnostic(error.code, f"doxygen.{field}: {error.message}"))
            if not isinstance(doxygen.get("warnings_as_errors"), bool):
                diagnostics.append(Diagnostic("doxygen.declaration_invalid", "doxygen.warnings_as_errors must be boolean"))
        return tuple(diagnostics), CapabilityRequirements(self.executable, ">=1.9")

    def plan_declaration(
        self, config: Mapping[str, Any], snapshot: Any
    ) -> DeclarativeStagePlan:
        doxygen = config["doxygen"]
        configuration = doxygen["configuration"]
        return DeclarativeStagePlan(
            stage="doxygen",
            selector=ADAPTER_SELECTOR,
            dependencies=("snapshot",),
            required_inputs=(configuration,),
            invocation=("{capability.executable}", "{workspace.root}/Doxyfile.inspector"),
            expected_outputs=(doxygen["output"],),
            workspace="stages/doxygen",
            adapter_options=(("warnings_as_errors", doxygen["warnings_as_errors"]),),
        )

    def _require_runtime(self) -> tuple[ProcessRunner, Path]:
        if (
            self.runner is None
            or self.snapshot_root is None
            or self.selected_paths is None
        ):
            _fail(
                "doxygen.runtime_unconfigured",
                "runtime adapter requires a runner, materialized snapshot root, and selected paths",
            )
        try:
            root = self.snapshot_root.resolve(strict=True)
        except OSError as error:
            _fail("doxygen.snapshot_unavailable", str(error))
        if not root.is_dir():
            _fail("doxygen.snapshot_unavailable", "materialized snapshot root is not a directory")
        return self.runner, root

    def probe(self, config: Mapping[str, Any], workspace: OwnedWorkspace) -> Capability:
        runner, _ = self._require_runtime()
        result = runner.run(
            [self.executable, "--version"],
            workspace=workspace,
            timeout_seconds=self.timeout_seconds,
        )
        if result.status is ProcessStatus.FAILED:
            assert result.failure is not None
            code = {
                FailureKind.SPAWN: "doxygen.capability_missing",
                FailureKind.TIMEOUT: "doxygen.capability_timeout",
                FailureKind.NONZERO_EXIT: "doxygen.capability_probe_failed",
            }.get(result.failure.kind, "doxygen.capability_probe_failed")
            _fail(code, result.failure.message)
        try:
            version = result.stdout_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as error:
            _fail("doxygen.capability_malformed", f"cannot read Doxygen version: {error}")
        if _version_tuple(version) is None:
            _fail("doxygen.capability_malformed", "Doxygen version output contains no semantic version")
        return Capability(os.fspath(result.executable.path), version)

    def validate_capability(
        self, config: Mapping[str, Any], capability: Capability
    ) -> tuple[Diagnostic, ...]:
        version = _version_tuple(capability.version)
        if version is None:
            return (Diagnostic("doxygen.capability_malformed", "Doxygen version cannot be parsed"),)
        if version < (1, 9, 0):
            return (Diagnostic("doxygen.capability_incompatible", "Doxygen >=1.9 is required"),)
        return ()

    def plan_command(
        self,
        plan: DeclarativeStagePlan,
        capability: Capability,
        workspace: OwnedWorkspace,
    ) -> DoxygenCommandPlan:
        runner, snapshot_root = self._require_runtime()
        if not runner.workspaces.owns(workspace):
            _fail(
                "doxygen.workspace_not_owned",
                "Doxygen configuration requires a live workspace owned by the shared runner",
            )
        diagnostics = self.validate_capability({}, capability)
        if diagnostics:
            _fail(diagnostics[0].code, diagnostics[0].message)
        if len(plan.required_inputs) != 1:
            _fail("doxygen.declaration_invalid", "Doxygen requires exactly one controlled configuration input")
        controlled_relative = _safe_path(
            plan.required_inputs[0], code="doxygen.declaration_invalid"
        )
        assert self.selected_paths is not None
        if controlled_relative not in self.selected_paths:
            _fail(
                "doxygen.input_not_selected",
                "controlled Doxygen configuration is not an exact selected snapshot record",
                controlled_relative,
            )
        controlled_candidate = snapshot_root.joinpath(
            *PurePosixPath(controlled_relative).parts
        )
        try:
            controlled_configuration = controlled_candidate.resolve(strict=True)
            controlled_configuration.relative_to(snapshot_root)
        except (OSError, ValueError):
            _fail(
                "doxygen.configuration_missing",
                "controlled Doxygen configuration is absent from the materialized snapshot",
                controlled_relative,
            )
        if not controlled_configuration.is_file():
            _fail(
                "doxygen.configuration_missing",
                "controlled Doxygen configuration is absent from the materialized snapshot",
                controlled_relative,
            )
        config_path = workspace.path / "Doxyfile.inspector"
        if config_path.exists():
            _fail("doxygen.configuration_stale", "generated Doxygen configuration already exists")
        def quote(path: Path) -> str:
            value = os.fspath(path)
            if any(character in value for character in ('"', "\n", "\r", "\x00")):
                _fail("doxygen.unsupported_workspace_path", "Doxygen path cannot be represented safely")
            return f'"{value}"'

        output_root = workspace.path / "output"
        generated = "\n".join(
            (
                "# Generated by OSQAr Inspector; producer output remains byte-identical.",
                f"@INCLUDE = {quote(controlled_configuration)}",
                f"INPUT = {quote(snapshot_root)}",
                "RECURSIVE = YES",
                "EXTRACT_ALL = YES",
                "FULL_PATH_NAMES = YES",
                f"STRIP_FROM_PATH = {quote(snapshot_root)}",
                f"OUTPUT_DIRECTORY = {quote(output_root)}",
                "GENERATE_HTML = YES",
                "HTML_OUTPUT = html",
                "GENERATE_XML = YES",
                "XML_OUTPUT = xml",
                "XML_PROGRAMLISTING = YES",
                f"GENERATE_TAGFILE = {quote(output_root / 'doxygen.tag')}",
                "QUIET = YES",
                "WARN_AS_ERROR = YES"
                if dict(plan.adapter_options).get("warnings_as_errors", False)
                else "WARN_AS_ERROR = NO",
                "",
            )
        )
        try:
            config_path.write_text(generated, encoding="utf-8", newline="\n")
        except OSError as error:
            _fail("doxygen.configuration_write_failed", str(error))
        outputs = (
            OutputDeclaration("output/xml/index.xml", "doxygen-xml-index", lambda path: _xml(path, "doxygenindex")),
            OutputDeclaration("output/doxygen.tag", "doxygen-tag", lambda path: _xml(path, "tagfile")),
            OutputDeclaration("output/html/index.html", "doxygen-html-index", _html),
        )
        return DoxygenCommandPlan(
            argv=(capability.executable, "Doxyfile.inspector"),
            workspace=workspace,
            timeout_seconds=self.timeout_seconds,
            outputs=outputs,
        )

    def execute(self, command_plan: CommandPlan) -> ProcessResult:
        runner, _ = self._require_runtime()
        if not isinstance(command_plan, DoxygenCommandPlan) or command_plan.workspace is None:
            _fail("doxygen.command_invalid", "Doxygen execution requires an owned Doxygen command plan")
        return runner.run(
            command_plan.argv,
            workspace=command_plan.workspace,
            timeout_seconds=command_plan.timeout_seconds,
            outputs=command_plan.outputs,
            fresh_paths=("output",),
            accepted_exit_codes=command_plan.accepted_exit_codes,
        )

    def collect(self, process_result: ProcessResult, workspace: OwnedWorkspace) -> DoxygenProducerOutput:
        runner, snapshot_root = self._require_runtime()
        if not runner.workspaces.owns(workspace):
            _fail("doxygen.workspace_not_owned", "Doxygen collection requires an owned workspace")
        if process_result.stdout_path.parent.resolve() != workspace.path.resolve():
            _fail("doxygen.workspace_mismatch", "process result does not belong to the collection workspace")
        if process_result.status is not ProcessStatus.SUCCEEDED:
            _fail("doxygen.process_failed", "failed producer output cannot be collected")
        root = workspace.path / "output"
        try:
            metadata = root.lstat()
        except OSError as error:
            _fail("doxygen.output_missing", str(error))
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            _fail("doxygen.output_malformed", "Doxygen output root must be a real directory")
        files: list[ProducerFile] = []
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode()):
            try:
                item = path.lstat()
            except OSError as error:
                _fail("doxygen.output_malformed", str(error))
            relative = _safe_path(path.relative_to(root).as_posix(), code="doxygen.output_malformed")
            if stat.S_ISDIR(item.st_mode) and not stat.S_ISLNK(item.st_mode):
                continue
            if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode):
                _fail("doxygen.output_malformed", "producer output contains a non-regular file", relative)
            try:
                content = path.read_bytes()
            except OSError as error:
                _fail("doxygen.output_malformed", str(error), relative)
            files.append(ProducerFile(relative, content, str(len(content)), hashlib.sha256(content).hexdigest()))
        if not files:
            _fail("doxygen.output_missing", "Doxygen produced no collectible payloads")
        return DoxygenProducerOutput(tuple(files), snapshot_root)

    def normalize(self, producer_output: DoxygenProducerOutput, snapshot: Any) -> DoxygenNormalizedOutput:
        selected = {record["path"] for record in snapshot.files if record.get("kind") == "file"}
        by_path = {item.path: item for item in producer_output.files}
        artifacts = tuple(self._artifact(item) for item in producer_output.files)
        artifact_by_path = {item.path: item for item in artifacts}
        entities = self._entities(by_path, producer_output.snapshot_root, selected)
        targets = self._targets(by_path)
        mappings: list[DoxygenMappingRecord] = []
        seen_refids: set[str] = set()
        for entity in entities:
            if entity.refid in seen_refids:
                _fail("doxygen.duplicate_refid", "duplicate producer refid in snapshot scope", entity.refid)
            seen_refids.add(entity.refid)
            candidates = self._target_candidates(entity, targets)
            if not candidates:
                _fail("doxygen.target_missing", "no explicit Doxygen tag target exists", entity.refid)
            if len(candidates) != 1:
                _fail("doxygen.ambiguous_target", "Doxygen entity has multiple explicit HTML targets", entity.refid)
            target = candidates[0]
            artifact = artifact_by_path.get(target.html_path)
            if artifact is None:
                _fail("doxygen.target_missing", "explicit HTML target is not a collected artifact", target.html_path)
            if target.anchor:
                self._validate_anchor(by_path[target.html_path].content, target.anchor, target.html_path)
            mappings.append(
                DoxygenMappingRecord(
                    MAPPING_SCHEMA,
                    snapshot.snapshot_id,
                    entity.refid,
                    entity.kind,
                    entity.qualified_name,
                    entity.source_path,
                    entity.line,
                    entity.column,
                    artifact.artifact_id,
                    target.anchor,
                )
            )
        mappings.sort(key=lambda item: item.refid.encode())
        return DoxygenNormalizedOutput(artifacts, tuple(mappings))

    @staticmethod
    def _artifact(item: ProducerFile) -> DoxygenArtifactRecord:
        if item.path.startswith("html/") and item.path.endswith(".html"):
            kind = "api-page"
        elif item.path.endswith(".xml") or item.path.endswith(".tag"):
            kind = "producer-machine-output"
        else:
            kind = "producer-asset"
        identity = canonical_json({"kind": "doxygen-payload", "path": item.path, "sha256": item.sha256})
        artifact_id = "artifact:sha256:" + hashlib.sha256(identity).hexdigest()
        return DoxygenArtifactRecord(ARTIFACT_SCHEMA, artifact_id, item.path, kind, item.size, item.sha256)

    @staticmethod
    def _entities(by_path: dict[str, ProducerFile], snapshot_root: Path, selected: set[str]) -> tuple[_Entity, ...]:
        index = by_path.get("xml/index.xml")
        if index is None:
            _fail("doxygen.output_missing", "Doxygen XML index was not collected")
        try:
            index_root = ET.fromstring(index.content)
        except ET.ParseError as error:
            _fail("doxygen.output_malformed", str(error), index.path)
        index_refids = [element.get("refid") for element in index_root.iter() if element.get("refid")]
        if len(index_refids) != len(set(index_refids)):
            _fail("doxygen.duplicate_refid", "Doxygen XML index contains duplicate refids")
        entities: list[_Entity] = []
        detail_refids: set[str] = set()
        for path, payload in sorted(by_path.items(), key=lambda item: item[0].encode()):
            if not path.startswith("xml/") or path == "xml/index.xml" or not path.endswith(".xml"):
                continue
            try:
                root = ET.fromstring(payload.content)
            except ET.ParseError as error:
                _fail("doxygen.output_malformed", str(error), path)
            for compound in root.iter("compounddef"):
                compound_name = _text(compound, "compoundname")
                DoxygenAdapter._append_entity(entities, detail_refids, compound, compound_name, None, None, snapshot_root, selected)
                for member in compound.iter("memberdef"):
                    DoxygenAdapter._append_entity(
                        entities,
                        detail_refids,
                        member,
                        compound_name,
                        _text(member, "name"),
                        _text(member, "argsstring"),
                        snapshot_root,
                        selected,
                    )
        missing = sorted(set(index_refids) - detail_refids, key=str.encode)
        if missing:
            _fail("doxygen.refid_target_missing", "XML index refid has no explicit detail definition", missing[0])
        unindexed = sorted(detail_refids - set(index_refids), key=str.encode)
        if unindexed:
            _fail(
                "doxygen.unindexed_refid",
                "XML detail refid is absent from the explicit Doxygen index",
                unindexed[0],
            )
        entities.sort(key=lambda item: item.refid.encode())
        return tuple(entities)

    @staticmethod
    def _append_entity(
        entities: list[_Entity],
        detail_refids: set[str],
        element: ET.Element,
        compound_name: str,
        member_name: str | None,
        args: str | None,
        snapshot_root: Path,
        selected: set[str],
    ) -> None:
        refid = element.get("id")
        kind = element.get("kind")
        if not refid or not kind:
            _fail("doxygen.output_malformed", "mapped XML entity lacks id or kind")
        if refid in detail_refids:
            _fail("doxygen.duplicate_refid", "duplicate producer refid in XML details", refid)
        detail_refids.add(refid)
        if kind == "dir":
            return
        location = element.find("location")
        if location is None or not location.get("file"):
            return
        qualified = _text(element, "qualifiedname") or (member_name if member_name is not None else compound_name)
        if not qualified:
            _fail("doxygen.output_malformed", "mapped XML entity lacks a qualified name", refid)
        entities.append(
            _Entity(
                refid,
                kind,
                qualified,
                _source_path(location.get("file", ""), snapshot_root, selected),
                location.get("line"),
                location.get("column"),
                compound_name,
                member_name,
                args,
            )
        )

    @staticmethod
    def _targets(by_path: dict[str, ProducerFile]) -> tuple[_Target, ...]:
        payload = by_path.get("doxygen.tag")
        if payload is None:
            _fail("doxygen.output_missing", "Doxygen tag file was not collected")
        try:
            root = ET.fromstring(payload.content)
        except ET.ParseError as error:
            _fail("doxygen.output_malformed", str(error), payload.path)
        targets: list[_Target] = []
        for compound in root.findall("compound"):
            compound_name = _text(compound, "name")
            filename = _text(compound, "filename")
            kind = compound.get("kind") or ""
            if compound_name and filename:
                targets.append(_Target(compound_name, kind, None, None, DoxygenAdapter._html_target(filename), ""))
            for member in compound.findall("member"):
                anchorfile = _text(member, "anchorfile")
                anchor = _text(member, "anchor")
                name = _text(member, "name")
                if not anchorfile or not anchor or not name:
                    _fail("doxygen.output_malformed", "tag member lacks explicit anchorfile, anchor, or name")
                targets.append(
                    _Target(
                        compound_name,
                        member.get("kind") or "",
                        name,
                        _text(member, "arglist"),
                        DoxygenAdapter._html_target(anchorfile),
                        anchor,
                    )
                )
        return tuple(targets)

    @staticmethod
    def _html_target(value: str) -> str:
        relative = _safe_path(value, code="doxygen.invalid_html_target")
        return _safe_path(f"html/{relative}", code="doxygen.invalid_html_target")

    @staticmethod
    def _target_candidates(entity: _Entity, targets: tuple[_Target, ...]) -> list[_Target]:
        if entity.member_name is None:
            return [item for item in targets if item.member_name is None and item.compound_name == entity.compound_name and item.kind == entity.kind]
        candidates = [
            item
            for item in targets
            if item.member_name == entity.member_name
            and item.compound_name == entity.compound_name
            and item.kind == entity.kind
        ]
        exact = [item for item in candidates if _arguments(item.args) == _arguments(entity.args)]
        return exact

    @staticmethod
    def _validate_anchor(content: bytes, anchor: str, path: str) -> None:
        try:
            parser = _Anchors()
            parser.feed(content.decode("utf-8", "strict"))
            parser.close()
        except (UnicodeError, ValueError) as error:
            _fail("doxygen.output_malformed", str(error), path)
        count = parser.values.count(anchor)
        if count == 0:
            _fail("doxygen.target_missing", "explicit Doxygen anchor is absent", f"{path}#{anchor}")
        if count != 1:
            _fail("doxygen.ambiguous_target", "explicit Doxygen anchor is ambiguous", f"{path}#{anchor}")
