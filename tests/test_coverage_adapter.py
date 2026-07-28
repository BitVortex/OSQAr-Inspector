from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

import osqar_inspector.coverage_adapter as coverage_module
from osqar_inspector.configuration import canonical_json
from osqar_inspector.coverage_adapter import (
    CoverageAdapter,
    CoverageError,
    CoverageProvenance,
)
from osqar_inspector.snapshot import GitSnapshot


CONFIGURATION_IDENTITY = {
    "controlled_input": {"path": "inspector.json", "sha256": "a" * 64, "size": "1"},
    "defaults": {"id": "builtin-v1", "sha256": "b" * 64},
    "overrides": [],
    "resolved": {"sha256": "c" * 64},
    "schema": {"id": "osqar.inspector.config.v1", "sha256": "d" * 64},
}
CONFIGURATION_IDENTITY_SHA256 = hashlib.sha256(
    canonical_json(CONFIGURATION_IDENTITY)
).hexdigest()


def _report_digest(entry_point: str, files: dict[str, bytes]) -> str:
    entries = [
        {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": str(len(content)),
        }
        for path, content in sorted(files.items(), key=lambda item: item[0].encode())
    ]
    del entry_point
    identity = {
        "entries": entries,
        "kind": "coverage-report-tree",
        "schema": "osqar.inspector.coverage-report-tree.v1",
    }
    return hashlib.sha256(canonical_json(identity)).hexdigest()


def _write_snapshot(root: Path, files: dict[str, bytes]) -> GitSnapshot:
    records: list[dict[str, Any]] = []
    for path, content in sorted(files.items(), key=lambda item: item[0].encode()):
        destination = root.joinpath(*path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        records.append(
            {
                "path": path,
                "kind": "file",
                "mode": "100644",
                "size": str(len(content)),
                "identity": {"sha256": hashlib.sha256(content).hexdigest()},
            }
        )
    snapshot_identity = {
        "schema": "osqar.inspector.snapshot.v1",
        "source": {"kind": "test"},
        "policy": {"include": [], "exclude": []},
        "files": records,
    }
    snapshot_id = "snapshot:sha256:" + hashlib.sha256(
        canonical_json({"kind": "snapshot", "identity": snapshot_identity})
    ).hexdigest()
    return GitSnapshot(
        manifest={**snapshot_identity, "snapshot_id": snapshot_id},
        manifest_bytes=canonical_json({**snapshot_identity, "snapshot_id": snapshot_id}),
        snapshot_id=snapshot_id,
        files=tuple(records),
        _content=tuple(sorted(files.items(), key=lambda item: item[0].encode())),
    )


def _mapping(report_digest: str) -> bytes:
    return canonical_json(
        {
            "schema": "osqar.inspector.coverage-map.v1",
            "report": {"entry_point": "index.html", "tree_sha256": report_digest},
            "relations": [
                {
                    "fragment": "line-2",
                    "line": 2,
                    "report_path": "index.html",
                    "source_path": "src/widget.c",
                    "symbol": "widget_run",
                }
            ],
        }
    )


def _attestation(
    report_digest: str,
    snapshot_id: str,
    configuration_identity_sha256: str = CONFIGURATION_IDENTITY_SHA256,
) -> bytes:
    return canonical_json(
        {
            "schema": "osqar.inspector.coverage-attestation.v1",
            "report": {"entry_point": "index.html", "tree_sha256": report_digest},
            "snapshot_id": snapshot_id,
            "configuration_identity_sha256": configuration_identity_sha256,
            "producer": {"name": "lcov", "version": "2.0"},
            "test_selection_identity": "test-selection:sha256:" + "1" * 64,
            "test_result_identity": "test-result:sha256:" + "4" * 64,
            "instrumentation_identity": "instrumentation:sha256:" + "2" * 64,
            "coverage_data_identity": "coverage-data:sha256:" + "3" * 64,
        }
    )


def test_report_with_valid_mapping_and_attestation_is_ingested(tmp_path: Path) -> None:
    report_files = {
        "assets/coverage.bin": b"\x00\xffproducer bytes\r\n",
        "index.html": b'<a id="line-2">coverage</a>\n',
    }
    digest = _report_digest("index.html", report_files)
    snapshot = _write_snapshot(
        tmp_path,
        {"src/widget.c": b"/* generated fixture */\nint widget_run(void) { return 0; }\n"},
    )
    inputs = {
        **{
            "reports/coverage/" + path: content
            for path, content in report_files.items()
        },
        "evidence/coverage-map.json": _mapping(digest),
        "evidence/coverage-attestation.json": _attestation(digest, snapshot.snapshot_id),
    }
    for path, content in inputs.items():
        destination = tmp_path.joinpath(*path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    output = CoverageAdapter().ingest(
        {
            "coverage": {
                "report": "reports/coverage/index.html",
                "mapping": "evidence/coverage-map.json",
                "attestation": "evidence/coverage-attestation.json",
            }
        },
        snapshot,
        tmp_path,
        configuration_identity=CONFIGURATION_IDENTITY,
    )

    assert output.provenance is CoverageProvenance.EXTERNALLY_ATTESTED
    assert output.report_tree_sha256 == digest
    assert [(item.path, item.content) for item in output.artifacts] == [
        ("assets/coverage.bin", report_files["assets/coverage.bin"]),
        ("index.html", report_files["index.html"]),
    ]
    assert [(item.kind, item.path, item.content) for item in output.sidecars] == [
        (
            "attestation",
            "evidence/coverage-attestation.json",
            inputs["evidence/coverage-attestation.json"],
        ),
        ("mapping", "evidence/coverage-map.json", inputs["evidence/coverage-map.json"]),
    ]
    assert len(output.relations) == 1
    relation = output.relations[0]
    assert relation.source_path == "src/widget.c"
    assert relation.line == 2
    assert relation.symbol == "widget_run"
    assert relation.report_path == "index.html"
    assert relation.fragment == "line-2"
    assert relation.relation_id == "coverage-relation:sha256:" + hashlib.sha256(
        canonical_json(
            {
                "fragment": "line-2",
                "line": 2,
                "report_artifact_id": relation.report_artifact_id,
                "report_path": "index.html",
                "snapshot_id": snapshot.snapshot_id,
                "source_path": "src/widget.c",
                "symbol": "widget_run",
            }
        )
    ).hexdigest()


def test_line_relation_must_resolve_in_snapshot_source(tmp_path: Path) -> None:
    report = {"index.html": b"coverage\n"}
    digest = _report_digest("index.html", report)
    snapshot = _write_snapshot(tmp_path, {"src/one.c": b"one line\n"})
    entry = tmp_path / "reports" / "coverage" / "index.html"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(report["index.html"])
    mapping = tmp_path / "evidence" / "coverage-map.json"
    mapping.parent.mkdir(parents=True)
    mapping.write_bytes(
        canonical_json(
            {
                "schema": "osqar.inspector.coverage-map.v1",
                "report": {"entry_point": "index.html", "tree_sha256": digest},
                "relations": [
                    {
                        "fragment": None,
                        "line": 2,
                        "report_path": "index.html",
                        "source_path": "src/one.c",
                        "symbol": None,
                    }
                ],
            }
        )
    )

    with pytest.raises(CoverageError, match="coverage.source_line_missing"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": "evidence/coverage-map.json",
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_relation_identity_binds_snapshot_and_report_context(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "coverage" / "index.html"
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(b"coverage one\n")
    snapshot = _write_snapshot(tmp_path, {"src/widget.c": b"one\ntwo\n"})
    mapping_path = tmp_path / "evidence" / "coverage-map.json"
    mapping_path.parent.mkdir()

    def write_mapping(report_digest: str) -> None:
        mapping_path.write_bytes(_mapping(report_digest))

    configuration = {
        "coverage": {
            "report": "reports/coverage/index.html",
            "mapping": "evidence/coverage-map.json",
            "attestation": None,
        }
    }
    write_mapping(_report_digest("index.html", {"index.html": b"coverage one\n"}))
    first = CoverageAdapter().ingest(
        configuration,
        snapshot,
        tmp_path,
        configuration_identity=CONFIGURATION_IDENTITY,
    )
    other_snapshot = replace(
        snapshot, snapshot_id="snapshot:sha256:" + "9" * 64
    )
    second = CoverageAdapter().ingest(
        configuration,
        other_snapshot,
        tmp_path,
        configuration_identity=CONFIGURATION_IDENTITY,
    )
    assert first.relations[0].relation_id != second.relations[0].relation_id

    report_path.write_bytes(b"coverage two\n")
    write_mapping(_report_digest("index.html", {"index.html": b"coverage two\n"}))
    third = CoverageAdapter().ingest(
        configuration,
        snapshot,
        tmp_path,
        configuration_identity=CONFIGURATION_IDENTITY,
    )
    assert first.relations[0].report_artifact_id != third.relations[0].report_artifact_id
    assert first.relations[0].relation_id != third.relations[0].relation_id


def test_sidecars_inside_report_tree_are_rejected(tmp_path: Path) -> None:
    report = {"index.html": b"coverage\n"}
    digest = _report_digest("index.html", report)
    snapshot = _write_snapshot(tmp_path, {"src/one.c": b"one\n"})
    report_root = tmp_path / "reports" / "coverage"
    report_root.mkdir(parents=True)
    (report_root / "index.html").write_bytes(report["index.html"])
    (report_root / "map.json").write_bytes(
        canonical_json(
            {
                "schema": "osqar.inspector.coverage-map.v1",
                "report": {"entry_point": "index.html", "tree_sha256": digest},
                "relations": [],
            }
        )
    )

    with pytest.raises(CoverageError, match="coverage.sidecar_in_report_tree"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": "reports/coverage/map.json",
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_symlinked_input_ancestors_cannot_escape_the_ingestion_root(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"main\n"})
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    report_root = outside / "coverage"
    report_root.mkdir(parents=True)
    (report_root / "index.html").write_bytes(b"coverage\n")
    (tmp_path / "reports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(CoverageError, match="coverage.path_symlink"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": None,
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_input_ancestor_symlink_swap_during_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"main\n"})
    report_root = tmp_path / "reports"
    report_root.mkdir()
    (report_root / "index.html").write_bytes(b"coverage\n")
    outside = tmp_path.parent / f"{tmp_path.name}-race-outside"
    outside.mkdir()
    (outside / "index.html").write_bytes(b"outside\n")
    original_open = coverage_module.os.open
    changed = False

    def swap_ancestor_before_open(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal changed
        if path == "reports" and dir_fd is not None and not changed:
            changed = True
            report_root.rename(tmp_path / "reports-original")
            report_root.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(coverage_module.os, "open", swap_ancestor_before_open)
    with pytest.raises(CoverageError):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/index.html",
                    "mapping": None,
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_report_tree_changes_during_inventory_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"main\n"})
    report_root = tmp_path / "reports"
    report_root.mkdir()
    entry = report_root / "index.html"
    entry.write_bytes(b"coverage\n")
    original_read = coverage_module._read_regular
    changed = False

    def add_file_after_read(
        root: Path, relative_path: str, *, display_path: str | None = None
    ) -> bytes:
        nonlocal changed
        content = original_read(root, relative_path, display_path=display_path)
        if not changed:
            changed = True
            (report_root / "late.bin").write_bytes(b"late\n")
        return content

    monkeypatch.setattr(coverage_module, "_read_regular", add_file_after_read)
    with pytest.raises(CoverageError, match="coverage.report_tree_changed"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/index.html",
                    "mapping": None,
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_report_tree_changes_during_sidecar_processing_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = {"index.html": b"original report\n"}
    digest = _report_digest("index.html", report)
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"main\n"})
    report_path = tmp_path / "reports" / "coverage" / "index.html"
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(report["index.html"])
    mapping_path = tmp_path / "evidence" / "coverage-map.json"
    mapping_path.parent.mkdir()
    mapping_path.write_bytes(
        canonical_json(
            {
                "schema": "osqar.inspector.coverage-map.v1",
                "report": {"entry_point": "index.html", "tree_sha256": digest},
                "relations": [],
            }
        )
    )
    original_parse_sidecar = coverage_module._parse_sidecar

    def mutate_report_after_sidecar_read(
        root: Path, configured_path: str, *, kind: str
    ) -> tuple[dict[str, Any], coverage_module.CoverageSidecarArtifact]:
        result = original_parse_sidecar(root, configured_path, kind=kind)
        report_path.write_bytes(b"changed during sidecar processing\n")
        return result

    monkeypatch.setattr(coverage_module, "_parse_sidecar", mutate_report_after_sidecar_read)
    with pytest.raises(CoverageError, match="coverage.report_tree_changed"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": "evidence/coverage-map.json",
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_report_file_symlink_swap_during_inventory_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"main\n"})
    report_root = tmp_path / "reports"
    report_root.mkdir()
    entry = report_root / "index.html"
    entry.write_bytes(b"coverage\n")
    outside = tmp_path / "outside.html"
    outside.write_bytes(b"outside\n")
    original_read = coverage_module._read_regular
    changed = False

    def swap_before_read(
        root: Path, relative_path: str, *, display_path: str | None = None
    ) -> bytes:
        nonlocal changed
        if not changed:
            changed = True
            path = root.joinpath(*PurePosixPath(relative_path).parts)
            path.unlink()
            path.symlink_to(outside)
        return original_read(root, relative_path, display_path=display_path)

    monkeypatch.setattr(coverage_module, "_read_regular", swap_before_read)
    with pytest.raises(CoverageError):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/index.html",
                    "mapping": None,
                    "attestation": None,
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_unmapped_unknown_origin_report_remains_navigable(tmp_path: Path) -> None:
    report = b"<html>producer report</html>\r\n"
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"int main(void) { return 0; }\n"})
    entry = tmp_path / "reports" / "coverage" / "index.html"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(report)

    output = CoverageAdapter().ingest(
        {"coverage": {"report": "reports/coverage/index.html", "mapping": None, "attestation": None}},
        snapshot,
        tmp_path,
        configuration_identity=CONFIGURATION_IDENTITY,
    )

    assert output.provenance is CoverageProvenance.UNKNOWN_ORIGIN
    assert output.mapping_valid is False
    assert output.attestation_valid is False
    assert output.relations == ()
    assert output.artifacts[0].content == report
    assert output.artifacts[0].entry_point is True


def test_coverage_declaration_requires_no_producer_execution(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"int main(void) { return 0; }\n"})
    config = {
        "coverage": {
            "report": "reports/coverage/index.html",
            "mapping": None,
            "attestation": None,
        }
    }

    diagnostics, capability = CoverageAdapter().validate_declaration(config)
    declaration = CoverageAdapter().plan_declaration(config, snapshot)

    assert diagnostics == ()
    assert capability.executable is None
    assert declaration.selector == "builtin.coverage-ingest.v1"
    assert declaration.invocation == ("{inspector.executable}", "ingest-coverage")


def test_report_tree_mutation_invalidates_mapping_and_attestation(tmp_path: Path) -> None:
    original = {"index.html": b"original report\n"}
    digest = _report_digest("index.html", original)
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"int main(void) { return 0; }\n"})
    inputs = {
        "reports/coverage/index.html": original["index.html"],
        "evidence/coverage-map.json": canonical_json(
            {
                "schema": "osqar.inspector.coverage-map.v1",
                "report": {"entry_point": "index.html", "tree_sha256": digest},
                "relations": [],
            }
        ),
        "evidence/coverage-attestation.json": _attestation(digest, snapshot.snapshot_id),
    }
    for path, content in inputs.items():
        destination = tmp_path.joinpath(*path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    (tmp_path / "reports" / "coverage" / "index.html").write_bytes(b"mutated report\n")

    with pytest.raises(CoverageError, match="coverage.mapping_report_mismatch"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": "evidence/coverage-map.json",
                    "attestation": "evidence/coverage-attestation.json",
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )


def test_snapshot_or_configuration_mismatch_is_not_upgraded(tmp_path: Path) -> None:
    report = {"index.html": b"coverage\n"}
    digest = _report_digest("index.html", report)
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"int main(void) { return 0; }\n"})
    for path, content in {
        "reports/coverage/index.html": report["index.html"],
        "evidence/coverage-attestation.json": _attestation(
            digest, "snapshot:sha256:" + "9" * 64
        ),
    }.items():
        destination = tmp_path.joinpath(*path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    snapshot_mismatch = CoverageAdapter().ingest(
        {
            "coverage": {
                "report": "reports/coverage/index.html",
                "mapping": None,
                "attestation": "evidence/coverage-attestation.json",
            }
        },
        snapshot,
        tmp_path,
        configuration_identity=CONFIGURATION_IDENTITY,
    )
    assert snapshot_mismatch.provenance is CoverageProvenance.UNKNOWN_ORIGIN
    assert snapshot_mismatch.attestation_valid is False
    assert snapshot_mismatch.diagnostics == ("coverage.attestation_snapshot_mismatch",)

    (tmp_path / "evidence" / "coverage-attestation.json").write_bytes(
        _attestation(digest, snapshot.snapshot_id)
    )
    with pytest.raises(CoverageError, match="coverage.invalid_configuration_identity"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": None,
                    "attestation": "evidence/coverage-attestation.json",
                }
            },
            snapshot,
            tmp_path,
            configuration_identity={"resolved": {"sha256": "c" * 64}},
        )

    configuration_mismatch = CoverageAdapter().ingest(
        {
            "coverage": {
                "report": "reports/coverage/index.html",
                "mapping": None,
                "attestation": "evidence/coverage-attestation.json",
            }
        },
        snapshot,
        tmp_path,
        configuration_identity={
            **CONFIGURATION_IDENTITY,
            "overrides": [{"pointer": "/coverage/report", "value": "other/index.html"}],
        },
    )
    assert configuration_mismatch.provenance is CoverageProvenance.UNKNOWN_ORIGIN
    assert configuration_mismatch.diagnostics == (
        "coverage.attestation_configuration_mismatch",
    )


@pytest.mark.parametrize(
    "overrides",
    [
        [{"pointer": "not-a-json-pointer", "value": None}],
        [
            {"pointer": "/coverage", "value": None},
            {"pointer": "/coverage", "value": None},
        ],
        [
            {"pointer": "/z", "value": None},
            {"pointer": "/a", "value": None},
        ],
        [
            {"pointer": "/coverage", "value": None},
            {"pointer": "/coverage/report", "value": None},
        ],
    ],
    ids=("malformed", "duplicate", "unsorted", "overlapping"),
)
def test_noncanonical_configuration_identity_cannot_be_attested(
    tmp_path: Path, overrides: list[dict[str, Any]]
) -> None:
    report = {"index.html": b"coverage\n"}
    digest = _report_digest("index.html", report)
    snapshot = _write_snapshot(tmp_path, {"src/main.c": b"main\n"})
    identity = {**CONFIGURATION_IDENTITY, "overrides": overrides}
    attestation = _attestation(
        digest,
        snapshot.snapshot_id,
        hashlib.sha256(canonical_json(identity)).hexdigest(),
    )
    for path, content in {
        "reports/coverage/index.html": report["index.html"],
        "evidence/coverage-attestation.json": attestation,
    }.items():
        destination = tmp_path.joinpath(*path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    with pytest.raises(CoverageError, match="coverage.invalid_configuration_identity"):
        CoverageAdapter().ingest(
            {
                "coverage": {
                    "report": "reports/coverage/index.html",
                    "mapping": None,
                    "attestation": "evidence/coverage-attestation.json",
                }
            },
            snapshot,
            tmp_path,
            configuration_identity=identity,
        )


def test_ambiguous_source_and_escaping_report_paths_fail(tmp_path: Path) -> None:
    report = {"index.html": b"coverage\n"}
    digest = _report_digest("index.html", report)
    snapshot = _write_snapshot(
        tmp_path,
        {
            "src/one/widget.c": b"one\n",
            "src/two/widget.c": b"two\n",
        },
    )
    entry = tmp_path / "reports" / "coverage" / "index.html"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(report["index.html"])
    mapping_path = tmp_path / "evidence" / "coverage-map.json"
    mapping_path.parent.mkdir(parents=True)

    def write_mapping(report_path: str, source_path: str) -> None:
        mapping_path.write_bytes(
            canonical_json(
                {
                    "schema": "osqar.inspector.coverage-map.v1",
                    "report": {"entry_point": "index.html", "tree_sha256": digest},
                    "relations": [
                        {
                            "fragment": None,
                            "line": None,
                            "report_path": report_path,
                            "source_path": source_path,
                            "symbol": None,
                        }
                    ],
                }
            )
        )

    configuration = {
        "coverage": {
            "report": "reports/coverage/index.html",
            "mapping": "evidence/coverage-map.json",
            "attestation": None,
        }
    }
    write_mapping("index.html", "widget.c")
    with pytest.raises(CoverageError, match="coverage.ambiguous_source"):
        CoverageAdapter().ingest(
            configuration,
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )

    write_mapping("../outside.html", "src/one/widget.c")
    with pytest.raises(CoverageError, match="coverage.invalid_path"):
        CoverageAdapter().ingest(
            configuration,
            snapshot,
            tmp_path,
            configuration_identity=CONFIGURATION_IDENTITY,
        )
