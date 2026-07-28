from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from osqar_inspector.artifact_graph import EdgeKind, NodeKind, build_artifact_graph
from osqar_inspector.navigation import render_navigation
from osqar_inspector.stage_result import StageStatus

from test_artifact_graph import (
    API_CONTENT,
    COVERAGE_CONTENT,
    _api,
    _coverage,
    _snapshot,
    _stage,
    _stage_record,
)


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_renderer_links_to_preserved_producer_artifacts(tmp_path: Path) -> None:
    producer = tmp_path / "artifacts"
    api_payload = producer / "api" / "html" / "widget.html"
    coverage_payload = producer / "coverage" / "index.html"
    api_payload.parent.mkdir(parents=True)
    coverage_payload.parent.mkdir(parents=True)
    api_payload.write_bytes(API_CONTENT)
    coverage_payload.write_bytes(COVERAGE_CONTENT)
    before = _tree_hashes(producer)

    graph = build_artifact_graph(
        _snapshot("src/widget.c"),
        api_output=_api(),
        coverage_output=_coverage(),
        stage_results=(
            _stage("optional-api-review", StageStatus.SKIPPED),
            _stage("optional-coverage-review", StageStatus.DEGRADED),
        ),
    )
    first = render_navigation(graph, tmp_path / "navigation-one")
    second = render_navigation(graph, tmp_path / "navigation-two")

    assert [(item.path, item.content) for item in first.files] == [
        (item.path, item.content) for item in second.files
    ]
    index = (tmp_path / "navigation-one" / "index.html").read_text(encoding="utf-8")
    provenance = (tmp_path / "navigation-one" / "provenance.html").read_text(
        encoding="utf-8"
    )
    assert '../artifacts/api/html/widget.html' in index
    assert '../artifacts/api/html/widget.html#run' in index
    assert '../artifacts/coverage/index.html' in index
    assert '../artifacts/coverage/index.html#line-2' in index
    assert "skipped" in index
    assert "degraded" in index
    assert "externally-attested" in index
    assert '../artifacts/api/html/widget.html' in provenance
    assert '../artifacts/coverage/index.html' in provenance
    assert "does not establish evidence adequacy" in index
    assert "node: symbol:sha256:" in index
    assert before == _tree_hashes(producer)
    assert len(
        [node for node in first.graph.nodes if node.kind is NodeKind.RENDERED_NAVIGATION_ARTIFACT]
    ) == 3
    assert any(edge.kind is EdgeKind.LINKS_TO for edge in first.graph.edges)
    rendered_content = {
        "navigation/" + item.path: item.content.decode("utf-8") for item in first.files
    }
    nodes_by_id = {node.node_id: node for node in first.graph.nodes}
    for edge in first.graph.edges:
        if edge.kind is not EdgeKind.LINKS_TO:
            continue
        page = nodes_by_id[edge.source]
        assert page.path is not None
        assert rendered_content[page.path].count(edge.target) == 1
    assert first.graph == second.graph


def test_renderer_rejects_unresolved_or_duplicate_producer_fragments(tmp_path: Path) -> None:
    for name, content in (
        ("missing", b"<html>no anchor</html>\n"),
        ("duplicate", b'<a id="run"></a><span id="run"></span>\n'),
        ("legacy-name-on-div", b'<div name="run"></div>\n'),
    ):
        payload = tmp_path / name / "artifacts" / "api" / "html" / "widget.html"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(content)
        graph = build_artifact_graph(
            _snapshot("src/widget.c"), api_output=_api(content=content)
        )
        with pytest.raises(ValueError, match="does not resolve exactly once"):
            render_navigation(graph, tmp_path / name / "navigation")


def test_renderer_rejects_producer_digest_mismatch(tmp_path: Path) -> None:
    payload = tmp_path / "artifacts" / "api" / "html" / "widget.html"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(API_CONTENT + b"changed")
    graph = build_artifact_graph(_snapshot("src/widget.c"), api_output=_api())

    with pytest.raises(ValueError, match="digest mismatch"):
        render_navigation(graph, tmp_path / "navigation")


def test_renderer_does_not_rewrite_producer_payloads(tmp_path: Path) -> None:
    producer = tmp_path / "artifacts"
    payload = producer / "api" / "html" / "widget.html"
    payload.parent.mkdir(parents=True)
    original = b"\xff\x00producer bytes that are not UTF-8\r\n"
    payload.write_bytes(original)

    api_output = _api(content=original)
    graph = build_artifact_graph(
        _snapshot("src/widget.c"), api_output=replace(api_output, mappings=())
    )
    render_navigation(graph, tmp_path / "navigation")

    assert payload.read_bytes() == original
    assert hashlib.sha256(payload.read_bytes()).hexdigest() == hashlib.sha256(original).hexdigest()


def test_renderer_writes_through_held_directory_not_replaceable_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside.html"
    outside.write_bytes(b"outside sentinel")
    navigation = tmp_path / "navigation"
    navigation.mkdir()
    original_write = Path.write_bytes
    intercepted = False

    def replace_destination_before_write(path: Path, content: bytes) -> int:
        nonlocal intercepted
        if path.name == "index.html":
            intercepted = True
            path.symlink_to(outside)
        return original_write(path, content)

    monkeypatch.setattr(Path, "write_bytes", replace_destination_before_write)
    render_navigation(build_artifact_graph(_snapshot("src/widget.c")), navigation)

    assert intercepted is False
    assert outside.read_bytes() == b"outside sentinel"


def test_output_directory_descriptors_close_when_identity_read_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        pytest.skip("descriptor inventory is unavailable")
    before = len(os.listdir(descriptor_directory))

    def fail_identity_read(descriptor: int) -> os.stat_result:
        raise OSError("injected identity read failure")

    monkeypatch.setattr("osqar_inspector.navigation.os.fstat", fail_identity_read)
    with pytest.raises(OSError, match="injected identity read failure"):
        render_navigation(build_artifact_graph(_snapshot("src/widget.c")), tmp_path / "navigation")

    assert len(os.listdir(descriptor_directory)) == before


@pytest.mark.parametrize(
    "operation",
    (
        "temporary-open",
        "write",
        "file-fsync",
        "close",
        "replace",
        "readback",
        "directory-fsync",
        "final-stat",
        "graph-augmentation",
    ),
)
def test_renderer_cleans_descriptors_and_temporaries_after_injected_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        pytest.skip("descriptor inventory is unavailable")
    before = len(os.listdir(descriptor_directory))
    navigation = tmp_path / "navigation"

    if operation == "temporary-open":
        real_open = os.open

        def fail_temporary_open(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
            if isinstance(path, str) and ".tmp-" in path:
                raise OSError("injected temporary open failure")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr("osqar_inspector.navigation.os.open", fail_temporary_open)
    elif operation == "write":
        monkeypatch.setattr(
            "osqar_inspector.navigation.os.write",
            lambda descriptor, content: (_ for _ in ()).throw(OSError("injected write failure")),
        )
    elif operation in {"file-fsync", "directory-fsync"}:
        real_fsync = os.fsync
        calls = 0

        def fail_selected_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            selected = 1 if operation == "file-fsync" else 4
            if calls == selected:
                raise OSError("injected fsync failure")
            real_fsync(descriptor)

        monkeypatch.setattr("osqar_inspector.navigation.os.fsync", fail_selected_fsync)
    elif operation == "close":
        real_close = os.close
        injected = False

        def fail_after_temporary_close(descriptor: int) -> None:
            nonlocal injected
            try:
                target = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                target = ""
            if not injected and ".tmp-" in target:
                injected = True
                real_close(descriptor)
                raise OSError("injected close failure")
            real_close(descriptor)

        monkeypatch.setattr("osqar_inspector.navigation.os.close", fail_after_temporary_close)
    elif operation == "replace":
        monkeypatch.setattr(
            "osqar_inspector.navigation.os.replace",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected replace failure")),
        )
    elif operation == "readback":
        monkeypatch.setattr(
            "osqar_inspector.navigation._read_owned_file",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected readback failure")),
        )
    elif operation == "final-stat":
        real_stat = os.stat

        def fail_final_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if kwargs.get("dir_fd") is not None:
                raise OSError("injected final stat failure")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr("osqar_inspector.navigation.os.stat", fail_final_stat)
    else:
        monkeypatch.setattr(
            "osqar_inspector.navigation.add_rendered_navigation",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected graph failure")),
        )

    with pytest.raises(OSError, match="injected"):
        render_navigation(build_artifact_graph(_snapshot("src/widget.c")), navigation)

    assert len(os.listdir(descriptor_directory)) == before
    assert not list(navigation.glob(".*.tmp-*"))


@pytest.mark.parametrize(
    ("include_api", "include_coverage", "status"),
    [
        (True, False, "skipped"),
        (False, True, "degraded"),
        (True, True, "failed"),
    ],
)
def test_renderer_supports_partial_combined_and_failed_stage_views(
    tmp_path: Path,
    include_api: bool,
    include_coverage: bool,
    status: str,
) -> None:
    if include_api:
        api = tmp_path / "artifacts" / "api" / "html" / "widget.html"
        api.parent.mkdir(parents=True)
        api.write_bytes(API_CONTENT)
    if include_coverage:
        coverage = tmp_path / "artifacts" / "coverage" / "index.html"
        coverage.parent.mkdir(parents=True)
        coverage.write_bytes(COVERAGE_CONTENT)
    graph = build_artifact_graph(
        _snapshot("src/widget.c"),
        api_output=_api() if include_api else None,
        coverage_output=_coverage() if include_coverage else None,
        stage_results=(_stage_record("evidence", StageStatus(status)),),
    )

    result = render_navigation(graph, tmp_path / f"navigation-{status}")
    index = next(item.content for item in result.files if item.path == "index.html").decode()
    assert status in index
    assert ("API artifacts" in index) is include_api
    assert ("Coverage artifacts" in index) is include_coverage


def test_renderer_rejects_producer_mutation_during_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = tmp_path / "artifacts" / "api" / "html" / "widget.html"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(API_CONTENT)
    graph = build_artifact_graph(_snapshot("src/widget.c"), api_output=_api())
    from osqar_inspector import navigation as navigation_module

    original_write = navigation_module._write_owned_file
    mutated = False

    def mutate_after_first_write(directory_fd: int, name: str, content: bytes) -> None:
        nonlocal mutated
        original_write(directory_fd, name, content)
        if not mutated:
            mutated = True
            payload.write_bytes(API_CONTENT + b"changed")

    monkeypatch.setattr(navigation_module, "_write_owned_file", mutate_after_first_write)
    with pytest.raises(ValueError, match="digest mismatch"):
        render_navigation(graph, tmp_path / "navigation")
