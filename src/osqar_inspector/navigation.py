"""Deterministic Inspector-owned navigation rendering."""

from __future__ import annotations

import hashlib
import html
import os
import secrets
import stat
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote

from .artifact_graph import (
    ArtifactGraph,
    ArtifactNode,
    EdgeKind,
    NodeKind,
    RenderedNavigationArtifact,
    add_rendered_navigation,
    validate_artifact_graph,
)

_MARKER = '<meta name="generator" content="osqar-inspector-navigation-v1">'
_CLAIM_BOUNDARY = (
    "This mechanical navigation exposes validated identities and relationships. "
    "It does not establish evidence adequacy, substantive correctness, software or "
    "tool qualification, standards compliance, certification, functional safety, "
    "security, or fitness for use."
)


@dataclass(frozen=True)
class NavigationFile:
    path: str
    content: bytes
    sha256: str


@dataclass(frozen=True)
class NavigationOutput:
    files: tuple[NavigationFile, ...]
    graph: ArtifactGraph


class _AnchorCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if (name == "id" or (tag == "a" and name == "name")) and value is not None:
                self.anchors.append(value)


def _validate_producer_targets(graph: ArtifactGraph, root_parent: Path) -> None:
    """Bind graph digests and fragments to exact producer bytes before rendering links."""

    producer_kinds = {
        NodeKind.API_PAGE,
        NodeKind.COVERAGE_REPORT,
        NodeKind.COVERAGE_PAGE,
        NodeKind.COVERAGE_SUMMARY,
        NodeKind.COVERAGE_SIDECAR,
        NodeKind.PRODUCER_LOG,
    }
    by_id = {node.node_id: node for node in graph.nodes}
    required_fragments: dict[str, list[str]] = {}
    for node in graph.nodes:
        if node.kind is NodeKind.SYMBOL and node.path is not None and node.fragment:
            required_fragments.setdefault(node.path, []).append(node.fragment)
    for edge in graph.edges:
        if edge.kind in {EdgeKind.COVERS_SOURCE, EdgeKind.COVERS_SYMBOL} and edge.fragment:
            report = by_id[edge.source]
            if report.path is not None:
                required_fragments.setdefault(report.path, []).append(edge.fragment)

    for node in graph.nodes:
        if node.kind not in producer_kinds or node.path is None or node.sha256 is None:
            continue
        path = root_parent / node.path
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ValueError(f"producer artifact is unavailable: {node.path}") from error
        if hashlib.sha256(payload).hexdigest() != node.sha256:
            raise ValueError(f"producer artifact digest mismatch: {node.path}")
        fragments = required_fragments.get(node.path, ())
        if fragments:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"producer HTML is not UTF-8: {node.path}") from error
            collector = _AnchorCollector()
            collector.feed(text)
            for fragment in set(fragments):
                if collector.anchors.count(fragment) != 1:
                    raise ValueError(
                        f"producer fragment does not resolve exactly once: {node.path}#{fragment}"
                    )


def _document(title: str, body: str) -> bytes:
    text = (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f"{_MARKER}\n"
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n"
        "</head>\n<body>\n"
        f"<header><h1>{html.escape(title)}</h1>"
        '<nav><a href="index.html">Artifacts</a> | '
        '<a href="stages.html">Stages</a> | '
        '<a href="provenance.html">Provenance and claim boundary</a></nav></header>\n'
        f"{body}\n"
        "</body>\n</html>\n"
    )
    return text.encode("utf-8")


def _artifact_href(node: ArtifactNode) -> str | None:
    if node.path is None or not node.path.startswith("artifacts/"):
        return None
    target = "../" + quote(node.path, safe="/")
    if node.fragment:
        target += "#" + quote(node.fragment, safe="")
    return target


def _artifact_list(nodes: list[ArtifactNode]) -> str:
    if not nodes:
        return "<p>None.</p>"
    items: list[str] = []
    for node in nodes:
        label = html.escape(node.label)
        href = _artifact_href(node)
        link = f'<a href="{html.escape(href, quote=True)}">{label}</a>' if href else label
        details = ["node: " + html.escape(node.node_id)]
        if node.provenance is not None:
            details.append("provenance: " + html.escape(node.provenance))
        if node.sha256 is not None:
            details.append("SHA-256: " + html.escape(node.sha256))
        suffix = f" <small>({' ; '.join(details)})</small>" if details else ""
        items.append(f"<li>{link}{suffix}</li>")
    return "<ul>" + "".join(items) + "</ul>"


def _stage_list(nodes: list[ArtifactNode]) -> str:
    if not nodes:
        return "<p>No stage results are present.</p>"
    return "<ul>" + "".join(
        f"<li>{html.escape(node.label)}: "
        f"<strong>{html.escape(node.stage_status or 'unknown')}</strong> "
        f"<small>(node: {html.escape(node.node_id)})</small></li>"
        for node in nodes
    ) + "</ul>"


def _coverage_relation_list(graph: ArtifactGraph) -> str:
    by_id = {node.node_id: node for node in graph.nodes}
    items: list[str] = []
    for edge in graph.edges:
        if edge.kind is not EdgeKind.COVERS_SOURCE:
            continue
        report = by_id[edge.source]
        source = by_id[edge.target]
        href = _artifact_href(
            ArtifactNode(
                report.node_id,
                report.kind,
                report.label,
                report.path,
                edge.fragment,
                report.sha256,
                report.provenance,
                report.stage_status,
                report.identity_sha256,
                report.identity_json,
            )
        )
        label = html.escape(source.label)
        if edge.line is not None:
            label += f":{edge.line}"
        link = (
            f'<a href="{html.escape(href, quote=True)}">{label}</a>'
            if href is not None
            else label
        )
        items.append(f"<li>{link}</li>")
    return "<ul>" + "".join(items) + "</ul>" if items else "<p>None.</p>"


def _index(graph: ArtifactGraph) -> bytes:
    sources = [node for node in graph.nodes if node.kind is NodeKind.SOURCE_FILE]
    symbols = [node for node in graph.nodes if node.kind is NodeKind.SYMBOL]
    api = [
        node
        for node in graph.nodes
        if node.kind in {NodeKind.API_PAGE, NodeKind.API_ARTIFACT}
    ]
    coverage = [
        node
        for node in graph.nodes
        if node.kind
        in {NodeKind.COVERAGE_REPORT, NodeKind.COVERAGE_PAGE, NodeKind.COVERAGE_SUMMARY}
    ]
    logs = [node for node in graph.nodes if node.kind is NodeKind.PRODUCER_LOG]
    sidecars = [node for node in graph.nodes if node.kind is NodeKind.COVERAGE_SIDECAR]
    stage_outputs = [node for node in graph.nodes if node.kind is NodeKind.STAGE_OUTPUT]
    snapshot = next(node for node in graph.nodes if node.kind is NodeKind.SNAPSHOT)
    sections: list[str] = [
        (
            f"<p>Snapshot: <code>{html.escape(graph.snapshot_id)}</code> "
            f"<small>(node: {html.escape(snapshot.node_id)})</small></p>"
        ),
    ]
    if api:
        sections.extend(("<section><h2>API artifacts</h2>", _artifact_list(api), "</section>"))
    if sources:
        sections.extend(("<section><h2>Source files</h2>", _artifact_list(sources), "</section>"))
    if symbols:
        sections.extend(("<section><h2>Documented symbols</h2>", _artifact_list(symbols), "</section>"))
    if coverage:
        sections.extend(
            ("<section><h2>Coverage artifacts</h2>", _artifact_list(coverage), "</section>")
        )
        sections.extend(
            (
                "<section><h2>Coverage relations</h2>",
                _coverage_relation_list(graph),
                "</section>",
            )
        )
    if logs:
        sections.extend(("<section><h2>Producer logs</h2>", _artifact_list(logs), "</section>"))
    if sidecars:
        sections.extend(
            ("<section><h2>Coverage sidecars</h2>", _artifact_list(sidecars), "</section>")
        )
    if stage_outputs:
        sections.extend(
            ("<section><h2>Stage outputs</h2>", _artifact_list(stage_outputs), "</section>")
        )
    if not (api or coverage or logs or sidecars or sources or stage_outputs or symbols):
        sections.append("<p>No producer artifacts are present in this graph.</p>")
    stages = [node for node in graph.nodes if node.kind is NodeKind.STAGE_RESULT]
    if stages:
        sections.extend(("<section><h2>Stage states</h2>", _stage_list(stages), "</section>"))
    provenance = sorted(
        {node.provenance for node in graph.nodes if node.provenance is not None},
        key=str.encode,
    )
    if provenance:
        sections.append(
            "<p>Provenance states: "
            + ", ".join(f"<code>{html.escape(value)}</code>" for value in provenance)
            + ".</p>"
        )
    sections.append(f"<p>{html.escape(_CLAIM_BOUNDARY)}</p>")
    return _document("OSQAr Inspector artifact navigation", "\n".join(sections))


def _stages(graph: ArtifactGraph) -> bytes:
    stages = [node for node in graph.nodes if node.kind is NodeKind.STAGE_RESULT]
    return _document("Inspector stage states", _stage_list(stages))


def _provenance(graph: ArtifactGraph) -> bytes:
    artifacts = [node for node in graph.nodes if node.provenance is not None]
    states = sorted(
        {node.provenance for node in artifacts if node.provenance is not None},
        key=str.encode,
    )
    body = (
        "<h2>Observed provenance states</h2>"
        + (
            "<ul>" + "".join(f"<li>{html.escape(state)}</li>" for state in states) + "</ul>"
            if states
            else "<p>No producer provenance state is present.</p>"
        )
        + "<h2>Artifacts carrying provenance</h2>"
        + _artifact_list(artifacts)
        + "<h2>Claim boundary</h2>"
        + f"<p>{html.escape(_CLAIM_BOUNDARY)}</p>"
    )
    return _document("Inspector provenance", body)


def _read_owned_file(directory_fd: int, name: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("navigation output contains a non-owned entry")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_owned_file(directory_fd: int, name: str, content: bytes) -> None:
    temporary = f".{name}.tmp-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o644, dir_fd=directory_fd)
    published = False
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("navigation write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        closing_descriptor = descriptor
        descriptor = -1
        try:
            os.close(closing_descriptor)
        except BaseException:
            try:
                os.close(closing_descriptor)
            except OSError:
                pass
            raise
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        published = True
        if _read_owned_file(directory_fd, name) != content:
            raise OSError("navigation output changed after publication")
    finally:
        try:
            if descriptor >= 0:
                os.close(descriptor)
        finally:
            if not published:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass


def _open_output_directory(root: Path) -> tuple[int, int, os.stat_result]:
    if root.name in {"", ".", ".."}:
        raise ValueError("navigation output must name a child directory")
    root.parent.mkdir(parents=True, exist_ok=True)
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    parent_fd = os.open(root.parent, parent_flags)
    try:
        try:
            os.mkdir(root.name, 0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
        root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            root_flags |= os.O_NOFOLLOW
        root_fd = os.open(root.name, root_flags, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        identity = os.fstat(root_fd)
    except BaseException:
        try:
            os.close(root_fd)
        finally:
            os.close(parent_fd)
        raise
    return parent_fd, root_fd, identity


def render_navigation(graph: ArtifactGraph, output_directory: str | Path) -> NavigationOutput:
    """Write only deterministic Inspector-owned pages; producer paths are link targets."""

    validate_artifact_graph(graph)
    rendered = {
        "index.html": _index(graph),
        "provenance.html": _provenance(graph),
        "stages.html": _stages(graph),
    }
    index_kinds = {
        NodeKind.SNAPSHOT,
        NodeKind.SOURCE_FILE,
        NodeKind.SYMBOL,
        NodeKind.API_PAGE,
        NodeKind.API_ARTIFACT,
        NodeKind.COVERAGE_REPORT,
        NodeKind.COVERAGE_PAGE,
        NodeKind.COVERAGE_SUMMARY,
        NodeKind.COVERAGE_SIDECAR,
        NodeKind.PRODUCER_LOG,
        NodeKind.STAGE_OUTPUT,
        NodeKind.STAGE_RESULT,
    }
    page_targets = {
        "index.html": tuple(
            node.node_id for node in graph.nodes if node.kind in index_kinds
        ),
        "provenance.html": tuple(
            node.node_id for node in graph.nodes if node.provenance is not None
        ),
        "stages.html": tuple(
            node.node_id for node in graph.nodes if node.kind is NodeKind.STAGE_RESULT
        ),
    }
    root = Path(output_directory)
    _validate_producer_targets(graph, root.parent)
    parent_fd, root_fd, root_identity = _open_output_directory(root)
    try:
        for existing in os.listdir(root_fd):
            if existing not in rendered:
                raise ValueError("navigation output contains a non-owned entry")
            if _MARKER.encode() not in _read_owned_file(root_fd, existing):
                raise ValueError("navigation output contains a file not owned by this renderer")

        files: list[NavigationFile] = []
        for relative, content in sorted(rendered.items(), key=lambda item: item[0].encode()):
            _write_owned_file(root_fd, relative, content)
            files.append(
                NavigationFile(relative, content, hashlib.sha256(content).hexdigest())
            )
        os.fsync(root_fd)
        final = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (root_identity.st_dev, root_identity.st_ino):
            raise OSError("navigation output directory changed during rendering")
        _validate_producer_targets(graph, root.parent)
        augmented = add_rendered_navigation(
            graph,
            (
                RenderedNavigationArtifact(
                    "navigation/" + item.path,
                    item.sha256,
                    len(item.content),
                    page_targets[item.path],
                )
                for item in files
            ),
        )
        _validate_producer_targets(graph, root.parent)
        return NavigationOutput(tuple(files), augmented)
    finally:
        try:
            os.close(root_fd)
        finally:
            os.close(parent_fd)
