from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).parents[1]
DOCS = ROOT / "docs"
PAGES_BASE = "https://bitvortex.github.io/OSQAr-Inspector/"
LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^) ]+)(?:\s+['\"][^'\"]+['\"])?\)")


def _markdown_files() -> list[Path]:
    return [ROOT / "README.md", *sorted(DOCS.glob("*.md"))]


def _resolve_local_link(source: Path, target: str) -> Path | None:
    parsed = urlsplit(target)
    if parsed.scheme or target.startswith(("#", "/")):
        return None
    path = parsed.path
    if not path:
        return None
    candidate = (source.parent / path).resolve()
    if source.parent == DOCS and candidate.suffix == ".html":
        candidate = candidate.with_suffix(".md")
    return candidate


def _heading_anchors(source: Path) -> set[str]:
    anchors: set[str] = set()
    headings = re.findall(
        r"^#{1,6} +(.+?)\s*$",
        source.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    for heading in headings:
        plain = re.sub(r"[`*_]", "", heading).lower()
        slug = re.sub(r"[^a-z0-9 _-]", "", plain).strip().replace(" ", "-")
        if slug:
            anchors.add(slug)
    return anchors


def test_pages_has_a_landing_page_configuration_and_deployment_workflow() -> None:
    index = DOCS / "index.md"
    config = DOCS / "_config.yml"
    workflow = ROOT / ".github" / "workflows" / "pages.yml"
    assert index.is_file()
    assert config.is_file()
    assert workflow.is_file()

    workflow_text = workflow.read_text(encoding="utf-8")
    for action in (
        "actions/checkout",
        "actions/jekyll-build-pages",
        "actions/upload-pages-artifact",
        "actions/deploy-pages",
    ):
        assert re.search(rf"uses: {re.escape(action)}@[0-9a-f]{{40}}", workflow_text)
    assert "persist-credentials: false" in workflow_text
    assert not re.search(r"uses: actions/[^@]+@v\d+", workflow_text)
    assert "path: ./docs/_site" in workflow_text
    assert "enablement: true" not in workflow_text


def test_pages_sources_have_front_matter_and_one_h1() -> None:
    for source in sorted(DOCS.glob("*.md")):
        text = source.read_text(encoding="utf-8")
        assert text.startswith("---\n"), f"missing Jekyll front matter: {source}"
        assert len(re.findall(r"^# ", text, flags=re.MULTILINE)) == 1, source


def test_readme_uses_canonical_rendered_documentation_links() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"[Documentation]({PAGES_BASE})" in readme
    assert f"[Quickstart]({PAGES_BASE}getting-started.html)" in readme
    assert f"[OSQAr integration]({PAGES_BASE}osqar-integration.html)" in readme
    assert not re.search(r"\]\(docs/[^)]+\.md(?:#[^)]+)?\)", readme)


def test_markdown_local_links_resolve_in_source_and_pages() -> None:
    failures: list[str] = []
    for source in _markdown_files():
        text = source.read_text(encoding="utf-8")
        for target in LINK.findall(text):
            resolved = _resolve_local_link(source, target)
            if resolved is not None and not resolved.exists():
                failures.append(f"{source.relative_to(ROOT)} -> {target}")
            fragment = urlsplit(target).fragment
            if resolved is not None and resolved.suffix == ".md" and fragment:
                if fragment not in _heading_anchors(resolved):
                    failures.append(
                        f"{source.relative_to(ROOT)} -> {target} (missing anchor)"
                    )
    assert not failures, "broken local links:\n" + "\n".join(failures)


def test_canonical_pages_links_map_to_document_sources() -> None:
    failures: list[str] = []
    for source in _markdown_files():
        for target in LINK.findall(source.read_text(encoding="utf-8")):
            if not target.startswith(PAGES_BASE):
                continue
            parsed = urlsplit(target)
            relative = parsed.path.removeprefix("/OSQAr-Inspector/")
            page = DOCS / ("index.md" if not relative else relative)
            if page.suffix == ".html":
                page = page.with_suffix(".md")
            if not page.exists():
                failures.append(f"{source.relative_to(ROOT)} -> {target}")
            elif parsed.fragment and parsed.fragment not in _heading_anchors(page):
                failures.append(f"{source.relative_to(ROOT)} -> {target} (missing anchor)")
    assert not failures, "invalid canonical Pages links:\n" + "\n".join(failures)


def test_landing_pages_cover_the_requested_reader_journey() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    docs_index = (DOCS / "index.md").read_text(encoding="utf-8").lower()
    getting_started = (DOCS / "getting-started.md").read_text(encoding="utf-8").lower()

    for phrase in ("problems it solves", "quickstart", "how it works with osqar"):
        assert phrase in readme
    for phrase in ("start here", "use the tool", "understand the contracts"):
        assert phrase in docs_index
    for phrase in ("prerequisites", "configuration", "plan", "build", "verify"):
        assert phrase in getting_started


def test_public_documentation_uses_restrained_assurance_language() -> None:
    public_text = "\n".join(
        source.read_text(encoding="utf-8").lower() for source in _markdown_files()
    )
    for prohibited in (
        "qualified local linux filesystem",
        "certified tool",
        "qualified tool",
        "iso 26262 compliant",
    ):
        assert prohibited not in public_text
