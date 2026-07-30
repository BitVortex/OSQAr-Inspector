from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow_text() -> str:
    assert WORKFLOW.is_file(), "issue #28 requires .github/workflows/ci.yml"
    return WORKFLOW.read_text(encoding="utf-8")


def test_ci_workflow_runs_required_matrix_and_baseline() -> None:
    text = _workflow_text()
    assert "pull_request:" in text
    assert re.search(r"push:\s+branches: \[main\]", text)
    assert "permissions:\n  contents: read" in text
    assert "runs-on: ubuntu-latest" in text
    assert "fail-fast: false" in text
    assert 'python-version: ["3.12", "3.13"]' in text
    assert 'CI: "1"' in text
    assert "UV_PYTHON: ${{ matrix.python-version }}" in text
    assert "BASE_REVISION: ${{ github.event.pull_request.base.sha || github.event.before }}" in text


def test_ci_workflow_runs_all_issue_28_gates() -> None:
    text = _workflow_text()
    assert re.search(r"actions/checkout@[0-9a-f]{40} # v4", text)
    assert "fetch-depth: 0" in text
    assert "persist-credentials: false" in text
    assert re.search(r"astral-sh/setup-uv@[0-9a-f]{40} # v6", text)
    assert "enable-cache: true" in text
    assert "python-version: ${{ matrix.python-version }}" in text
    assert "sudo apt-get install --yes doxygen" in text
    assert "uv sync --locked" in text
    assert "uv run pytest -q" in text
    assert 'uv run python tests/probes/contract_change.py "$BASE_REVISION"' in text
    assert "uv build" in text
    assert "uv run python -m osqar_inspector.release_gate dist/*" in text
    assert "uv run python tests/probes/installed_package.py dist/*.whl" in text


def test_ci_workflow_publishes_lane_specific_verified_distributions() -> None:
    text = _workflow_text()
    assert "sha256sum dist/*.whl dist/*.tar.gz > SHA256SUMS" in text
    assert re.search(r"actions/upload-artifact@[0-9a-f]{40} # v4", text)
    assert "name: distributions-python-${{ matrix.python-version }}" in text
    assert "if-no-files-found: error" in text
    assert "dist/*.whl" in text
    assert "dist/*.tar.gz" in text
    assert "SHA256SUMS" in text
