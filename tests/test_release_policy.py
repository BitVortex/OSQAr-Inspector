from __future__ import annotations

import copy
import subprocess
from pathlib import Path

import pytest

from osqar_inspector.release_gate import (
    ContractPolicyError,
    load_release_policy,
    validate_contract_change,
)


def test_contract_change_requires_version_and_fixture_update() -> None:
    previous = {
        "package": {"version": "0.1.0"},
        "fixture_revision": 1,
    }

    version_only = copy.deepcopy(previous)
    version_only["package"]["version"] = "0.2.0"
    with pytest.raises(ContractPolicyError, match="fixture revision"):
        validate_contract_change(previous, version_only, contracts_changed=True)

    fixture_only = copy.deepcopy(previous)
    fixture_only["fixture_revision"] = 2
    with pytest.raises(ContractPolicyError, match="package version"):
        validate_contract_change(previous, fixture_only, contracts_changed=True)


def test_release_policy_binds_supported_versions_and_contract_assets() -> None:
    policy = load_release_policy()

    assert policy["package"] == {"name": "osqar-inspector", "version": "0.1.0"}
    assert policy["support"]["operating_systems"] == ["linux"]
    assert policy["support"]["python"] == ["3.12", "3.13"]
    assert policy["support"]["process_protocols"] == ["osqar-inspector-run-v1"]
    assert policy["contract_assets"]


def test_release_documentation_matches_implemented_commands() -> None:
    checkout = Path(__file__).resolve().parents[1]
    documentation = (checkout / "docs" / "release.md").read_text(encoding="utf-8")
    result = subprocess.run(
        ["uv", "run", "osqar-inspector", "--help"],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=True,
    )

    for command in ("capabilities", "plan", "build", "verify"):
        assert command in result.stdout
        assert f"`{command}`" in documentation
    for schema in load_release_policy()["support"]["schemas"]:
        assert f"`{schema}`" in documentation
    assert "Python 3.12 and 3.13" in documentation
    assert "Linux" in documentation
    assert "osqar-inspector-run-v1" in documentation
