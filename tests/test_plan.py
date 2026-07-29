from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from types import SimpleNamespace

from osqar_inspector.configuration import canonical_json, resolve_configuration
from osqar_inspector.plan import create_plan


def _snapshot(*paths: str) -> SimpleNamespace:
    files = tuple(
        {
            "path": path,
            "kind": "file",
            "mode": "100644",
            "size": "0",
            "identity": {"sha256": "0" * 64},
        }
        for path in paths
    )
    manifest = {
        "schema": "osqar.inspector.snapshot.v1",
        "source": {
            "kind": "git-clean",
            "object_format": "sha1",
            "commit": "1" * 40,
            "tree": "2" * 40,
        },
        "policy": {"include": [], "exclude": []},
        "files": list(files),
        "snapshot_id": "snapshot:sha256:" + "3" * 64,
        "metadata": {"inspector_version": "0.1.0"},
    }
    return SimpleNamespace(
        manifest=manifest,
        snapshot_id=manifest["snapshot_id"],
        files=files,
    )


def test_plan_is_byte_deterministic_and_contains_unresolved_capabilities() -> None:
    configuration = resolve_configuration(
        b'{"schema":"osqar.inspector.config.v1"}', "inspector.json"
    )
    snapshot = _snapshot("Doxyfile", "src/main.c")

    first = create_plan(configuration, snapshot)
    second = create_plan(configuration, snapshot)

    assert first.plan_bytes == second.plan_bytes
    assert first.value == second.value
    assert first.value["schema"] == "osqar.inspector.plan.v1"
    assert first.value["configuration"] == configuration.identity
    assert first.value["snapshot"]["snapshot_id"] == snapshot.snapshot_id
    assert first.value["diagnostics"] == []
    assert first.blocked is False
    identity = {key: value for key, value in first.value.items() if key != "plan_digest"}
    assert first.value["plan_digest"] == hashlib.sha256(
        canonical_json({"kind": "plan", "identity": identity})
    ).hexdigest()
    assert [stage["id"] for stage in first.value["stages"]] == ["doxygen"]
    assert first.value["edges"] == [{"from": "snapshot", "to": "doxygen"}]
    stage = first.value["stages"][0]
    assert stage["dependencies"] == ["snapshot"]
    assert stage["policy"] == "required"
    assert stage["capability"] == {
        "executable": "doxygen",
        "status": "unresolved",
        "version_constraint": ">=1.9",
    }
    assert stage["invocation"]["argv"] == [
        "{capability.executable}",
        "{workspace.root}/Doxyfile.inspector",
    ]
    assert stage["expected_outputs"] == ["build/doxygen"]
    assert stage["required_inputs"] == ["Doxyfile"]
    assert stage["adapter_options"] == {"warnings_as_errors": False}


def test_static_required_prerequisite_blocks_plan() -> None:
    configuration = resolve_configuration(
        b'{"schema":"osqar.inspector.config.v1"}', "inspector.json"
    )

    result = create_plan(configuration, _snapshot("src/main.c"))

    assert result.blocked is True
    assert result.value["diagnostics"] == [
        {
            "blocking": True,
            "code": "plan.input_missing",
            "message": "selected snapshot does not contain 'Doxyfile'",
            "stage": "doxygen",
        }
    ]


def test_plan_contract_has_a_shipped_closed_schema() -> None:
    schema = json.loads(
        files("osqar_inspector").joinpath("resources/plan-v1.schema.json").read_bytes()
    )

    assert schema["$id"] == "osqar.inspector.plan.v1"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "configuration",
        "diagnostics",
        "edges",
        "plan_digest",
        "schema",
        "snapshot",
        "stages",
    }
    identity = schema["properties"]["snapshot"]["properties"]["files"]["items"][
        "properties"
    ]["identity"]
    assert identity == {
        "oneOf": [
            {"$ref": "#/$defs/fileIdentity"},
            {"$ref": "#/$defs/symlinkIdentity"},
        ]
    }
    assert schema["$defs"]["fileIdentity"]["additionalProperties"] is False
    assert schema["$defs"]["symlinkIdentity"]["additionalProperties"] is False
    stage_schema = schema["properties"]["stages"]["items"]
    assert "required_inputs" in stage_schema["required"]
    assert "required_inputs" in stage_schema["properties"]
