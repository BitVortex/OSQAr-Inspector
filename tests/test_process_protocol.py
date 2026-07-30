from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from test_cli_plan import _git, _repository

from osqar_inspector import conformance
from osqar_inspector.cli import main
from osqar_inspector.configuration import canonical_json
from osqar_inspector.conformance import run_protocol_command
from osqar_inspector.process_protocol import (
    ProcessProtocolError,
    capabilities,
    validate_process_result,
    write_result,
)

PROTOCOL = "osqar-inspector-run-v1"


def test_capability_handshake_and_supported_schema_sets(
    tmp_path: Path, capsys
) -> None:
    result_file = tmp_path / "capabilities.json"

    status = main(
        [
            "capabilities",
            "--protocol",
            PROTOCOL,
            "--result-file",
            os.fspath(result_file),
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert captured.out == ""
    assert captured.err == ""
    assert result_file.read_bytes().endswith(b"}")
    result = json.loads(result_file.read_bytes())
    assert result == {
        "inspector_version": version("osqar-inspector"),
        "protocol": PROTOCOL,
        "schema": "osqar.inspector.capabilities-result.v1",
        "supported_schemas": {
            "bundle": ["osqar.inspector.bundle-manifest.v1"],
            "config": ["osqar.inspector.config.v1"],
            "plan": ["osqar.inspector.plan.v1"],
            "publication-result": ["osqar.inspector.publication-result.v1"],
            "run-report": ["osqar.inspector.run.v1"],
            "signature-envelope": ["osqar.inspector.detached-signature.v1"],
            "snapshot": ["osqar.inspector.snapshot.v1"],
            "stage-result": ["osqar.inspector.stage-result.v1"],
        },
    }


def test_plan_and_build_results_use_dedicated_canonical_channel(
    tmp_path: Path, capsys
) -> None:
    project = _repository(
        tmp_path,
        {
            "stages": {
                "coverage": {"enabled": False, "required": False},
                "doxygen": {"enabled": False, "required": False},
            }
        },
    )
    plan_file = tmp_path / "plan-result.json"
    build_file = tmp_path / "build-result.json"
    verify_file = tmp_path / "verify-result.json"
    common = [
        "--protocol",
        PROTOCOL,
        "--project",
        os.fspath(project),
        "--configuration",
        "inspector.json",
    ]

    plan_status = main(
        [
            "plan",
            *common,
            "--result-schema",
            "osqar.inspector.plan-process-result.v1",
            "--result-file",
            os.fspath(plan_file),
        ]
    )
    plan_console = capsys.readouterr()
    build_status = main(
        [
            "build",
            *common,
            "--result-schema",
            "osqar.inspector.build-process-result.v1",
            "--result-file",
            os.fspath(build_file),
            "--run-id",
            "protocol-run",
        ]
    )
    build_console = capsys.readouterr()
    build = json.loads(build_file.read_bytes())
    verify_status = main(
        [
            "verify",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.verify-process-result.v1",
            "--result-file",
            os.fspath(verify_file),
            "--bundle",
            os.fspath(
                project
                / "build"
                / "osqar-inspector"
                / build["publication"]["release_path"]
            ),
        ]
    )
    verify_console = capsys.readouterr()

    assert plan_status == build_status == verify_status == 0
    assert plan_console.out == build_console.out == verify_console.out == ""
    assert plan_console.err == build_console.err == verify_console.err == ""
    plan = json.loads(plan_file.read_bytes())
    verify = json.loads(verify_file.read_bytes())
    assert plan["schema"] == "osqar.inspector.plan-process-result.v1"
    assert plan["status"] == "succeeded"
    assert plan["plan"]["schema"] == "osqar.inspector.plan.v1"
    assert plan["source"] == plan["plan"]["snapshot"]["source"]
    assert plan["configuration_identity"] == plan["plan"]["configuration"]
    assert build["schema"] == "osqar.inspector.build-process-result.v1"
    assert build["status"] == "succeeded"
    assert build["source"] == plan["source"]
    assert build["configuration_identity"] == plan["configuration_identity"]
    assert build["publication"]["state"] == "durable-success"
    assert verify == {
        "bundle_id": build["publication"]["bundle_id"],
        "diagnostics": [],
        "protocol": PROTOCOL,
        "schema": "osqar.inspector.verify-process-result.v1",
        "status": "succeeded",
        "valid": True,
    }


def test_unknown_protocol_and_schema_versions_are_rejected(
    tmp_path: Path, capsys
) -> None:
    project = _repository(tmp_path)
    cases = [
        [
            "capabilities",
            "--protocol",
            "osqar-inspector-run-v2",
            "--result-file",
            os.fspath(tmp_path / "bad-protocol.json"),
        ],
        [
            "plan",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.plan-process-result.v2",
            "--result-file",
            os.fspath(tmp_path / "bad-result-schema.json"),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ],
        [
            "plan",
            "--protocol",
            PROTOCOL,
            "--result-file",
            os.fspath(tmp_path / "incomplete-negotiation.json"),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ],
    ]

    for argv in cases:
        status = main(argv)
        assert status == 2
        result = json.loads(Path(argv[argv.index("--result-file") + 1]).read_bytes())
        assert result["schema"] == "osqar.inspector.protocol-error.v1"
        assert result["status"] == "rejected"
        assert len(result["diagnostics"]) == 1
        assert result["diagnostics"][0]["code"] in {
            "protocol.unsupported",
            "protocol.unsupported_result_schema",
            "protocol.incomplete_negotiation",
        }
        assert capsys.readouterr().out == ""


def test_protocol_rejection_does_not_mutate_project(tmp_path: Path) -> None:
    project = _repository(tmp_path)
    result_file = project / "protocol-error.json"

    status = main(
        [
            "plan",
            "--protocol",
            "osqar-inspector-run-v2",
            "--result-schema",
            "osqar.inspector.plan-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )

    assert status == 2
    assert not os.path.lexists(result_file)
    assert _git(project, "status", "--porcelain") == b""


def test_malformed_result_and_exit_state_mismatch_fail(tmp_path: Path) -> None:
    protocol_error_value = ProcessProtocolError("stable message")
    message_attribute = "message"
    with pytest.raises(AttributeError):
        setattr(protocol_error_value, message_attribute, "divergent message")
    assert protocol_error_value.message == str(protocol_error_value) == "stable message"
    assert protocol_error_value.args == ("stable message",)

    with pytest.raises(ProcessProtocolError, match="integer"):
        validate_process_result("capabilities", b'{"value":' + b"9" * 5000 + b"}", 0)
    with pytest.raises(ProcessProtocolError, match="forbidden number"):
        validate_process_result("capabilities", b'{"value":1.0}', 0)
    for invalid_exit in (False, True):
        with pytest.raises(ProcessProtocolError, match="exit code"):
            validate_process_result(
                "capabilities", canonical_json(capabilities()), invalid_exit
            )

    with pytest.raises(ProcessProtocolError):
        validate_process_result("capabilities", b"{", 0)

    open_result = capabilities()
    open_result["unexpected"] = True
    with pytest.raises(ProcessProtocolError):
        validate_process_result("capabilities", canonical_json(open_result), 0)

    blocked_plan = {
        "configuration_identity": {},
        "diagnostics": [],
        "plan": {},
        "protocol": PROTOCOL,
        "schema": "osqar.inspector.plan-process-result.v1",
        "source": {},
        "status": "blocked",
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("plan", canonical_json(blocked_plan), 0)

    indeterminate_build = {
        "configuration_identity": None,
        "protocol": PROTOCOL,
        "publication": {
            "bundle_id": None,
            "diagnostics": [],
            "intended_current_target": None,
            "prior_current_target": None,
            "release_path": None,
            "run_id": "run",
            "run_report_path": "reports/run.json",
            "run_report_sha256": None,
            "schema": "osqar.inspector.publication-result.v1",
            "state": "commit-indeterminate",
        },
        "schema": "osqar.inspector.build-process-result.v1",
        "source": None,
        "status": "failed",
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(indeterminate_build), 0)
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(indeterminate_build), 11)
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(indeterminate_build), 12)

    mismatched_run = {
        **indeterminate_build,
        "publication": {
            **indeterminate_build["publication"],
            "run_id": "different-caller-run",
            "state": "not-attempted",
        },
    }
    with pytest.raises(ProcessProtocolError, match="requested run ID"):
        validate_process_result(
            "build",
            canonical_json(mismatched_run),
            10,
            expected_run_id="expected-caller-run",
        )

    malformed_failed_build = {
        **indeterminate_build,
        "publication": {
            "bundle_id": False,
            "diagnostics": [],
            "intended_current_target": 7,
            "prior_current_target": {},
            "release_path": True,
            "run_id": False,
            "run_report_path": None,
            "run_report_sha256": [],
            "schema": "osqar.inspector.publication-result.v1",
            "state": "not-attempted",
        },
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(malformed_failed_build), 10)

    contradictory_precommit_failure = {
        **indeterminate_build,
        "publication": {
            **indeterminate_build["publication"],
            "bundle_id": "bundle:sha256:" + "a" * 64,
            "run_report_sha256": "b" * 64,
            "state": "definite-pre-commit-failure",
        },
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result(
            "build", canonical_json(contradictory_precommit_failure), 11
        )

    durable_but_failed = {
        **indeterminate_build,
        "configuration_identity": {
            "controlled_input": {"path": "inspector.json", "sha256": "a" * 64, "size": "1"},
            "defaults": {"id": "builtin-v1", "sha256": "b" * 64},
            "overrides": [],
            "resolved": {"sha256": "c" * 64},
            "schema": {"id": "osqar.inspector.config.v1", "sha256": "d" * 64},
        },
        "publication": {
            **indeterminate_build["publication"],
            "bundle_id": "bundle:sha256:" + "e" * 64,
            "intended_current_target": "releases/bundle:sha256:" + "e" * 64,
            "release_path": "releases/bundle:sha256:" + "e" * 64,
            "run_report_sha256": "f" * 64,
            "state": "durable-success",
        },
        "source": {
            "commit": "1" * 40,
            "kind": "git-clean",
            "object_format": "sha1",
            "tree": "2" * 40,
        },
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(durable_but_failed), 0)

    succeeded_build = {**durable_but_failed, "status": "succeeded"}
    for state, exit_code in (
        ("definite-pre-commit-failure", 11),
        ("commit-indeterminate", 12),
    ):
        valid_failed_publication = {
            **succeeded_build,
            "publication": {**succeeded_build["publication"], "state": state},
            "status": "failed",
        }
        assert (
            validate_process_result(
                "build",
                canonical_json(valid_failed_publication),
                exit_code,
                expected_run_id="run",
            )["status"]
            == "failed"
        )

    malformed_source = {
        **succeeded_build,
        "source": {**succeeded_build["source"], "commit": "not-a-git-object-id"},
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(malformed_source), 0)

    malformed_identity = {
        **succeeded_build,
        "configuration_identity": {
            **succeeded_build["configuration_identity"],
            "resolved": {"sha256": "not-a-digest"},
        },
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("build", canonical_json(malformed_identity), 0)

    recovered_build = {
        **succeeded_build,
        "publication": {
            **succeeded_build["publication"],
            "intended_current_target": None,
            "prior_current_target": succeeded_build["publication"]["release_path"],
            "run_id": "recovery",
            "state": "recovered-durable-success",
        },
    }
    assert (
        validate_process_result("build", canonical_json(recovered_build), 0)["status"]
        == "succeeded"
    )
    invalid_recovery_run = {
        **recovered_build,
        "publication": {
            **recovered_build["publication"],
            "run_id": "caller-run",
        },
    }
    with pytest.raises(ProcessProtocolError, match="recovery result"):
        validate_process_result("build", canonical_json(invalid_recovery_run), 0)

    ordinary_reserved_run = {
        **succeeded_build,
        "publication": {**succeeded_build["publication"], "run_id": "recovery"},
    }
    with pytest.raises(ProcessProtocolError, match="reserved"):
        validate_process_result(
            "build",
            canonical_json(ordinary_reserved_run),
            0,
            expected_run_id="recovery",
        )
    with pytest.raises(ProcessProtocolError, match="correlation"):
        validate_process_result("build", canonical_json(succeeded_build), 0)

    mismatched_plan = {
        "configuration_identity": succeeded_build["configuration_identity"],
        "diagnostics": [],
        "plan": {
            "configuration": succeeded_build["configuration_identity"],
            "schema": "osqar.inspector.plan.v1",
            "snapshot": {
                "source": {**succeeded_build["source"], "tree": "3" * 40}
            },
        },
        "protocol": PROTOCOL,
        "schema": "osqar.inspector.plan-process-result.v1",
        "source": succeeded_build["source"],
        "status": "succeeded",
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("plan", canonical_json(mismatched_plan), 0)

    project = _repository(tmp_path)
    (project / "Doxyfile").unlink()
    _git(project, "add", "--all")
    _git(project, "commit", "-m", "remove required input")
    plan_file = tmp_path / "plan-for-validation.json"
    assert (
        main(
            [
                "plan",
                "--protocol",
                PROTOCOL,
                "--result-schema",
                "osqar.inspector.plan-process-result.v1",
                "--result-file",
                os.fspath(plan_file),
                "--project",
                os.fspath(project),
                "--configuration",
                "inspector.json",
            ]
        )
        == 1
    )
    blocking_plan_as_success = json.loads(plan_file.read_bytes())
    assert any(
        diagnostic["blocking"]
        for diagnostic in blocking_plan_as_success["plan"]["diagnostics"]
    )
    blocking_plan_as_success["status"] = "succeeded"
    with pytest.raises(ProcessProtocolError):
        validate_process_result("plan", canonical_json(blocking_plan_as_success), 0)

    malformed_nested_plan = json.loads(plan_file.read_bytes())
    malformed_nested_plan["plan"]["unexpected"] = True
    with pytest.raises(ProcessProtocolError):
        validate_process_result("plan", canonical_json(malformed_nested_plan), 1)

    malformed_identity_plan = json.loads(plan_file.read_bytes())
    malformed_identity_plan["configuration_identity"]["controlled_input"]["path"] = (
        "../outside"
    )
    malformed_identity_plan["plan"]["configuration"] = malformed_identity_plan[
        "configuration_identity"
    ]
    with pytest.raises(ProcessProtocolError):
        validate_process_result("plan", canonical_json(malformed_identity_plan), 1)

    duplicate_override_plan = json.loads(plan_file.read_bytes())
    duplicate_override_plan["configuration_identity"]["overrides"] = [
        {"pointer": "/stages/doxygen/enabled", "value": True},
        {"pointer": "/stages/doxygen/enabled", "value": False},
    ]
    duplicate_override_plan["plan"]["configuration"] = duplicate_override_plan[
        "configuration_identity"
    ]
    with pytest.raises(ProcessProtocolError):
        validate_process_result("plan", canonical_json(duplicate_override_plan), 1)

    invalid_verify = {
        "bundle_id": "e" * 64,
        "diagnostics": [],
        "protocol": PROTOCOL,
        "schema": "osqar.inspector.verify-process-result.v1",
        "status": "failed",
        "valid": True,
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("verify", canonical_json(invalid_verify), 1)

    invalid_successful_verify = {
        **invalid_verify,
        "diagnostics": [],
        "status": "succeeded",
        "valid": True,
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("verify", canonical_json(invalid_successful_verify), 0)

    failed_verify = {
        "bundle_id": None,
        "diagnostics": [{"code": "verify.failed", "message": "verification failed"}],
        "protocol": PROTOCOL,
        "schema": "osqar.inspector.verify-process-result.v1",
        "status": "failed",
        "valid": False,
    }
    with pytest.raises(ProcessProtocolError):
        validate_process_result("verify", canonical_json(failed_verify), 99)

    malformed_capabilities = capabilities()
    malformed_capabilities["inspector_version"] = None
    with pytest.raises(ProcessProtocolError):
        validate_process_result("capabilities", canonical_json(malformed_capabilities), 0)


def test_machine_verify_failure_is_valid_protocol_result(tmp_path: Path) -> None:
    bundle = tmp_path / "invalid-bundle"
    bundle.mkdir()
    result_file = tmp_path / "verify-failure.json"

    status = main(
        [
            "verify",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.verify-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--bundle",
            os.fspath(bundle),
        ]
    )

    result = validate_process_result("verify", result_file.read_bytes(), status)
    assert status == 1
    assert result["status"] == "failed"
    assert result["valid"] is False
    assert result["diagnostics"]


def test_caller_rejects_unknown_plan_dependency_and_dangling_snapshot_symlink(
    tmp_path: Path,
) -> None:
    project = _repository(tmp_path)
    (project / "selected-target.txt").write_text("selected\n", encoding="utf-8")
    (project / "selected-link.txt").symlink_to("selected-target.txt")
    _git(project, "add", "--all")
    _git(project, "commit", "-m", "add selected symlink")
    result_file = tmp_path / "plan-for-structural-validation.json"
    status = main(
        [
            "plan",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.plan-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )
    assert status == 0

    def refresh_plan_digest(result: dict[str, Any]) -> None:
        plan = result["plan"]
        identity = {key: value for key, value in plan.items() if key != "plan_digest"}
        plan["plan_digest"] = hashlib.sha256(
            canonical_json({"kind": "plan", "identity": identity})
        ).hexdigest()

    unknown_dependency = json.loads(result_file.read_bytes())
    stage = unknown_dependency["plan"]["stages"][0]
    stage["dependencies"].append("ghost-stage")
    unknown_dependency["plan"]["edges"] = sorted(
        (
            {"from": dependency, "to": item["id"]}
            for item in unknown_dependency["plan"]["stages"]
            for dependency in item["dependencies"]
        ),
        key=lambda edge: (edge["from"].encode(), edge["to"].encode()),
    )
    refresh_plan_digest(unknown_dependency)
    with pytest.raises(ProcessProtocolError, match="unknown stage"):
        validate_process_result("plan", canonical_json(unknown_dependency), 0)

    dangling_symlink = json.loads(result_file.read_bytes())
    snapshot = dangling_symlink["plan"]["snapshot"]
    link = next(
        item for item in snapshot["files"] if item["path"] == "selected-link.txt"
    )
    link["identity"] = {
        "sha256": hashlib.sha256(b"missing.txt").hexdigest(),
        "target": "missing.txt",
    }
    snapshot_identity = {
        key: value for key, value in snapshot.items() if key != "snapshot_id"
    }
    snapshot["snapshot_id"] = "snapshot:sha256:" + hashlib.sha256(
        canonical_json({"kind": "snapshot", "identity": snapshot_identity})
    ).hexdigest()
    refresh_plan_digest(dangling_symlink)
    with pytest.raises(ProcessProtocolError, match="selected non-symlink file"):
        validate_process_result("plan", canonical_json(dangling_symlink), 0)

    invalid_output = json.loads(result_file.read_bytes())
    invalid_output["plan"]["stages"][0]["expected_outputs"] = ["../outside"]
    refresh_plan_digest(invalid_output)
    with pytest.raises(ProcessProtocolError, match="invalid path"):
        validate_process_result("plan", canonical_json(invalid_output), 0)

    invalid_workspace = json.loads(result_file.read_bytes())
    invalid_workspace["plan"]["stages"][0]["workspace"] = "../outside"
    refresh_plan_digest(invalid_workspace)
    with pytest.raises(ProcessProtocolError, match="workspace"):
        validate_process_result("plan", canonical_json(invalid_workspace), 0)


def test_result_channel_never_overwrites_an_existing_path(tmp_path: Path) -> None:
    result_file = tmp_path / "result.json"
    result_file.write_bytes(b"existing")

    with pytest.raises(FileExistsError):
        write_result(os.fspath(result_file), capabilities())

    assert result_file.read_bytes() == b"existing"


def test_result_writer_is_anchored_to_owned_directory_descriptor(tmp_path: Path) -> None:
    parent = tmp_path / "owned"
    moved = tmp_path / "owned-moved"
    parent.mkdir()
    descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        parent.rename(moved)
        parent.mkdir()
        write_result(
            os.fspath(parent / "result.json"),
            capabilities(),
            directory_fd=descriptor,
        )
    finally:
        os.close(descriptor)

    assert not (parent / "result.json").exists()
    assert (moved / "result.json").read_bytes() == canonical_json(capabilities())


def test_machine_build_rejects_stale_result_before_side_effects(tmp_path: Path) -> None:
    project = _repository(tmp_path)
    result_file = tmp_path / "stale-result.json"
    result_file.write_bytes(b"caller sentinel")

    status = main(
        [
            "build",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.build-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
            "--run-id",
            "stale-result-test",
        ]
    )

    assert status == 2
    assert result_file.read_bytes() == b"caller sentinel"
    assert not (project / "build").exists()
    assert _git(project, "status", "--porcelain") == b""


def test_machine_build_requires_caller_owned_run_id(tmp_path: Path) -> None:
    project = _repository(tmp_path)
    result_file = tmp_path / "missing-run-id.json"

    status = main(
        [
            "build",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.build-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )

    result = json.loads(result_file.read_bytes())
    assert status == 2
    assert result["status"] == "rejected"
    assert result["diagnostics"] == [
        {
            "code": "protocol.missing_run_id",
            "message": "machine build requires a caller-owned run ID",
        }
    ]


@pytest.mark.parametrize(
    "run_id", [".", "..", "recovery", "a/b", "a\\b", "a\x00b"]
)
def test_machine_build_rejects_invalid_run_id_before_dispatch(
    tmp_path: Path, run_id: str
) -> None:
    result_file = tmp_path / f"invalid-run-{len(list(tmp_path.iterdir()))}.json"

    status = main(
        [
            "build",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.build-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(tmp_path / "missing-project"),
            "--configuration",
            "inspector.json",
            "--run-id",
            run_id,
        ]
    )

    result = json.loads(result_file.read_bytes())
    assert status == 2
    assert result["status"] == "rejected"
    assert result["diagnostics"][0]["code"] == "protocol.invalid_run_id"


def test_conformance_rejects_symlink_result_created_by_process(tmp_path: Path) -> None:
    external = tmp_path / "external.json"
    external.write_bytes(canonical_json(capabilities()))
    result_file = tmp_path / "result.json"
    script = (
        "import os,sys;"
        "result=sys.argv[sys.argv.index('--result-file')+1];"
        "os.symlink(sys.argv[1],result)"
    )

    with pytest.raises(ProcessProtocolError, match="regular result file"):
        run_protocol_command(
            [
                sys.executable,
                "-c",
                script,
                os.fspath(external),
                "capabilities",
                "--protocol",
                PROTOCOL,
                "--result-file",
                os.fspath(result_file),
            ],
            command="capabilities",
            result_file=result_file,
        )


def test_conformance_rejects_hardlinked_preexisting_result(tmp_path: Path) -> None:
    external = tmp_path / "external.json"
    external.write_bytes(canonical_json(capabilities()))
    result_file = tmp_path / "result.json"
    script = (
        "import os,sys;"
        "result=sys.argv[sys.argv.index('--result-file')+1];"
        "os.link(sys.argv[1],result)"
    )

    with pytest.raises(ProcessProtocolError, match="regular result file"):
        run_protocol_command(
            [
                sys.executable,
                "-c",
                script,
                os.fspath(external),
                "capabilities",
                "--protocol",
                PROTOCOL,
                "--result-file",
                os.fspath(result_file),
            ],
            command="capabilities",
            result_file=result_file,
        )


def test_conformance_rejects_fifo_result_without_blocking(tmp_path: Path) -> None:
    result_file = tmp_path / "result.fifo"
    script = (
        "import os,sys;"
        "result=sys.argv[sys.argv.index('--result-file')+1];"
        "os.mkfifo(result)"
    )

    with pytest.raises(ProcessProtocolError, match="regular result file"):
        run_protocol_command(
            [
                sys.executable,
                "-c",
                script,
                "capabilities",
                "--protocol",
                PROTOCOL,
                "--result-file",
                os.fspath(result_file),
            ],
            command="capabilities",
            result_file=result_file,
        )


def test_conformance_bounds_execution_console_and_result_file(tmp_path: Path) -> None:
    result_file = tmp_path / "result.json"
    with pytest.raises(ProcessProtocolError, match="timed out"):
        run_protocol_command(
            [sys.executable, "-c", "import time; time.sleep(0.2)"],
            command="capabilities",
            result_file=result_file,
            timeout_seconds=0.02,
        )

    with pytest.raises(ProcessProtocolError, match="could not be started"):
        run_protocol_command(
            [os.fspath(tmp_path / "missing-executable")],
            command="capabilities",
            result_file=result_file,
        )

    oversized_script = (
        "import sys;"
        "p=sys.argv[sys.argv.index('--result-file')+1];"
        "open(p,'xb').write(b'x'*(int(sys.argv[1])+1))"
    )
    with pytest.raises(ProcessProtocolError, match="size limit"):
        run_protocol_command(
            [
                sys.executable,
                "-c",
                oversized_script,
                str(conformance.MAX_RESULT_BYTES),
                "capabilities",
                "--result-file",
                os.fspath(result_file),
            ],
            command="capabilities",
            result_file=result_file,
        )
    result_file.unlink()

    noisy_script = (
        "import sys;"
        "p=sys.argv[sys.argv.index('--result-file')+1];"
        "open(p,'xb').write(bytes.fromhex(sys.argv[1]));"
        "sys.stdout.buffer.write(b'x'*(int(sys.argv[2])+17))"
    )
    run = run_protocol_command(
        [
            sys.executable,
            "-c",
            noisy_script,
            canonical_json(capabilities()).hex(),
            str(conformance.MAX_CONSOLE_BYTES),
            "capabilities",
            "--result-file",
            os.fspath(result_file),
        ],
        command="capabilities",
        result_file=result_file,
    )
    assert len(run.stdout) == conformance.MAX_CONSOLE_BYTES


def test_conformance_rejects_parent_directory_substitution(tmp_path: Path) -> None:
    parent = tmp_path / "owned"
    parent.mkdir()
    result_file = parent / "result.json"
    script = (
        "import os,sys;"
        "parent=sys.argv[1];"
        "os.rename(parent,parent+'.moved');"
        "os.mkdir(parent);"
        "result=sys.argv[sys.argv.index('--result-file')+1];"
        "open(result,'xb').write(bytes.fromhex(sys.argv[2]))"
    )

    with pytest.raises(ProcessProtocolError, match="directory changed"):
        run_protocol_command(
            [
                sys.executable,
                "-c",
                script,
                os.fspath(parent),
                canonical_json(capabilities()).hex(),
                "capabilities",
                "--result-file",
                os.fspath(result_file),
            ],
            command="capabilities",
            result_file=result_file,
        )


def test_conformance_reaps_setsid_descendants_without_resource_leaks(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "escaped.pid"
    child = "import os,time; os.setsid(); time.sleep(30)"
    producer = (
        "import subprocess,sys;"
        "p=subprocess.Popen([sys.executable,'-c',sys.argv[1]]);"
        "open(sys.argv[2],'w').write(str(p.pid))"
    )
    before_fds = len(list(Path("/proc/self/fd").iterdir()))
    before_threads = threading.active_count()

    with pytest.raises(ProcessProtocolError):
        run_protocol_command(
            [sys.executable, "-c", producer, child, os.fspath(pid_file)],
            command="capabilities",
            result_file=tmp_path / "result.json",
        )

    escaped_pid = int(pid_file.read_text(encoding="utf-8"))
    for _ in range(50):
        if not Path(f"/proc/{escaped_pid}").exists():
            break
        time.sleep(0.02)
    escaped_alive = Path(f"/proc/{escaped_pid}").exists()
    after_fds = len(list(Path("/proc/self/fd").iterdir()))
    after_threads = threading.active_count()
    if escaped_alive:
        try:
            os.kill(escaped_pid, 9)
        except ProcessLookupError:
            pass

    assert not escaped_alive
    assert after_fds == before_fds
    assert after_threads == before_threads


def test_human_console_text_is_never_parsed_as_protocol(tmp_path: Path) -> None:
    fake = tmp_path / "fake-inspector"
    fake.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' "
        + repr(canonical_json(capabilities()).decode("utf-8"))
        + "\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    with pytest.raises(ProcessProtocolError, match="result file"):
        run_protocol_command(
            [os.fspath(fake)],
            command="capabilities",
            result_file=tmp_path / "owned-result.json",
        )


def test_blocked_plan_reports_process_diagnostics(tmp_path: Path) -> None:
    project = _repository(tmp_path)
    (project / "Doxyfile").unlink()
    _git(project, "add", "--all")
    _git(project, "commit", "-m", "remove required input")
    result_file = tmp_path / "blocked-plan.json"

    status = main(
        [
            "plan",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.plan-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )

    result = validate_process_result("plan", result_file.read_bytes(), status)
    assert status == 1
    assert result["status"] == "blocked"
    assert result["diagnostics"] == [
        {
            "code": "plan.input_missing",
            "message": "selected snapshot does not contain 'Doxyfile'",
        }
    ]


def test_machine_plan_rejects_result_inside_project_without_mutation(
    tmp_path: Path,
) -> None:
    project = _repository(tmp_path)
    result_file = project / "protocol-result.json"

    status = main(
        [
            "plan",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.plan-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )

    assert status == 2
    assert not result_file.exists()
    assert _git(project, "status", "--porcelain", "--untracked-files=all") == b""


def test_machine_plan_failure_is_closed_in_result_file(
    tmp_path: Path, capsys
) -> None:
    project = _repository(tmp_path)
    (project / "inspector.json").write_text(
        '{"schema":"osqar.inspector.config.v2"}', encoding="utf-8"
    )
    result_file = tmp_path / "failed-plan.json"

    status = main(
        [
            "plan",
            "--protocol",
            PROTOCOL,
            "--result-schema",
            "osqar.inspector.plan-process-result.v1",
            "--result-file",
            os.fspath(result_file),
            "--project",
            os.fspath(project),
            "--configuration",
            "inspector.json",
        ]
    )

    assert status == 1
    assert capsys.readouterr().out == ""
    result = validate_process_result("plan", result_file.read_bytes(), status)
    assert result["status"] == "failed"
    assert result["plan"] is None
    assert result["diagnostics"][0]["code"] == "configuration.unsupported_schema"
