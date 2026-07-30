from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run(*argv: str, cwd: Path | None = None) -> None:
    result = subprocess.run(
        list(argv),
        cwd=cwd,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_installed_package_passes_handoff_conformance(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[2]
    wheelhouse = tmp_path / "wheelhouse"
    environment = tmp_path / "installed"
    outside = tmp_path / "outside-checkout"
    wheelhouse.mkdir()
    outside.mkdir()
    _run("uv", "build", "--wheel", "--out-dir", os.fspath(wheelhouse), cwd=checkout)
    _run("uv", "venv", "--python", sys.executable, os.fspath(environment))
    wheel = next(wheelhouse.glob("osqar_inspector-*.whl"))
    _run(
        "uv",
        "pip",
        "install",
        "--python",
        os.fspath(environment / "bin" / "python"),
        os.fspath(wheel),
    )

    project = outside / "project"
    project.mkdir()
    _run("git", "init", os.fspath(project))
    _run("git", "-C", os.fspath(project), "config", "user.name", "Protocol Test")
    _run(
        "git",
        "-C",
        os.fspath(project),
        "config",
        "user.email",
        "protocol@example.invalid",
    )
    (project / "inspector.json").write_text(
        json.dumps(
            {
                "schema": "osqar.inspector.config.v1",
                "stages": {
                    "coverage": {"enabled": False, "required": False},
                    "doxygen": {"enabled": False, "required": False},
                },
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    _run("git", "-C", os.fspath(project), "add", "--all")
    _run("git", "-C", os.fspath(project), "commit", "-m", "fixture")

    runner = outside / "installed-consumer.py"
    runner.write_text(
        """from __future__ import annotations
import json
import sys
from pathlib import Path
import osqar_inspector._process_supervisor as process_supervisor
import osqar_inspector.conformance as conformance
import osqar_inspector.process_protocol as process_protocol

environment = Path(sys.argv[1]).resolve()
executable = Path(sys.argv[2]).resolve()
project = Path(sys.argv[3]).resolve()
for module in (conformance, process_protocol, process_supervisor):
    module_path = Path(module.__file__).resolve()
    if not module_path.is_relative_to(environment):
        raise AssertionError(f"module escaped installed environment: {module_path}")
driver = conformance.InspectorDriver(executable, cwd=project.parent)
capability = driver.capabilities(project.parent / "capabilities.json").result
plan = driver.plan(project, "inspector.json", project.parent / "plan-result.json").result
build = driver.build(
    project,
    "inspector.json",
    project.parent / "build-result.json",
    run_id="installed-run",
).result
ordinary_bytes = json.dumps(build, sort_keys=True, separators=(",", ":")).encode()
try:
    process_protocol.validate_process_result("build", ordinary_bytes, 0)
except process_protocol.ProcessProtocolError:
    pass
else:
    raise AssertionError("ordinary build validation accepted missing caller correlation")
reserved = {**build, "publication": {**build["publication"], "run_id": "recovery"}}
reserved_bytes = json.dumps(reserved, sort_keys=True, separators=(",", ":")).encode()
try:
    process_protocol.validate_process_result(
        "build", reserved_bytes, 0, expected_run_id="recovery"
    )
except process_protocol.ProcessProtocolError:
    pass
else:
    raise AssertionError("ordinary publication accepted the reserved recovery run ID")
bundle = project / "build" / "osqar-inspector" / build["publication"]["release_path"]
verified = driver.verify(bundle, project.parent / "verify-result.json").result
print(json.dumps({
    "build_state": build["publication"]["state"],
    "bundle_matches": verified["bundle_id"] == build["publication"]["bundle_id"],
    "config_matches": plan["configuration_identity"] == build["configuration_identity"],
    "inspector_version": capability["inspector_version"],
    "source_matches": plan["source"] == build["source"],
}, sort_keys=True))
""",
        encoding="utf-8",
    )
    environment_variables = os.environ.copy()
    environment_variables.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            os.fspath(environment / "bin" / "python"),
            os.fspath(runner),
            os.fspath(environment),
            os.fspath(environment / "bin" / "osqar-inspector"),
            os.fspath(project),
        ],
        cwd=outside,
        env=environment_variables,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    summary = json.loads(result.stdout)
    assert summary == {
        "build_state": "durable-success",
        "bundle_matches": True,
        "config_matches": True,
        "inspector_version": "0.1.0",
        "source_matches": True,
    }
