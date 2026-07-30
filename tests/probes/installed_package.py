"""Exercise a built wheel from a clean environment outside the checkout."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(
    *argv: str, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n"
            + result.stderr.decode("utf-8", "replace")
        )
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: installed_package.py DIST.whl", file=sys.stderr)
        return 2
    wheel = Path(sys.argv[1]).resolve(strict=True)
    if wheel.suffix != ".whl":
        print("probe requires exactly one wheel", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="osqar-installed-probe-") as temporary:
        outside = Path(temporary).resolve()
        environment = outside / "environment"
        _run("uv", "venv", "--python", sys.executable, str(environment), cwd=outside)
        python = environment / "bin" / "python"
        executable = environment / "bin" / "osqar-inspector"
        _run("uv", "pip", "install", "--python", str(python), str(wheel), cwd=outside)

        project = outside / "project"
        project.mkdir()
        _run("git", "init", str(project), cwd=outside)
        _run("git", "config", "user.name", "Installed Package Probe", cwd=project)
        _run("git", "config", "user.email", "probe@example.invalid", cwd=project)
        (project / "inspector.json").write_text(
            '{"schema":"osqar.inspector.config.v1","stages":'
            '{"coverage":{"enabled":false,"required":false},'
            '"doxygen":{"enabled":false,"required":false}}}',
            encoding="utf-8",
        )
        _run("git", "add", "--all", cwd=project)
        _run("git", "commit", "-m", "fixture", cwd=project)

        consumer = outside / "consumer.py"
        consumer.write_text(
            """from __future__ import annotations
import json
import os
import sys
import types
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import osqar_inspector
import osqar_inspector._process_supervisor as process_supervisor
import osqar_inspector.conformance as conformance
import osqar_inspector.process_protocol as process_protocol
import osqar_inspector.publication as publication
import osqar_inspector.release_gate as release_gate
import osqar_inspector.signatures as signatures

environment = Path(sys.argv[1]).resolve()
executable = Path(sys.argv[2]).resolve()
project = Path(sys.argv[3]).resolve()
for module in (
    osqar_inspector,
    process_supervisor,
    conformance,
    process_protocol,
    publication,
    release_gate,
    signatures,
):
    module_path = Path(module.__file__).resolve()
    if not module_path.is_relative_to(environment):
        raise AssertionError(f"module escaped installed environment: {module_path}")
supervisor_path = Path(conformance.__file__).with_name("_process_supervisor.py").resolve()
if not supervisor_path.is_absolute() or not supervisor_path.is_relative_to(environment):
    raise AssertionError(f"supervisor escaped installed environment: {supervisor_path}")
if supervisor_path != Path(process_supervisor.__file__).resolve():
    raise AssertionError("conformance does not resolve the installed supervisor module")
policy = release_gate.load_release_policy()
supervisor_commands = []
original_popen = conformance.subprocess.Popen
def recording_popen(argv, *args, **kwargs):
    supervisor_commands.append(tuple(argv))
    return original_popen(argv, *args, **kwargs)
conformance.subprocess.Popen = recording_popen
driver = conformance.InspectorDriver(executable, cwd=project.parent)
capability = driver.capabilities(project.parent / "capabilities.json").result
plan = driver.plan(project, "inspector.json", project.parent / "plan.json").result
build = driver.build(
    project,
    "inspector.json",
    project.parent / "build.json",
    run_id="installed-probe",
).result
bundle = project / "build" / "osqar-inspector" / build["publication"]["release_path"]
verified = driver.verify(bundle, project.parent / "verify.json").result
payload = b"installed package probe statement\\n"
private_key = Ed25519PrivateKey.generate()
signed = signatures.sign_bundle(
    bundle,
    private_key,
    key_id="installed-probe-key",
    statement_type="osqar.inspector.probe.v1",
    payload=payload,
)
signature = signatures.verify_detached_signature(
    bundle,
    signed.envelope_bytes,
    payload,
    trust_anchors={"installed-probe-key": signed.public_key_bytes},
)
recovered = publication.recover_publication(project / "build" / "osqar-inspector")
def assert_installed_module_origins(modules):
    for module_name, module in sorted(modules.items()):
        if module_name != "osqar_inspector" and not module_name.startswith("osqar_inspector."):
            continue
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, (str, bytes, os.PathLike)):
            raise AssertionError(f"loaded package module has no file origin: {module_name}")
        module_path = Path(module_file).resolve()
        if not module_path.is_relative_to(environment):
            raise AssertionError(
                f"loaded package module escaped installed environment: {module_name}={module_path}"
            )
synthetic_name = "osqar_inspector.synthetic_missing_origin"
sys.modules[synthetic_name] = types.ModuleType(synthetic_name)
try:
    try:
        assert_installed_module_origins(sys.modules)
    except AssertionError as error:
        assert "has no file origin" in str(error)
    else:
        raise AssertionError("missing package module origin was accepted")
finally:
    del sys.modules[synthetic_name]
assert_installed_module_origins(sys.modules)
assert supervisor_commands
for command in supervisor_commands:
    assert Path(command[1]).resolve() == supervisor_path, command
assert capability["protocol"] == "osqar-inspector-run-v1"
assert plan["configuration_identity"] == build["configuration_identity"]
assert verified["bundle_id"] == build["publication"]["bundle_id"]
assert signature.valid and signature.trusted
assert recovered.state.value == "recovered-durable-success", recovered
print(json.dumps({
    "build": build["publication"]["state"],
    "installed_root": str(environment),
    "protocol": capability["protocol"],
    "python": policy["support"]["python"],
    "recovery": recovered.state.value,
    "signature": signature.status,
    "verified": verified["valid"],
}, sort_keys=True))
""",
            encoding="utf-8",
        )
        clean_environment = os.environ.copy()
        clean_environment.pop("PYTHONPATH", None)
        result = _run(
            str(python),
            "-I",
            str(consumer),
            str(environment),
            str(executable),
            str(project),
            cwd=outside,
            env=clean_environment,
        )
        sys.stdout.buffer.write(result.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
