from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from osqar_inspector import bundle_generation
from osqar_inspector.bundle_generation import BundleGenerationError, generate_bundle


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def valid_run_report() -> bytes:
    digest = "0" * 64
    return canonical(
        {
            "artifact_counts": [{"count": "1", "kind": "api-page"}],
            "claim_boundary": {
                "does_not_establish": [
                    "certification",
                    "evidence-adequacy",
                    "evidence-approval",
                    "fitness-for-use",
                    "functional-safety",
                    "security",
                    "software-qualification",
                    "standards-compliance",
                    "tool-qualification",
                ],
                "scope": "mechanical-structural-and-integrity-inspection",
            },
            "configuration_identity": {
                "controlled_input": {
                    "path": "inspector.json",
                    "sha256": digest,
                    "size": "1",
                },
                "defaults": {"id": "builtin-v1", "sha256": digest},
                "overrides": [],
                "resolved": {"sha256": digest},
                "schema": {"id": "osqar.inspector.config.v1", "sha256": digest},
            },
            "diagnostics": [],
            "inspector": {"version": "0.1.0"},
            "optional_stages": {"degraded": [], "skipped": []},
            "plan_sha256": digest,
            "required_stage_decision": "satisfied",
            "schema": "osqar.inspector.run.v1",
            "snapshot_id": f"snapshot:sha256:{digest}",
            "stage_result_digests": [digest],
        }
    )


@dataclass(frozen=True)
class Candidate:
    payloads: tuple[tuple[str, bytes], ...]
    candidate_ready: bool = True


def candidate(*extra: tuple[str, bytes]) -> Candidate:
    return Candidate(
        (
            ("navigation/index.html", b"<h1>Inspection</h1>\n"),
            ("reports/run.json", valid_run_report()),
            *extra,
        )
    )


def run_verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "osqar_inspector.cli",
            "verify",
            "--bundle",
            str(bundle),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_generated_bundle_is_byte_deterministic_and_self_verifies(
    tmp_path: Path,
) -> None:
    first = generate_bundle(
        candidate(("artifacts/data.bin", b"\x00\xff")), tmp_path / "one"
    )
    second = generate_bundle(
        candidate(("artifacts/data.bin", b"\x00\xff")), tmp_path / "two"
    )

    assert first.bundle_id == second.bundle_id
    assert first.manifest_bytes == second.manifest_bytes
    assert first.checksums_bytes == second.checksums_bytes
    assert (first.root / "manifest.json").read_bytes() == first.manifest_bytes
    assert (first.root / "checksums.sha256").read_bytes() == first.checksums_bytes

    result = run_verify(first.root)
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"bundle_id": first.bundle_id, "valid": True}


def test_unicode_paths_use_canonical_sorted_inventory(tmp_path: Path) -> None:
    generated = generate_bundle(
        candidate(("artifacts/é.txt", b"accent"), ("artifacts/😀.txt", b"emoji")),
        tmp_path / "bundle",
    )

    manifest = json.loads(generated.manifest_bytes)
    paths = [entry["path"] for entry in manifest["entries"]]
    assert paths == sorted(paths, key=str.encode)
    assert paths == [
        "artifacts/é.txt",
        "artifacts/😀.txt",
        "navigation/index.html",
        "reports/run.json",
    ]
    assert generated.manifest_bytes == canonical(manifest)


def test_payload_mutation_during_closure_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original: Callable[[Path, str, bytes], None] = bundle_generation._write_payload
    mutated = False

    def mutate_after_write(root: Path, path: str, content: bytes) -> None:
        nonlocal mutated
        original(root, path, content)
        if path == "manifest.json" and not mutated:
            (root / "navigation" / "index.html").write_bytes(b"mutated")
            mutated = True

    monkeypatch.setattr(bundle_generation, "_write_payload", mutate_after_write)

    with pytest.raises(BundleGenerationError) as failure:
        generate_bundle(candidate(), tmp_path / "bundle")

    assert failure.value.code == "bundle.self_verification_failed"
    assert mutated is True


@pytest.mark.parametrize(
    "mutation",
    ("manifest", "checksums", "extra-file", "empty-directory", "symlink"),
)
def test_late_control_or_inventory_mutation_during_closure_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    from osqar_inspector import verify

    original = verify._validate_links

    def mutate_after_semantic_validation(
        root: Path, paths: set[str], expectations: dict[str, tuple[str, str]]
    ) -> None:
        original(root, paths, expectations)
        if mutation == "manifest":
            (root / "manifest.json").write_bytes(b"{}")
        elif mutation == "checksums":
            (root / "checksums.sha256").write_bytes(b"")
        elif mutation == "extra-file":
            (root / "extra.txt").write_bytes(b"extra")
        elif mutation == "empty-directory":
            (root / "empty").mkdir()
        else:
            (root / "late-link").symlink_to("navigation/index.html")

    monkeypatch.setattr(verify, "_validate_links", mutate_after_semantic_validation)

    with pytest.raises(BundleGenerationError) as failure:
        generate_bundle(candidate(), tmp_path / "bundle")

    assert failure.value.code == "bundle.self_verification_failed"


@pytest.mark.parametrize("control", ("manifest.json", "checksums.sha256"))
def test_mutation_during_terminal_control_reread_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, control: str
) -> None:
    from osqar_inspector import verify

    original = verify._read_regular
    control_reads = 0

    def mutate_during_terminal_read(root: Path, relative: str) -> bytes:
        nonlocal control_reads
        content = original(root, relative)
        if relative == control:
            control_reads += 1
            if control_reads == 2:
                if control == "manifest.json":
                    (root / "navigation/index.html").write_bytes(
                        b"late payload mutation"
                    )
                else:
                    (root / "late-empty").mkdir()
        return content

    monkeypatch.setattr(verify, "_read_regular", mutate_during_terminal_read)

    with pytest.raises(BundleGenerationError) as failure:
        generate_bundle(candidate(), tmp_path / "bundle")

    assert failure.value.code == "bundle.self_verification_failed"
    assert control_reads == 2


def test_extra_directory_symlink_and_path_collision_fail(tmp_path: Path) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "extra.txt").write_bytes(b"extra")
    with pytest.raises(BundleGenerationError) as extra:
        generate_bundle(candidate(), occupied)
    assert extra.value.code == "bundle.destination_exists"

    symlink = tmp_path / "symlink"
    symlink.symlink_to(occupied, target_is_directory=True)
    with pytest.raises(BundleGenerationError) as linked:
        generate_bundle(candidate(), symlink)
    assert linked.value.code == "bundle.destination_exists"

    with pytest.raises(BundleGenerationError) as collision:
        generate_bundle(
            candidate(
                ("artifacts/collision", b"file"), ("artifacts/collision/item", b"child")
            ),
            tmp_path / "collision",
        )
    assert collision.value.code == "bundle.path_collision"
    assert not (tmp_path / "collision").exists()

    empty = tmp_path / "empty-directory"
    empty.mkdir()
    (empty / "empty").mkdir()
    with pytest.raises(BundleGenerationError) as directory:
        generate_bundle(candidate(), empty)
    assert directory.value.code == "bundle.destination_exists"


def test_generator_cannot_bypass_independent_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []

    def wrong_identity(root: Path) -> str:
        calls.append(root)
        return "bundle:sha256:" + "f" * 64

    monkeypatch.setattr("osqar_inspector.verify.verify_bundle", wrong_identity)

    with pytest.raises(BundleGenerationError) as failure:
        generate_bundle(candidate(), tmp_path / "bundle")

    assert failure.value.code == "bundle.verification_mismatch"
    assert calls == [tmp_path / "bundle"]


def test_unready_candidate_reserved_duplicate_and_noncanonical_paths_fail(
    tmp_path: Path,
) -> None:
    cases = [
        (
            Candidate(candidate().payloads, candidate_ready=False),
            "bundle.candidate_not_ready",
        ),
        (candidate(("manifest.json", b"reserved")), "bundle.reserved_path"),
        (candidate(("navigation/index.html", b"duplicate")), "bundle.path_collision"),
        (candidate(("manifest.json/child", b"collision")), "bundle.path_collision"),
        (candidate(("checksums.sha256/child", b"collision")), "bundle.path_collision"),
        (candidate(("artifacts/e\u0301.txt", b"not NFC")), "bundle.invalid_path"),
    ]
    for index, (value, code) in enumerate(cases):
        with pytest.raises(BundleGenerationError) as failure:
            generate_bundle(value, tmp_path / f"invalid-{index}")
        assert failure.value.code == code
        assert not (tmp_path / f"invalid-{index}").exists()


def test_checksums_are_exact_and_exclude_themselves(tmp_path: Path) -> None:
    generated = generate_bundle(candidate(), tmp_path / "bundle")
    manifest_digest = hashlib.sha256(generated.manifest_bytes).hexdigest()
    lines = generated.checksums_bytes.decode("utf-8").splitlines(keepends=True)

    assert lines[-1].endswith("\n")
    assert all(line.count("  ") == 1 for line in lines)
    assert f"{manifest_digest}  manifest.json\n" in lines
    assert all("checksums.sha256" not in line for line in lines)


def test_unsupported_payload_types_fail_before_writing(tmp_path: Path) -> None:
    malformed = Candidate(
        (
            ("navigation/index.html", bytearray(b"mutable")),
            ("reports/run.json", valid_run_report()),
        )
    )  # type: ignore[arg-type]
    with pytest.raises(BundleGenerationError) as failure:
        generate_bundle(malformed, tmp_path / "bundle")
    assert failure.value.code == "bundle.invalid_payload"
    assert not (tmp_path / "bundle").exists()
