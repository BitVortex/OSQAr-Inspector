from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path

from osqar_inspector.publication import (
    LinuxPublicationOperations,
    PublicationResult,
    PublicationState,
    publish_candidate,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _run_report() -> bytes:
    digest = "0" * 64
    return _canonical(
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


class MutateNewReleaseDuringDirectorySync:
    def __init__(self, previous_target: str) -> None:
        self.previous_target = previous_target
        self.mutated = False

    @staticmethod
    def fsync_file(path: Path) -> None:
        LinuxPublicationOperations.fsync_file(path)

    def fsync_directory(self, path: Path) -> None:
        if path.name == "releases" and not self.mutated:
            for release in path.iterdir():
                relative = f"releases/{release.name}"
                if release.is_dir() and relative != self.previous_target:
                    (release / "navigation" / "index.html").write_bytes(b"mutated")
                    self.mutated = True
                    break
        LinuxPublicationOperations.fsync_directory(path)

    @staticmethod
    def rename(source: Path, destination: Path) -> None:
        LinuxPublicationOperations.rename(source, destination)

    @staticmethod
    def replace(source: Path, destination: Path) -> None:
        LinuxPublicationOperations.replace(source, destination)

    @staticmethod
    def symlink(target: str, path: Path) -> None:
        LinuxPublicationOperations.symlink(target, path)

    @staticmethod
    def unlink(path: Path) -> None:
        LinuxPublicationOperations.unlink(path)


def _candidate() -> Candidate:
    return Candidate(
        (
            ("navigation/index.html", b"<h1>Inspection</h1>\n"),
            ("reports/run.json", _run_report()),
        )
    )


def test_new_release_and_current_pointer_reach_durable_success(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publication"
    root.mkdir()

    result = publish_candidate(_candidate(), root, run_id="run-001")

    assert result.state is PublicationState.DURABLE_SUCCESS
    assert result.exit_code == 0
    assert result.bundle_id is not None
    assert result.release_path is not None
    assert result.release_path == f"releases/{result.bundle_id}"
    assert result.prior_current_target is None
    assert result.intended_current_target == result.release_path
    assert result.run_report_path == "reports/run.json"
    assert result.run_report_sha256 == hashlib.sha256(_run_report()).hexdigest()
    assert result.diagnostics == ()
    assert (root / "current").is_symlink()
    assert os.readlink(root / "current") == result.release_path
    assert (root / result.release_path).is_dir()
    assert not tuple(root.glob(".recovery-*.json"))
    assert not tuple((root / "releases").glob(".candidate-*"))

    payload = json.loads(result.canonical_bytes)
    assert payload["schema"] == "osqar.inspector.publication-result.v1"
    assert payload["state"] == "durable-success"
    assert payload["bundle_id"] == result.bundle_id


def test_existing_exact_release_is_safely_reused(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    first = publish_candidate(_candidate(), root, run_id="run-001")
    assert first.release_path is not None
    release = root / first.release_path
    before = tuple(
        sorted(
            (path.relative_to(release).as_posix(), path.lstat().st_ino)
            for path in release.rglob("*")
        )
    )

    second = publish_candidate(_candidate(), root, run_id="run-002")

    assert second.state is PublicationState.DURABLE_SUCCESS
    assert second.exit_code == 0
    assert second.bundle_id == first.bundle_id
    assert second.release_path == first.release_path
    assert second.prior_current_target == first.release_path
    assert os.readlink(root / "current") == first.release_path
    assert (
        tuple(
            sorted(
                (path.relative_to(release).as_posix(), path.lstat().st_ino)
                for path in release.rglob("*")
            )
        )
        == before
    )
    assert not (root / "releases" / ".candidate-run-002").exists()


def test_identity_mismatch_and_unsafe_existing_entries_block_publication(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    first = publish_candidate(_candidate(), root, run_id="run-001")
    assert first.release_path is not None
    release = root / first.release_path
    current_target = os.readlink(root / "current")
    (release / "navigation" / "index.html").write_bytes(b"tampered")

    mismatch = publish_candidate(_candidate(), root, run_id="run-002")

    assert mismatch.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert mismatch.exit_code == 11
    assert mismatch.diagnostics[0].code == "publication.filesystem_error"
    assert "identity_mismatch" in mismatch.diagnostics[0].message
    assert os.readlink(root / "current") == current_target

    shutil.rmtree(release)
    outside = tmp_path / "outside"
    outside.mkdir()
    release.symlink_to(outside, target_is_directory=True)

    unsafe = publish_candidate(_candidate(), root, run_id="run-003")

    assert unsafe.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert unsafe.exit_code == 11
    assert "current_target_unsafe" in unsafe.diagnostics[0].message
    assert release.is_symlink()
    assert os.readlink(root / "current") == current_target


def test_unsafe_current_target_is_rejected_without_replacement(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    first = publish_candidate(_candidate(), root, run_id="run-001")
    assert first.state is PublicationState.DURABLE_SUCCESS
    current = root / "current"
    current.unlink()
    current.symlink_to("../../outside")

    result = publish_candidate(_candidate(), root, run_id="run-002")

    assert result.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert result.exit_code == 11
    assert "current_target_unsafe" in result.diagnostics[0].message
    assert os.readlink(current) == "../../outside"


def test_publication_state_exit_mapping_is_closed() -> None:
    assert {state.value for state in PublicationState} == {
        "not-attempted",
        "definite-pre-commit-failure",
        "commit-indeterminate",
        "durable-success",
        "recovered-durable-success",
        "recovered-no-commit",
        "recovery-blocked",
    }
    expected = {
        PublicationState.NOT_ATTEMPTED: 10,
        PublicationState.DEFINITE_PRE_COMMIT_FAILURE: 11,
        PublicationState.COMMIT_INDETERMINATE: 12,
        PublicationState.DURABLE_SUCCESS: 0,
        PublicationState.RECOVERED_DURABLE_SUCCESS: 0,
        PublicationState.RECOVERED_NO_COMMIT: 13,
        PublicationState.RECOVERY_BLOCKED: 14,
    }
    for state, exit_code in expected.items():
        result = PublicationResult(
            "run", state, None, None, "reports/run.json", None, None, None
        )
        assert result.exit_code == exit_code


def test_publication_waits_for_the_single_writer_lock(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    lock_path = root / ".publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    os.write(descriptor, b"publication-ready\n")
    os.fsync(descriptor)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    results: list[PublicationResult] = []
    started = threading.Event()

    def publish() -> None:
        started.set()
        results.append(publish_candidate(_candidate(), root, run_id="locked"))

    worker = threading.Thread(target=publish)
    worker.start()
    assert started.wait(timeout=1)
    worker.join(timeout=0.1)
    assert worker.is_alive()

    fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert results[0].state is PublicationState.DURABLE_SUCCESS


def test_lock_release_failure_cannot_recast_a_durable_commit(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    real_flock = fcntl.flock

    def fail_after_unlock(descriptor: int, operation: int) -> None:
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN:
            raise OSError("injected lock-release failure")

    monkeypatch.setattr(fcntl, "flock", fail_after_unlock)

    result = publish_candidate(_candidate(), root, run_id="lock-release")

    assert result.state is PublicationState.DURABLE_SUCCESS
    assert result.exit_code == 0
    assert result.bundle_id is not None
    assert result.release_path is not None
    assert result.intended_current_target == result.release_path
    assert os.readlink(root / "current") == result.release_path
    assert result.diagnostics[-1].code == "publication.lock_release_error"


def test_lock_close_failure_cannot_recast_a_durable_commit(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    lock_path = root / ".publication.lock"
    lock_descriptors: set[int] = set()
    real_open = os.open
    real_close = os.close

    def track_lock_open(path, flags: int, mode: int = 0o777) -> int:
        descriptor = real_open(path, flags, mode)
        if Path(path) == lock_path:
            lock_descriptors.add(descriptor)
        return descriptor

    def fail_after_lock_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor in lock_descriptors:
            raise OSError("injected lock-close failure")

    monkeypatch.setattr(os, "open", track_lock_open)
    monkeypatch.setattr(os, "close", fail_after_lock_close)

    result = publish_candidate(_candidate(), root, run_id="lock-close")

    assert result.state is PublicationState.DURABLE_SUCCESS
    assert result.exit_code == 0
    assert result.release_path is not None
    assert result.intended_current_target == result.release_path
    assert os.readlink(root / "current") == result.release_path
    assert result.diagnostics[-1].code == "publication.lock_release_error"


def test_malformed_runtime_candidates_return_a_closed_result(tmp_path: Path) -> None:
    class MissingReady:
        payloads = _candidate().payloads

    class ExplodingPayloads:
        candidate_ready = True

        @property
        def payloads(self):
            raise RuntimeError("malformed payload accessor")

    class OneShotPayloads:
        candidate_ready = True

        def __init__(self) -> None:
            self.reads = 0

        @property
        def payloads(self):
            self.reads += 1
            if self.reads > 1:
                raise RuntimeError("payloads were read more than once")
            return _candidate().payloads

    root = tmp_path / "publication"
    root.mkdir()

    for malformed in (MissingReady(), ExplodingPayloads()):
        result = publish_candidate(malformed, root, run_id="malformed")  # type: ignore[arg-type]
        assert result.state is PublicationState.NOT_ATTEMPTED
        assert result.diagnostics[0].code == "bundle.invalid_candidate"

    assert tuple(root.iterdir()) == ()

    one_shot = OneShotPayloads()
    accepted = publish_candidate(one_shot, root, run_id="one-shot")  # type: ignore[arg-type]
    assert accepted.state is PublicationState.DURABLE_SUCCESS
    assert one_shot.reads == 1


def test_malformed_candidate_returns_closed_failure_state(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()

    class MalformedCandidate:
        payloads = None

    result = publish_candidate(
        MalformedCandidate(),  # pyright: ignore[reportArgumentType]
        root,
        run_id="malformed",
    )

    assert result.state is PublicationState.NOT_ATTEMPTED
    assert result.diagnostics[0].code == "bundle.invalid_candidate"


def test_release_is_reverified_after_installation_sync(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    first = publish_candidate(_candidate(), root, run_id="first")
    assert first.release_path is not None
    changed = Candidate(_candidate().payloads + (("artifacts/new.txt", b"new"),))
    operations = MutateNewReleaseDuringDirectorySync(first.release_path)

    result = publish_candidate(changed, root, run_id="mutated", operations=operations)

    assert operations.mutated is True
    assert result.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert os.readlink(root / "current") == first.release_path


def test_existing_candidate_name_is_a_definite_pre_commit_failure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publication"
    (root / "releases" / ".candidate-repeat").mkdir(parents=True)

    result = publish_candidate(_candidate(), root, run_id="repeat")

    assert result.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert result.exit_code == 11
    assert result.diagnostics[0].code == "bundle.destination_exists"
