from __future__ import annotations

import os
from pathlib import Path

from test_publication import Candidate, _candidate, _run_report
from test_publication_recovery import _changed_candidate, _root_with_previous_release

from osqar_inspector.publication import (
    LinuxPublicationOperations,
    PublicationState,
    publish_candidate,
    recover_publication_if_present,
)


class NoRecoveryJournalOperations(LinuxPublicationOperations):
    @staticmethod
    def write_recovery(path: Path, content: bytes) -> None:
        raise AssertionError("the AoU-based protocol must not create a recovery journal")


class FailPointerDirectorySync:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.replacement_reached = False
        self.failed = False

    @staticmethod
    def fsync_file(path: Path) -> None:
        LinuxPublicationOperations.fsync_file(path)

    def fsync_directory(self, path: Path) -> None:
        if path == self.root and self.replacement_reached and not self.failed:
            self.failed = True
            raise OSError("injected pointer-directory synchronization failure")
        LinuxPublicationOperations.fsync_directory(path)

    @staticmethod
    def rename(source: Path, destination: Path) -> None:
        LinuxPublicationOperations.rename(source, destination)

    def replace(self, source: Path, destination: Path) -> None:
        LinuxPublicationOperations.replace(source, destination)
        self.replacement_reached = True

    @staticmethod
    def symlink(target: str, path: Path) -> None:
        LinuxPublicationOperations.symlink(target, path)

    @staticmethod
    def unlink(path: Path) -> None:
        LinuxPublicationOperations.unlink(path)


def test_publication_uses_current_as_the_only_commit_record(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()

    result = publish_candidate(
        _candidate(), root, run_id="no-journal", operations=NoRecoveryJournalOperations()
    )

    assert result.state is PublicationState.DURABLE_SUCCESS
    assert not tuple(root.glob(".recovery-*.json"))
    assert os.readlink(root / "current") == result.release_path


def test_operator_can_retry_after_reestablishing_aou_without_a_journal(
    tmp_path: Path,
) -> None:
    root, _ = _root_with_previous_release(tmp_path, "aou-pointer-sync")

    failed = publish_candidate(
        _changed_candidate(),
        root,
        run_id="uncertain",
        operations=FailPointerDirectorySync(root),
    )

    assert failed.state is PublicationState.COMMIT_INDETERMINATE
    assert not tuple(root.glob(".recovery-*.json"))
    # The next call represents operator re-establishment after the injected
    # one-shot synchronization fault; no journal can prove that external act.
    assert recover_publication_if_present(root) is None
    retried = publish_candidate(_changed_candidate(), root, run_id="retry")
    assert retried.state is PublicationState.DURABLE_SUCCESS


def test_lock_bytes_are_not_a_persistent_publication_state(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    (root / ".publication.lock").write_bytes(b"arbitrary prior process bytes")

    result = publish_candidate(_candidate(), root, run_id="ordinary-lock")

    assert result.state is PublicationState.DURABLE_SUCCESS


def test_startup_preflight_rejects_an_invalid_current_without_a_journal(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    first = publish_candidate(_candidate(), root, run_id="first")
    assert first.state is PublicationState.DURABLE_SUCCESS
    (root / "current").unlink()
    (root / "current").symlink_to("releases/bundle:sha256:" + "f" * 64)

    result = recover_publication_if_present(root)

    assert result is not None
    assert result.state is PublicationState.RECOVERY_BLOCKED
    assert result.exit_code == 14


def test_not_attempted_permits_only_idempotent_infrastructure_initialization(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    malformed = Candidate((("reports/run.json", _run_report()),))

    result = publish_candidate(malformed, root, run_id="malformed")

    assert result.state is PublicationState.NOT_ATTEMPTED
    assert {path.name for path in root.iterdir()} == {".publication.lock", "releases"}
    assert tuple((root / "releases").iterdir()) == ()
