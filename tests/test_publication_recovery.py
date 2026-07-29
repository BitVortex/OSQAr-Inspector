from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path

from test_publication import Candidate, _candidate

from osqar_inspector.publication import (
    LinuxPublicationOperations,
    PublicationResult,
    PublicationState,
    publish_candidate,
    recover_publication,
    recover_publication_if_present,
)


class FailBeforeReplace(LinuxPublicationOperations):
    @staticmethod
    def replace(source: Path, destination: Path) -> None:
        raise OSError("injected failure before pointer replacement")


class FailAfterReplace(LinuxPublicationOperations):
    @staticmethod
    def replace(source: Path, destination: Path) -> None:
        LinuxPublicationOperations.replace(source, destination)
        raise OSError("injected uncertain result after pointer replacement")


class FailReconciliationSync(LinuxPublicationOperations):
    @staticmethod
    def fsync_directory(path: Path) -> None:
        raise OSError("injected reconciliation synchronization failure")


def _changed_candidate() -> Candidate:
    original = _candidate()
    return Candidate(original.payloads + (("artifacts/new.txt", b"new release"),))


def _root_with_previous_release(tmp_path: Path, name: str) -> tuple[Path, str]:
    root = tmp_path / name
    root.mkdir()
    previous = publish_candidate(_candidate(), root, run_id="previous")
    assert previous.state is PublicationState.DURABLE_SUCCESS
    assert previous.release_path is not None
    return root, previous.release_path


def test_reconciliation_accepts_whichever_exact_release_current_names(
    tmp_path: Path,
) -> None:
    uncommitted_root, old_target = _root_with_previous_release(tmp_path, "uncommitted")
    uncertain_no_commit = publish_candidate(
        _changed_candidate(),
        uncommitted_root,
        run_id="next",
        operations=FailBeforeReplace(),
    )
    assert uncertain_no_commit.state is PublicationState.COMMIT_INDETERMINATE
    assert os.readlink(uncommitted_root / "current") == old_target

    old_reconciled = recover_publication(uncommitted_root)

    assert old_reconciled.state is PublicationState.RECOVERED_DURABLE_SUCCESS
    assert old_reconciled.release_path == old_target
    assert old_reconciled.prior_current_target == old_target
    assert old_reconciled.intended_current_target is None

    committed_root, _ = _root_with_previous_release(tmp_path, "committed")
    uncertain_commit = publish_candidate(
        _changed_candidate(),
        committed_root,
        run_id="next",
        operations=FailAfterReplace(),
    )
    assert uncertain_commit.state is PublicationState.COMMIT_INDETERMINATE
    assert uncertain_commit.intended_current_target is not None

    new_reconciled = recover_publication(committed_root)

    assert new_reconciled.state is PublicationState.RECOVERED_DURABLE_SUCCESS
    assert new_reconciled.bundle_id == uncertain_commit.bundle_id
    assert new_reconciled.release_path == uncertain_commit.intended_current_target
    assert new_reconciled.prior_current_target == uncertain_commit.intended_current_target
    assert new_reconciled.intended_current_target is None
    assert not tuple(committed_root.glob(".recovery-*.json"))


def test_reconciliation_without_current_reports_no_commit(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()

    result = recover_publication(root)

    assert result.state is PublicationState.RECOVERED_NO_COMMIT
    assert result.exit_code == 13


def test_empty_root_reconciliation_sync_failure_is_blocked(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()

    result = recover_publication(root, operations=FailReconciliationSync())

    assert result.state is PublicationState.RECOVERY_BLOCKED
    assert result.exit_code == 14


def test_empty_root_startup_sync_failure_is_blocked(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()

    result = recover_publication_if_present(root, operations=FailReconciliationSync())

    assert result is not None
    assert result.state is PublicationState.RECOVERY_BLOCKED
    assert result.exit_code == 14


def test_legacy_recovery_record_requires_operator_inspection(tmp_path: Path) -> None:
    root = tmp_path / "publication"
    root.mkdir()
    record = root / ".recovery-unknown.json"
    record.write_bytes(b"legacy-or-malformed")

    result = publish_candidate(_candidate(), root, run_id="new")

    assert result.state is PublicationState.RECOVERY_BLOCKED
    assert result.exit_code == 14
    assert result.diagnostics[0].code == "publication.legacy_recovery_record"
    assert record.read_bytes() == b"legacy-or-malformed"
    assert not (root / "releases" / ".candidate-new").exists()


def test_reconciliation_waits_for_the_single_writer_lock(tmp_path: Path) -> None:
    root, _ = _root_with_previous_release(tmp_path, "locked-recovery")
    descriptor = os.open(root / ".publication.lock", os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    results: list[PublicationResult] = []
    started = threading.Event()

    def recover() -> None:
        started.set()
        results.append(recover_publication(root))

    worker = threading.Thread(target=recover)
    worker.start()
    assert started.wait(timeout=1)
    worker.join(timeout=0.1)
    assert worker.is_alive()

    fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert results[0].state is PublicationState.RECOVERED_DURABLE_SUCCESS


def test_recovery_lock_release_failure_preserves_reconciled_identity(
    tmp_path: Path, monkeypatch
) -> None:
    root, target = _root_with_previous_release(tmp_path, "recovery-lock-release")
    real_flock = fcntl.flock

    def fail_after_unlock(descriptor: int, operation: int) -> None:
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN:
            raise OSError("injected recovery lock-release failure")

    monkeypatch.setattr(fcntl, "flock", fail_after_unlock)

    result = recover_publication(root)

    assert result.state is PublicationState.RECOVERED_DURABLE_SUCCESS
    assert result.exit_code == 0
    assert result.release_path == target
    assert result.prior_current_target == target
    assert result.intended_current_target is None
    assert result.diagnostics[-1].code == "publication.lock_release_error"


def test_startup_lock_release_failure_returns_the_reconciled_result(
    tmp_path: Path, monkeypatch
) -> None:
    root, target = _root_with_previous_release(tmp_path, "startup-lock-release")
    real_flock = fcntl.flock

    def fail_after_unlock(descriptor: int, operation: int) -> None:
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN:
            raise OSError("injected startup lock-release failure")

    monkeypatch.setattr(fcntl, "flock", fail_after_unlock)

    result = recover_publication_if_present(root)

    assert result is not None
    assert result.state is PublicationState.RECOVERED_DURABLE_SUCCESS
    assert result.exit_code == 0
    assert result.release_path == target
    assert result.prior_current_target == target
    assert result.intended_current_target is None
    assert result.diagnostics[-1].code == "publication.lock_release_error"


def test_startup_reconciliation_sync_failure_requires_operator_inspection(
    tmp_path: Path,
) -> None:
    root, target = _root_with_previous_release(tmp_path, "sync-failure")

    blocked = recover_publication_if_present(root, operations=FailReconciliationSync())

    assert blocked is not None
    assert blocked.state is PublicationState.RECOVERY_BLOCKED
    assert os.readlink(root / "current") == target
    # The following call represents a new operator-authorized invocation after
    # the injected one-shot fault has been investigated and the AoU restored.
    assert recover_publication_if_present(root) is None
