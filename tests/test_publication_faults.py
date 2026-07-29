from __future__ import annotations

import os
from pathlib import Path

import pytest
from test_publication_recovery import _changed_candidate, _root_with_previous_release

from osqar_inspector.publication import (
    LinuxPublicationOperations,
    PublicationState,
    publish_candidate,
)


class FaultOperations:
    def __init__(self, boundary: str) -> None:
        self.boundary = boundary
        self.replacement_reached = False
        self.failed = False

    def _fail(self, boundary: str) -> None:
        if self.boundary == boundary and not self.failed:
            self.failed = True
            raise OSError(f"injected {boundary} failure")

    @staticmethod
    def _candidate_relative(path: Path) -> str | None:
        for index, part in enumerate(path.parts):
            if part.startswith(".candidate-"):
                return (
                    Path(*path.parts[index + 1 :]).as_posix()
                    if index + 1 < len(path.parts)
                    else "."
                )
        return None

    def fsync_file(self, path: Path) -> None:
        relative = self._candidate_relative(path)
        self._fail(f"file-sync:{relative}")
        self._fail("file-sync")
        LinuxPublicationOperations.fsync_file(path)

    def fsync_directory(self, path: Path) -> None:
        relative = self._candidate_relative(path)
        if relative is not None:
            self._fail(f"candidate-directory-sync:{relative}")
            self._fail("candidate-directory-sync")
        elif path.name == "releases":
            self._fail("releases-directory-sync")
        elif self.replacement_reached:
            self._fail("pointer-directory-sync")
        LinuxPublicationOperations.fsync_directory(path)

    def rename(self, source: Path, destination: Path) -> None:
        self._fail("release-rename")
        LinuxPublicationOperations.rename(source, destination)

    def replace(self, source: Path, destination: Path) -> None:
        self._fail("pointer-replacement")
        LinuxPublicationOperations.replace(source, destination)
        self.replacement_reached = True

    def symlink(self, target: str, path: Path) -> None:
        self._fail("temporary-pointer-create")
        LinuxPublicationOperations.symlink(target, path)

    @staticmethod
    def unlink(path: Path) -> None:
        LinuxPublicationOperations.unlink(path)


class CleanupDirectorySyncFailure(FaultOperations):
    def __init__(self) -> None:
        super().__init__("file-sync")

    def fsync_directory(self, path: Path) -> None:
        if self.failed and path.name == "releases":
            raise OSError("injected candidate cleanup directory-sync failure")
        super().fsync_directory(path)


@pytest.mark.parametrize(
    ("boundary", "expected_state"),
    (
        ("file-sync", PublicationState.DEFINITE_PRE_COMMIT_FAILURE),
        ("candidate-directory-sync", PublicationState.DEFINITE_PRE_COMMIT_FAILURE),
        ("release-rename", PublicationState.DEFINITE_PRE_COMMIT_FAILURE),
        ("releases-directory-sync", PublicationState.DEFINITE_PRE_COMMIT_FAILURE),
        ("temporary-pointer-create", PublicationState.DEFINITE_PRE_COMMIT_FAILURE),
        ("pointer-replacement", PublicationState.COMMIT_INDETERMINATE),
        ("pointer-directory-sync", PublicationState.COMMIT_INDETERMINATE),
    ),
)
def test_each_publication_durability_boundary_has_a_truthful_result(
    tmp_path: Path,
    boundary: str,
    expected_state: PublicationState,
) -> None:
    root, previous_target = _root_with_previous_release(tmp_path, boundary)
    operations = FaultOperations(boundary)

    result = publish_candidate(
        _changed_candidate(), root, run_id="fault", operations=operations
    )

    assert operations.failed is True
    assert result.state is expected_state
    assert result.exit_code == (
        11 if expected_state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE else 12
    )
    current_target = os.readlink(root / "current")
    if expected_state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE:
        assert current_target == previous_target
    else:
        assert current_target in {previous_target, result.intended_current_target}
    assert not tuple(root.glob(".recovery-*.json"))
    assert "filesystem assumption" in result.diagnostics[0].message


@pytest.mark.parametrize("cleanup_failure", ("remove", "sync"))
def test_cleanup_failure_reports_that_the_filesystem_assumption_was_lost(
    tmp_path: Path, monkeypatch, cleanup_failure: str
) -> None:
    root, previous_target = _root_with_previous_release(tmp_path, cleanup_failure)
    operations: FaultOperations = FaultOperations("file-sync")
    if cleanup_failure == "remove":
        monkeypatch.setattr(
            "osqar_inspector.publication.shutil.rmtree",
            lambda path: (_ for _ in ()).throw(OSError("injected candidate cleanup failure")),
        )
    else:
        operations = CleanupDirectorySyncFailure()

    failed = publish_candidate(
        _changed_candidate(), root, run_id="cleanup", operations=operations
    )

    assert failed.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert os.readlink(root / "current") == previous_target
    assert "automatic retry requires" in failed.diagnostics[0].message


@pytest.mark.parametrize(
    "boundary", ("file-sync", "release-rename", "temporary-pointer-create")
)
def test_definite_pre_commit_failure_cleans_owned_state_for_retry(
    tmp_path: Path, boundary: str
) -> None:
    root, previous_target = _root_with_previous_release(tmp_path, f"retry-{boundary}")

    failed = publish_candidate(
        _changed_candidate(),
        root,
        run_id="retry",
        operations=FaultOperations(boundary),
    )

    assert failed.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert not (root / "releases" / ".candidate-retry").exists()
    assert not (root / ".current-retry").exists()
    assert os.readlink(root / "current") == previous_target
    retried = publish_candidate(_changed_candidate(), root, run_id="retry")
    assert retried.state is PublicationState.DURABLE_SUCCESS


@pytest.mark.parametrize(
    "relative",
    (
        "artifacts/new.txt",
        "checksums.sha256",
        "manifest.json",
        "navigation/index.html",
        "reports/run.json",
    ),
)
def test_every_candidate_file_sync_is_fault_injected(
    tmp_path: Path, relative: str
) -> None:
    root, previous_target = _root_with_previous_release(
        tmp_path, relative.replace("/", "-")
    )
    operations = FaultOperations(f"file-sync:{relative}")

    result = publish_candidate(
        _changed_candidate(), root, run_id="file-fault", operations=operations
    )

    assert operations.failed is True
    assert result.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert os.readlink(root / "current") == previous_target


@pytest.mark.parametrize("relative", ("artifacts", "navigation", "reports", "."))
def test_every_candidate_directory_sync_is_fault_injected(
    tmp_path: Path, relative: str
) -> None:
    root, previous_target = _root_with_previous_release(
        tmp_path, "directory-" + relative.replace(".", "root")
    )
    operations = FaultOperations(f"candidate-directory-sync:{relative}")

    result = publish_candidate(
        _changed_candidate(), root, run_id="directory-fault", operations=operations
    )

    assert operations.failed is True
    assert result.state is PublicationState.DEFINITE_PRE_COMMIT_FAILURE
    assert os.readlink(root / "current") == previous_target
