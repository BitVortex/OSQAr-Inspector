"""Linux immutable-release publication with explicit durability states."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import shutil
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Protocol

from .bundle_generation import (
    BundleGenerationError,
    FinalizedCandidate,
    generate_bundle,
)
from .configuration import canonical_json
from .verify import VerificationError, verify_bundle

PUBLICATION_SCHEMA = "osqar.inspector.publication-result.v1"
_RUN_REPORT_PATH = "reports/run.json"


class PublicationState(str, Enum):
    NOT_ATTEMPTED = "not-attempted"
    DEFINITE_PRE_COMMIT_FAILURE = "definite-pre-commit-failure"
    COMMIT_INDETERMINATE = "commit-indeterminate"
    DURABLE_SUCCESS = "durable-success"
    RECOVERED_DURABLE_SUCCESS = "recovered-durable-success"
    RECOVERED_NO_COMMIT = "recovered-no-commit"
    RECOVERY_BLOCKED = "recovery-blocked"


_EXIT_CODES = {
    PublicationState.NOT_ATTEMPTED: 10,
    PublicationState.DEFINITE_PRE_COMMIT_FAILURE: 11,
    PublicationState.COMMIT_INDETERMINATE: 12,
    PublicationState.DURABLE_SUCCESS: 0,
    PublicationState.RECOVERED_DURABLE_SUCCESS: 0,
    PublicationState.RECOVERED_NO_COMMIT: 13,
    PublicationState.RECOVERY_BLOCKED: 14,
}


@dataclass(frozen=True)
class PublicationDiagnostic:
    code: str
    message: str

    def value(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class PublicationResult:
    run_id: str
    state: PublicationState
    bundle_id: str | None
    release_path: str | None
    run_report_path: str
    run_report_sha256: str | None
    prior_current_target: str | None
    intended_current_target: str | None
    diagnostics: tuple[PublicationDiagnostic, ...] = ()

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self.state]

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(
            {
                "bundle_id": self.bundle_id,
                "diagnostics": [item.value() for item in self.diagnostics],
                "intended_current_target": self.intended_current_target,
                "prior_current_target": self.prior_current_target,
                "release_path": self.release_path,
                "run_id": self.run_id,
                "run_report_path": self.run_report_path,
                "run_report_sha256": self.run_report_sha256,
                "schema": PUBLICATION_SCHEMA,
                "state": self.state.value,
            }
        )


class PublicationOperations(Protocol):
    def fsync_file(self, path: Path) -> None: ...

    def fsync_directory(self, path: Path) -> None: ...

    def rename(self, source: Path, destination: Path) -> None: ...

    def replace(self, source: Path, destination: Path) -> None: ...

    def symlink(self, target: str, path: Path) -> None: ...

    def unlink(self, path: Path) -> None: ...


class LinuxPublicationOperations:
    """Injectable Linux filesystem operations at every durability boundary."""

    @staticmethod
    def fsync_file(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("publication member is not a regular file")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def fsync_directory(path: Path) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def rename(source: Path, destination: Path) -> None:
        os.rename(source, destination)

    @staticmethod
    def replace(source: Path, destination: Path) -> None:
        os.replace(source, destination)

    @staticmethod
    def symlink(target: str, path: Path) -> None:
        os.symlink(target, path)


    @staticmethod
    def unlink(path: Path) -> None:
        path.unlink()


def valid_run_id(value: str) -> bool:
    """Return whether a run identifier is one safe publication path component."""

    return (
        bool(value)
        and value not in {".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def valid_caller_run_id(value: str) -> bool:
    """Return whether a run identifier is valid and not reserved for recovery."""

    return value != "recovery" and valid_run_id(value)


def _directory(path: Path, code: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise OSError(f"{code}: directory cannot be inspected") from error
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(f"{code}: path is not a real directory")
    return info


def _open_lock(root: Path) -> int:
    """Open the advisory single-writer lock; its contents carry no state."""
    common = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    lock = root / ".publication.lock"
    return os.open(lock, common | os.O_CREAT, 0o600)


@contextmanager
def _publication_lock(root: Path) -> Iterator[None]:
    root_info = _directory(root, "publication.invalid_root")
    descriptor = _open_lock(root)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_dev != root_info.st_dev:
            raise OSError("publication.lock_unsafe: lock is not a same-filesystem regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class _ClosedCandidate:
    payloads: tuple[tuple[str, bytes], ...]
    candidate_ready: bool = True


def _close_candidate(candidate: FinalizedCandidate) -> _ClosedCandidate:
    try:
        candidate_ready = candidate.candidate_ready
        payloads = candidate.payloads
    except Exception as error:
        raise BundleGenerationError(
            "bundle.invalid_candidate", "candidate does not expose finalized payloads"
        ) from error
    if candidate_ready is not True or type(payloads) is not tuple:
        raise BundleGenerationError(
            "bundle.invalid_candidate", "candidate is not a finalized payload collection"
        )
    if any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not str
        or type(item[1]) is not bytes
        for item in payloads
    ):
        raise BundleGenerationError(
            "bundle.invalid_candidate", "candidate contains a malformed payload"
        )
    return _ClosedCandidate(payloads)


def _run_report(candidate: FinalizedCandidate) -> bytes:
    payloads = _close_candidate(candidate).payloads
    matches = [content for path, content in payloads if path == _RUN_REPORT_PATH]
    if len(matches) != 1:
        raise BundleGenerationError(
            "bundle.missing_entry_point",
            "candidate omits the exact run report",
            _RUN_REPORT_PATH,
        )
    return matches[0]


def _current_target(root: Path) -> str | None:
    current = root / "current"
    try:
        info = current.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(info.st_mode):
        raise OSError("publication.current_unsafe: current is not a symbolic link")
    return os.readlink(current)


def _sync_candidate(root: Path, operations: PublicationOperations) -> None:
    root_info = _directory(root, "publication.candidate_unsafe")
    files: list[Path] = []
    directories: list[Path] = [root]
    for path in root.rglob("*"):
        info = path.lstat()
        if info.st_dev != root_info.st_dev:
            raise OSError(
                "publication.cross_filesystem: candidate entries must share one filesystem"
            )
        if stat.S_ISREG(info.st_mode):
            files.append(path)
        elif stat.S_ISDIR(info.st_mode):
            directories.append(path)
        else:
            raise OSError(
                "publication.candidate_unsafe: candidate contains an unsafe entry"
            )
    for path in sorted(
        files, key=lambda item: item.relative_to(root).as_posix().encode()
    ):
        operations.fsync_file(path)
    for path in sorted(
        directories,
        key=lambda item: (
            -len(item.relative_to(root).parts),
            item.relative_to(root).as_posix().encode(),
        ),
    ):
        operations.fsync_directory(path)


def _accept_release(
    candidate_root: Path,
    release: Path,
    bundle_id: str,
    operations: PublicationOperations,
) -> None:
    """Install a new release or discard the candidate after exact independent reuse verification."""

    try:
        release_info = release.lstat()
    except FileNotFoundError:
        try:
            operations.rename(candidate_root, release)
            return
        except FileExistsError:
            release_info = release.lstat()
    if not stat.S_ISDIR(release_info.st_mode):
        raise OSError(
            "publication.release_unsafe: existing release is not a real directory"
        )
    try:
        verified_id = verify_bundle(release)
    except VerificationError as error:
        raise OSError(
            f"publication.release_identity_mismatch: existing release failed verification ({error.code})"
        ) from error
    if verified_id != bundle_id:
        raise OSError(
            "publication.release_identity_mismatch: existing release has a different identity"
        )
    shutil.rmtree(candidate_root)


def _cleanup_owned_candidate(
    path: Path | None, operations: PublicationOperations
) -> OSError | None:
    if path is None:
        return None
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        return error
    if not stat.S_ISDIR(info.st_mode):
        return OSError("publication.candidate_cleanup_unsafe: owned candidate is not a directory")
    try:
        shutil.rmtree(path)
        operations.fsync_directory(path.parent)
    except OSError as error:
        return error
    return None


def _cleanup_precommit_evidence(
    root: Path,
    temporary: Path | None,
    intended: str | None,
    operations: PublicationOperations,
) -> OSError | None:
    removed = False
    try:
        if temporary is not None:
            try:
                info = temporary.lstat()
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISLNK(info.st_mode) or os.readlink(temporary) != intended:
                    raise OSError(
                        "publication.temporary_cleanup_unsafe: owned pointer is not the expected symlink"
                    )
                operations.unlink(temporary)
                removed = True
        if removed:
            operations.fsync_directory(root)
    except OSError as error:
        return error
    return None


def _failure(
    run_id: str,
    state: PublicationState,
    code: str,
    message: str,
    *,
    bundle_id: str | None = None,
    release_path: str | None = None,
    run_report_sha256: str | None = None,
    prior: str | None = None,
    intended: str | None = None,
) -> PublicationResult:
    return PublicationResult(
        run_id,
        state,
        bundle_id,
        release_path,
        _RUN_REPORT_PATH,
        run_report_sha256,
        prior,
        intended,
        (PublicationDiagnostic(code, message),),
    )


def _publish_candidate_locked(
    candidate: FinalizedCandidate,
    publication_root: Path,
    *,
    run_id: str,
    operations: PublicationOperations | None = None,
) -> PublicationResult:
    """Publish one immutable release with ``current`` as the sole commit object.

    Success records filesystem placement and durability only. It does not establish
    review, authorization, fitness, qualification, certification, or compliance.
    """

    ops = operations or LinuxPublicationOperations()
    root = Path(publication_root)
    owned_temporary: Path | None = None
    candidate_root: Path | None = None
    candidate_owned = False
    replacement_started = False
    if not valid_run_id(run_id):
        return _failure(
            run_id,
            PublicationState.NOT_ATTEMPTED,
            "publication.invalid_run_id",
            "run identifier must be one safe path component",
        )
    try:
        root_info = _directory(root, "publication.invalid_root")
        if tuple(root.glob(".recovery-*.json")):
            return _failure(
                run_id,
                PublicationState.RECOVERY_BLOCKED,
                "publication.legacy_recovery_record",
                "a legacy recovery record requires operator inspection",
            )
        releases = root / "releases"
        try:
            releases.mkdir()
        except FileExistsError:
            pass
        releases_info = _directory(releases, "publication.invalid_releases")
        if releases_info.st_dev != root_info.st_dev:
            raise OSError(
                "publication.cross_filesystem: releases must share the publication filesystem"
            )
        prior = _current_target(root)
        if prior is not None:
            try:
                _verify_release_target(root, prior)
            except OSError as error:
                raise OSError(
                    f"publication.current_target_unsafe: existing current target is invalid ({error})"
                ) from error
        report = _run_report(candidate)
        report_digest = hashlib.sha256(report).hexdigest()
        candidate_root = releases / f".candidate-{run_id}"
        try:
            candidate_root.lstat()
        except FileNotFoundError:
            candidate_preexisting = False
        else:
            candidate_preexisting = True
        generated = generate_bundle(candidate, candidate_root)
        candidate_owned = not candidate_preexisting
        bundle_id = generated.bundle_id
        release_path = f"releases/{bundle_id}"
        intended = release_path
        release = root / release_path
        _sync_candidate(candidate_root, ops)
        _accept_release(candidate_root, release, bundle_id, ops)
        ops.fsync_directory(releases)
        _verify_release_target(
            root,
            intended,
            expected_bundle_id=bundle_id,
            expected_run_report_sha256=report_digest,
        )
        temporary = root / f".current-{run_id}"
        try:
            temporary.lstat()
        except FileNotFoundError:
            owned_temporary = temporary
        else:
            raise OSError(
                "publication.temporary_unsafe: temporary pointer already exists"
            )
        ops.symlink(intended, temporary)
        replacement_started = True
        ops.replace(temporary, root / "current")
        ops.fsync_directory(root)
        _verify_release_target(
            root,
            intended,
            expected_bundle_id=bundle_id,
            expected_run_report_sha256=report_digest,
        )
    except BundleGenerationError as error:
        publication_attempted = bool(locals().get("candidate_preexisting", False))
        if candidate_root is not None and not publication_attempted:
            try:
                info = candidate_root.lstat()
            except FileNotFoundError:
                pass
            else:
                publication_attempted = True
                candidate_owned = stat.S_ISDIR(info.st_mode)
        cleanup_error = (
            _cleanup_owned_candidate(candidate_root, ops) if candidate_owned else None
        )
        message = error.message
        if cleanup_error is not None:
            message += (
                f"; owned candidate cleanup failed: {cleanup_error}; "
                "the filesystem assumption is no longer established"
            )
        return _failure(
            run_id,
            PublicationState.DEFINITE_PRE_COMMIT_FAILURE
            if publication_attempted
            else PublicationState.NOT_ATTEMPTED,
            error.code,
            message,
        )
    except OSError as error:
        evidence_cleanup_error = (
            _cleanup_precommit_evidence(
                root, owned_temporary, locals().get("intended"), ops
            )
            if not replacement_started
            else None
        )
        cleanup_error = (
            _cleanup_owned_candidate(candidate_root, ops)
            if not replacement_started and candidate_owned
            else None
        )
        state = (
            PublicationState.COMMIT_INDETERMINATE
            if replacement_started
            else PublicationState.DEFINITE_PRE_COMMIT_FAILURE
        )
        message = str(error)
        if evidence_cleanup_error is not None:
            message += f"; pre-commit evidence cleanup failed: {evidence_cleanup_error}"
        if cleanup_error is not None:
            message += f"; owned candidate cleanup failed: {cleanup_error}"
        message += "; automatic retry requires the filesystem assumption to be re-established"
        return _failure(
            run_id,
            state,
            "publication.filesystem_error",
            message,
            bundle_id=locals().get("bundle_id"),
            release_path=locals().get("release_path"),
            run_report_sha256=locals().get("report_digest"),
            prior=locals().get("prior"),
            intended=locals().get("intended"),
        )

    return PublicationResult(
        run_id,
        PublicationState.DURABLE_SUCCESS,
        bundle_id,
        release_path,
        _RUN_REPORT_PATH,
        report_digest,
        prior,
        intended,
    )





def publish_candidate(
    candidate: FinalizedCandidate,
    publication_root: Path,
    *,
    run_id: str,
    operations: PublicationOperations | None = None,
) -> PublicationResult:
    """Serialize and publish one closed candidate."""

    root = Path(publication_root)
    if not valid_run_id(run_id):
        return _failure(
            run_id,
            PublicationState.NOT_ATTEMPTED,
            "publication.invalid_run_id",
            "run identifier must be one safe path component",
        )
    try:
        closed_candidate = _close_candidate(candidate)
        _run_report(closed_candidate)
    except BundleGenerationError as error:
        return _failure(
            run_id,
            PublicationState.NOT_ATTEMPTED,
            error.code,
            error.message,
        )
    locked_result: PublicationResult | None = None
    try:
        with _publication_lock(root):
            locked_result = _publish_candidate_locked(
                closed_candidate, root, run_id=run_id, operations=operations
            )
    except OSError as error:
        if locked_result is not None:
            return replace(
                locked_result,
                diagnostics=locked_result.diagnostics
                + (
                    PublicationDiagnostic(
                        "publication.lock_release_error",
                        f"publication result preserved after lock teardown failed: {error}",
                    ),
                ),
            )
        return _failure(
            run_id,
            PublicationState.DEFINITE_PRE_COMMIT_FAILURE,
            "publication.filesystem_error",
            str(error),
        )
    assert locked_result is not None
    return locked_result





def _verify_release_target(
    root: Path,
    target: str,
    *,
    expected_bundle_id: str | None = None,
    expected_run_report_sha256: str | None = None,
) -> str:
    if re.fullmatch(r"releases/bundle:sha256:[0-9a-f]{64}", target) is None:
        raise OSError(
            "publication.recovery_target_unsafe: current target is outside the release profile"
        )
    release = root / target
    try:
        info = release.lstat()
    except OSError as error:
        raise OSError(
            "publication.recovery_target_missing: pointed release is unavailable"
        ) from error
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(
            "publication.recovery_target_unsafe: pointed release is not a real directory"
        )
    publication_device = _directory(root, "publication.invalid_root").st_dev
    if info.st_dev != publication_device:
        raise OSError(
            "publication.cross_filesystem: pointed release is on another filesystem"
        )
    for member in release.rglob("*"):
        if member.lstat().st_dev != publication_device:
            raise OSError(
                "publication.cross_filesystem: release entries must share one filesystem"
            )
    try:
        verified = verify_bundle(release)
    except VerificationError as error:
        raise OSError(
            f"publication.recovery_identity_mismatch: pointed release failed verification ({error.code})"
        ) from error
    named = target.removeprefix("releases/")
    if verified != named or (
        expected_bundle_id is not None and verified != expected_bundle_id
    ):
        raise OSError(
            "publication.recovery_identity_mismatch: pointed release identity does not match"
        )
    if expected_run_report_sha256 is not None:
        try:
            digest = hashlib.sha256(
                (release / _RUN_REPORT_PATH).read_bytes()
            ).hexdigest()
        except OSError as error:
            raise OSError(
                "publication.recovery_report_unavailable: run report cannot be read"
            ) from error
        if digest != expected_run_report_sha256:
            raise OSError(
                "publication.recovery_report_mismatch: run report digest does not match"
            )
    return verified


def _reconcile_current_locked(
    publication_root: Path,
    operations: PublicationOperations | None = None,
) -> tuple[str, str, str] | None:
    """Synchronize and verify the sole observable commit object, if present."""

    ops = operations or LinuxPublicationOperations()
    root = Path(publication_root)
    _directory(root, "publication.invalid_root")
    if tuple(root.glob(".recovery-*.json")):
        raise OSError(
            "publication.legacy_recovery_record: operator inspection is required"
        )
    target = _current_target(root)
    ops.fsync_directory(root)
    if target is None:
        return None
    bundle_id = _verify_release_target(root, target)
    _verify_release_target(root, target, expected_bundle_id=bundle_id)
    try:
        report_digest = hashlib.sha256(
            (root / target / _RUN_REPORT_PATH).read_bytes()
        ).hexdigest()
    except OSError as error:
        raise OSError(
            "publication.recovery_report_unavailable: run report cannot be read"
        ) from error
    return target, bundle_id, report_digest


def _reconciliation_result(
    reconciled: tuple[str, str, str] | None,
    diagnostics: tuple[PublicationDiagnostic, ...] = (),
) -> PublicationResult:
    if reconciled is None:
        return PublicationResult(
            "recovery",
            PublicationState.RECOVERED_NO_COMMIT,
            None,
            None,
            _RUN_REPORT_PATH,
            None,
            None,
            None,
            diagnostics,
        )
    target, bundle_id, report_digest = reconciled
    return PublicationResult(
        "recovery",
        PublicationState.RECOVERED_DURABLE_SUCCESS,
        bundle_id,
        target,
        _RUN_REPORT_PATH,
        report_digest,
        target,
        None,
        diagnostics,
    )


def recover_publication(
    publication_root: Path,
    *,
    operations: PublicationOperations | None = None,
) -> PublicationResult:
    """Reconcile the exact observable ``current`` pointer under the writer lock."""

    root = Path(publication_root)
    reconciled: tuple[str, str, str] | None = None
    reconciliation_completed = False
    try:
        with _publication_lock(root):
            reconciled = _reconcile_current_locked(root, operations)
            reconciliation_completed = True
    except OSError as error:
        if reconciliation_completed:
            return _reconciliation_result(
                reconciled,
                (
                    PublicationDiagnostic(
                        "publication.lock_release_error",
                        f"reconciliation result preserved after lock teardown failed: {error}",
                    ),
                ),
            )
        return _failure(
            "recovery",
            PublicationState.RECOVERY_BLOCKED,
            "publication.recovery_blocked",
            f"{error}; operator inspection is required",
        )
    return _reconciliation_result(reconciled)


def recover_publication_if_present(
    publication_root: Path,
    *,
    operations: PublicationOperations | None = None,
) -> PublicationResult | None:
    """Run startup reconciliation; return a result whenever startup must stop."""

    root = Path(publication_root)
    reconciled: tuple[str, str, str] | None = None
    reconciliation_completed = False
    try:
        with _publication_lock(root):
            reconciled = _reconcile_current_locked(root, operations)
            reconciliation_completed = True
    except OSError as error:
        if reconciliation_completed:
            return _reconciliation_result(
                reconciled,
                (
                    PublicationDiagnostic(
                        "publication.lock_release_error",
                        f"reconciliation result preserved after lock teardown failed: {error}",
                    ),
                ),
            )
        return _failure(
            "recovery",
            PublicationState.RECOVERY_BLOCKED,
            "publication.recovery_blocked",
            f"{error}; operator inspection is required",
        )
    return None
