"""Immutable clean-Git snapshot capture and owned materialization."""

from __future__ import annotations

import hashlib
import os
import posixpath
import stat
import subprocess
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.metadata import version as package_version
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from .configuration import canonical_json

SCHEMA_ID = "osqar.inspector.snapshot.v1"
_SUPPORTED_MODES = {"100644", "100755", "120000"}


@dataclass
class SnapshotError(Exception):
    """A fail-closed snapshot error with a stable machine-readable code."""

    code: str
    message: str
    path: str | None = None

    def __str__(self) -> str:
        suffix = f" ({self.path})" if self.path is not None else ""
        return f"{self.code}: {self.message}{suffix}"


@dataclass(frozen=True)
class GitSnapshot:
    """A deterministic manifest plus private Git-object materialization bytes."""

    manifest: dict[str, Any]
    manifest_bytes: bytes
    snapshot_id: str
    files: tuple[dict[str, Any], ...]
    _content: tuple[tuple[str, bytes], ...]


def _fail(code: str, message: str, path: str | None = None) -> NoReturn:
    raise SnapshotError(code, message, path)


def _git(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", os.fspath(repo), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    except OSError as error:
        _fail("snapshot.git_unavailable", f"cannot execute Git: {error}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        _fail("snapshot.git_error", detail or "Git command failed")
    return result.stdout


def _path(value: str) -> str:
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _fail("snapshot.invalid_path", "path is not representable as UTF-8", value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _fail("snapshot.invalid_path", "path does not satisfy the v1 profile", value)
    return value


def _policy(paths: Sequence[str], name: str) -> tuple[str, ...]:
    if isinstance(paths, (str, bytes)):
        _fail("snapshot.invalid_policy", f"{name} must be a sequence of paths")
    checked = [_path(item) if isinstance(item, str) else _fail(
        "snapshot.invalid_policy", f"{name} entries must be strings"
    ) for item in paths]
    if len(checked) != len(set(checked)):
        _fail("snapshot.invalid_policy", f"{name} contains duplicate paths")
    return tuple(sorted(checked, key=str.encode))


def _selected(path: str, include: tuple[str, ...], exclude: tuple[str, ...]) -> bool:
    def contains(root: str, candidate: str) -> bool:
        return candidate == root or candidate.startswith(root + "/")

    included = not include or any(contains(root, path) for root in include)
    return included and not any(contains(root, path) for root in exclude)


def _require_clean(repo: Path, allowed_untracked: tuple[str, ...] = ()) -> None:
    if _git(repo, "ls-files", "--unmerged", "-z"):
        _fail("snapshot.unmerged_worktree", "Git index contains unmerged entries")
    status = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    for record in status.split(b"\0"):
        if not record:
            continue
        if record.startswith(b"?? "):
            path = record[3:]
            if any(
                path == root.encode("utf-8")
                or path.startswith(root.encode("utf-8") + b"/")
                for root in allowed_untracked
            ):
                continue
        _fail("snapshot.dirty_worktree", "Git worktree has tracked or untracked changes")


def _decode_path(raw: bytes) -> str:
    try:
        return _path(raw.decode("utf-8", "strict"))
    except UnicodeDecodeError:
        _fail("snapshot.invalid_path", "Git path is not valid UTF-8")


def _symlink_target(path: str, blob: bytes) -> tuple[str, str]:
    try:
        target = blob.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail("snapshot.invalid_symlink", "symlink target is not valid UTF-8", path)
    if (
        not target
        or target.startswith("/")
        or "\\" in target
        or any(unicodedata.category(character) == "Cc" for character in target)
    ):
        _fail("snapshot.invalid_symlink", "symlink target must be a relative safe path", path)
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        _fail("snapshot.symlink_escape", "symlink target escapes the snapshot root", path)
    if (
        unicodedata.normalize("NFC", target) != target
        or any(part in {"", ".", ".."} for part in target.split("/"))
    ):
        _fail(
            "snapshot.invalid_symlink",
            "symlink target does not satisfy the v1 project-relative path profile",
            path,
        )
    return target, resolved


def capture_git_snapshot(
    project: str | os.PathLike[str],
    *,
    include: Sequence[str] = (),
    exclude: Sequence[str] = (),
    allowed_untracked: Sequence[str] = (),
) -> GitSnapshot:
    """Capture selected ``HEAD`` bytes after rejecting tracked and unowned changes."""

    repo = Path(project)
    normalized_include = _policy(include, "include")
    normalized_exclude = _policy(exclude, "exclude")
    normalized_allowed_untracked = _policy(allowed_untracked, "allowed_untracked")
    _require_clean(repo, normalized_allowed_untracked)
    commit = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(repo, "rev-parse", "--verify", f"{commit}^{{tree}}").decode("ascii").strip()
    object_format = _git(repo, "rev-parse", "--show-object-format").decode("ascii").strip()
    if object_format not in {"sha1", "sha256"}:
        _fail("snapshot.unsupported_object_format", f"unsupported Git object format {object_format!r}")

    records: list[dict[str, Any]] = []
    content: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for raw_record in _git(repo, "ls-tree", "-r", "-z", "--full-tree", tree).split(b"\0"):
        if not raw_record:
            continue
        try:
            header, raw_path = raw_record.split(b"\t", 1)
            raw_mode, raw_type, raw_oid = header.split(b" ", 2)
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            oid = raw_oid.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            _fail("snapshot.git_protocol", "Git returned an invalid tree record")
        path = _decode_path(raw_path)
        if path in seen:
            _fail("snapshot.path_collision", "normalized Git paths are not unique", path)
        seen.add(path)
        if not _selected(path, normalized_include, normalized_exclude):
            continue
        if mode == "160000" or object_type == "commit":
            _fail("snapshot.unsupported_gitlink", "Gitlinks are unsupported in snapshot v1", path)
        if mode not in _SUPPORTED_MODES or object_type != "blob":
            _fail("snapshot.unsupported_entry", f"unsupported Git entry mode {mode}", path)
        blob = _git(repo, "cat-file", "blob", oid)
        kind = "symlink" if mode == "120000" else "file"
        identity = {"sha256": hashlib.sha256(blob).hexdigest()}
        if kind == "symlink":
            target, _ = _symlink_target(path, blob)
            identity = {"target": target, **identity}
        records.append(
            {
                "path": path,
                "kind": kind,
                "mode": mode,
                "size": str(len(blob)),
                "identity": identity,
            }
        )
        content.append((path, blob))

    records.sort(key=lambda record: record["path"].encode())
    content.sort(key=lambda item: item[0].encode())
    selected_modes = {record["path"]: record["mode"] for record in records}
    for record, (_, blob) in zip(records, content, strict=True):
        if record["kind"] == "symlink":
            _, resolved = _symlink_target(record["path"], blob)
            if selected_modes.get(resolved) not in {"100644", "100755"}:
                _fail(
                    "snapshot.invalid_symlink",
                    "symlink must resolve to a selected non-symlink file",
                    record["path"],
                )
    identity = {
        "schema": SCHEMA_ID,
        "source": {
            "kind": "git-clean",
            "object_format": object_format,
            "commit": commit,
            "tree": tree,
        },
        "policy": {"include": list(normalized_include), "exclude": list(normalized_exclude)},
        "files": records,
    }
    digest = hashlib.sha256(canonical_json({"kind": "snapshot", "identity": identity})).hexdigest()
    snapshot_id = f"snapshot:sha256:{digest}"
    manifest = {
        **identity,
        "snapshot_id": snapshot_id,
        "metadata": {"inspector_version": package_version("osqar-inspector")},
    }
    _require_clean(repo, normalized_allowed_untracked)
    final_commit = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    final_tree = _git(repo, "rev-parse", "--verify", f"{final_commit}^{{tree}}").decode("ascii").strip()
    if final_commit != commit or final_tree != tree:
        _fail("snapshot.capture_race", "Git HEAD changed during snapshot capture")
    return GitSnapshot(
        manifest=manifest,
        manifest_bytes=canonical_json(manifest),
        snapshot_id=snapshot_id,
        files=tuple(records),
        _content=tuple(content),
    )


def _prepare_workspace(workspace: Path) -> None:
    try:
        metadata = workspace.lstat()
    except FileNotFoundError:
        try:
            workspace.mkdir(parents=False, mode=0o700)
        except OSError as error:
            _fail("snapshot.workspace_creation_failed", str(error))
        return
    except OSError as error:
        _fail("snapshot.workspace_inspection_failed", str(error))
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        _fail("snapshot.workspace_not_owned", "workspace must be a real directory")
    try:
        if any(workspace.iterdir()):
            _fail("snapshot.workspace_not_empty", "workspace must be empty")
    except OSError as error:
        _fail("snapshot.workspace_inspection_failed", str(error))


def materialize_snapshot(snapshot: GitSnapshot, workspace: str | os.PathLike[str]) -> None:
    """Materialize exactly the selected Git-object bytes into an empty owned workspace."""

    root = Path(workspace)
    _prepare_workspace(root)
    records = {record["path"]: record for record in snapshot.files}
    ordered_content = sorted(
        snapshot._content,
        key=lambda item: records[item[0]]["kind"] == "symlink",
    )
    for path, blob in ordered_content:
        destination = root.joinpath(*PurePosixPath(path).parts)
        record = records[path]
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            parent = destination.parent
            while parent != root:
                parent.chmod(0o755)
                parent = parent.parent
            if record["kind"] == "symlink":
                target = blob.decode("utf-8", "strict")
                os.symlink(target, destination)
            else:
                with destination.open("xb") as stream:
                    stream.write(blob)
                destination.chmod(0o755 if record["mode"] == "100755" else 0o644)
        except (OSError, UnicodeDecodeError) as error:
            _fail("snapshot.materialization_failed", str(error), path)


def _hash_stream(stream: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _materialized_records(root: Path) -> tuple[tuple[dict[str, Any], ...], set[str]]:
    try:
        root_stat = root.lstat()
    except OSError as error:
        _fail("snapshot.materialization_changed", f"cannot inspect workspace: {error}")
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        _fail("snapshot.materialization_changed", "workspace root is not a real directory")

    records: list[dict[str, Any]] = []
    directories: set[str] = set()
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            _fail("snapshot.materialization_changed", f"cannot inventory workspace: {error}")
        for entry in entries:
            path = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                _path(path)
                metadata = entry.stat(follow_symlinks=False)
            except (OSError, SnapshotError) as error:
                _fail("snapshot.materialization_changed", f"invalid workspace entry: {error}", path)
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o755:
                    _fail("snapshot.materialization_changed", "directory mode changed", path)
                directories.add(path)
                pending.append((Path(entry.path), path))
                continue
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(entry.path)
                    target_bytes = target.encode("utf-8", "strict")
                except (OSError, UnicodeEncodeError) as error:
                    _fail("snapshot.materialization_changed", f"invalid symlink target: {error}", path)
                records.append(
                    {
                        "path": path,
                        "kind": "symlink",
                        "mode": "120000",
                        "size": str(len(target_bytes)),
                        "identity": {
                            "target": target,
                            "sha256": hashlib.sha256(target_bytes).hexdigest(),
                        },
                    }
                )
                continue
            if stat.S_ISREG(metadata.st_mode):
                permissions = stat.S_IMODE(metadata.st_mode)
                mode = {0o644: "100644", 0o755: "100755"}.get(
                    permissions, f"filesystem:{permissions:o}"
                )
                try:
                    with open(entry.path, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        digest, size = _hash_stream(stream)
                        after = os.fstat(stream.fileno())
                    current = os.lstat(entry.path)
                except OSError as error:
                    _fail("snapshot.materialization_changed", f"cannot hash workspace file: {error}", path)
                stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
                if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or any(
                    getattr(after, field) != getattr(current, field) for field in stable_fields
                ):
                    _fail("snapshot.materialization_changed", "workspace file changed while hashing", path)
                records.append(
                    {
                        "path": path,
                        "kind": "file",
                        "mode": mode,
                        "size": str(size),
                        "identity": {"sha256": digest},
                    }
                )
                continue
            _fail("snapshot.materialization_changed", "unsupported workspace entry type", path)
    records.sort(key=lambda record: record["path"].encode("utf-8"))
    return tuple(records), directories


def verify_materialized_snapshot(
    snapshot: GitSnapshot, workspace: str | os.PathLike[str]
) -> None:
    """Fail when the complete materialized record set differs from the snapshot."""

    actual, actual_directories = _materialized_records(Path(workspace))
    expected_directories = {
        "/".join(record["path"].split("/")[:index])
        for record in snapshot.files
        for index in range(1, len(record["path"].split("/")))
    }
    if actual != snapshot.files or actual_directories != expected_directories:
        _fail(
            "snapshot.materialization_changed",
            "complete materialized record set differs from the captured snapshot",
        )
