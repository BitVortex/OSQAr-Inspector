from __future__ import annotations

import hashlib
import os
import subprocess
from importlib.metadata import version
from pathlib import Path

import pytest

import osqar_inspector.snapshot as snapshot_module
from osqar_inspector.configuration import canonical_json
from osqar_inspector.snapshot import (
    SnapshotError,
    capture_git_snapshot,
    materialize_snapshot,
    verify_materialized_snapshot,
)


def _git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode(errors="replace"))
    return completed.stdout


def _repository(tmp_path: Path, object_format: str = "sha1") -> Path:
    repo = tmp_path / f"repo-{object_format}"
    subprocess.run(
        ["git", "init", f"--object-format={object_format}", os.fspath(repo)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _git(repo, "config", "user.name", "Snapshot Tests")
    _git(repo, "config", "user.email", "snapshot@example.invalid")
    return repo


def _commit(repo: Path, message: str = "fixture") -> None:
    _git(repo, "add", "--all")
    _git(repo, "commit", "-m", message)


def test_clean_git_snapshot_materializes_exact_inventory(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    (repo / "src").mkdir()
    (repo / "src" / "main.c").write_bytes(b"int main(void) { return 0; }\n")
    (repo / "src" / "ignored.c").write_bytes(b"ignored\n")
    (repo / "README.md").write_bytes(b"snapshot fixture\n")
    (repo / "outside.txt").write_bytes(b"not selected\n")
    _commit(repo)
    source_status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    source_bytes = (repo / "src" / "main.c").read_bytes()

    first = capture_git_snapshot(
        repo, include=["README.md", "src"], exclude=["src/ignored.c"]
    )
    second = capture_git_snapshot(
        repo, include=["src", "README.md"], exclude=["src/ignored.c"]
    )

    assert first.manifest_bytes == second.manifest_bytes
    assert first.snapshot_id == second.snapshot_id
    assert first.manifest_bytes == canonical_json(first.manifest)
    assert first.manifest["schema"] == "osqar.inspector.snapshot.v1"
    assert first.manifest["source"] == {
        "kind": "git-clean",
        "object_format": "sha1",
        "commit": _git(repo, "rev-parse", "HEAD").decode().strip(),
        "tree": _git(repo, "rev-parse", "HEAD^{tree}").decode().strip(),
    }
    assert first.manifest["policy"] == {
        "include": ["README.md", "src"],
        "exclude": ["src/ignored.c"],
    }
    assert first.manifest["metadata"] == {
        "inspector_version": version("osqar-inspector")
    }
    assert first.files == (
        {
            "path": "README.md",
            "kind": "file",
            "mode": "100644",
            "size": "17",
            "identity": {"sha256": hashlib.sha256(b"snapshot fixture\n").hexdigest()},
        },
        {
            "path": "src/main.c",
            "kind": "file",
            "mode": "100644",
            "size": "29",
            "identity": {
                "sha256": hashlib.sha256(b"int main(void) { return 0; }\n").hexdigest()
            },
        },
    )

    workspace = tmp_path / "owned-workspace"
    materialize_snapshot(first, workspace)
    assert sorted(
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if not path.is_dir()
    ) == ["README.md", "src/main.c"]
    assert (workspace / "README.md").read_bytes() == b"snapshot fixture\n"
    assert (workspace / "src" / "main.c").read_bytes() == source_bytes
    assert _git(repo, "status", "--porcelain=v1", "--untracked-files=all") == source_status
    assert (repo / "src" / "main.c").read_bytes() == source_bytes


def _supports_sha256(tmp_path: Path) -> bool:
    probe = tmp_path / "sha256-probe"
    result = subprocess.run(
        ["git", "init", "--object-format=sha256", os.fspath(probe)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.returncode == 0


def test_executable_and_internal_symlink_identity_is_stable(tmp_path: Path) -> None:
    formats = ["sha1"]
    if _supports_sha256(tmp_path):
        formats.append("sha256")

    for object_format in formats:
        repo = _repository(tmp_path, object_format)
        (repo / "bin").mkdir()
        tool_bytes = b"#!/bin/sh\nprintf 'stable\\n'\n"
        tool = repo / "bin" / "tool"
        tool.write_bytes(tool_bytes)
        tool.chmod(0o755)
        (repo / "run-tool").symlink_to("bin/tool")
        _commit(repo)

        first = capture_git_snapshot(repo)
        second = capture_git_snapshot(repo)
        executable, link = first.files
        assert executable == {
            "path": "bin/tool",
            "kind": "file",
            "mode": "100755",
            "size": str(len(tool_bytes)),
            "identity": {"sha256": hashlib.sha256(tool_bytes).hexdigest()},
        }
        assert link == {
            "path": "run-tool",
            "kind": "symlink",
            "mode": "120000",
            "size": "8",
            "identity": {
                "target": "bin/tool",
                "sha256": hashlib.sha256(b"bin/tool").hexdigest(),
            },
        }
        assert first.manifest_bytes == second.manifest_bytes
        assert first.snapshot_id == second.snapshot_id
        assert first.manifest["source"]["object_format"] == object_format

        workspace = tmp_path / f"workspace-{object_format}"
        materialize_snapshot(first, workspace)
        assert (workspace / "run-tool").is_symlink()
        assert os.readlink(workspace / "run-tool") == "bin/tool"
        assert (workspace / "run-tool").read_bytes() == tool_bytes
        assert stat_mode(workspace / "bin" / "tool") == 0o755


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_dirty_or_unmerged_worktree_is_rejected(tmp_path: Path) -> None:
    tracked = _repository(tmp_path / "tracked")
    (tracked / "file.txt").write_bytes(b"committed\n")
    _commit(tracked)
    (tracked / "file.txt").write_bytes(b"modified\n")
    with pytest.raises(SnapshotError) as dirty_error:
        capture_git_snapshot(tracked)
    assert dirty_error.value.code == "snapshot.dirty_worktree"

    untracked = _repository(tmp_path / "untracked")
    (untracked / "file.txt").write_bytes(b"committed\n")
    _commit(untracked)
    (untracked / "new.txt").write_bytes(b"untracked\n")
    with pytest.raises(SnapshotError) as untracked_error:
        capture_git_snapshot(untracked)
    assert untracked_error.value.code == "snapshot.dirty_worktree"

    conflicted = _repository(tmp_path / "conflicted")
    (conflicted / "file.txt").write_bytes(b"base\n")
    _commit(conflicted, "base")
    _git(conflicted, "checkout", "-b", "other")
    (conflicted / "file.txt").write_bytes(b"other\n")
    _commit(conflicted, "other")
    _git(conflicted, "checkout", "master")
    (conflicted / "file.txt").write_bytes(b"master\n")
    _commit(conflicted, "master")
    merge = subprocess.run(
        ["git", "-C", os.fspath(conflicted), "merge", "other"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert merge.returncode != 0
    with pytest.raises(SnapshotError) as unmerged_error:
        capture_git_snapshot(conflicted)
    assert unmerged_error.value.code == "snapshot.unmerged_worktree"


def test_escape_symlink_and_unsupported_entry_are_rejected(tmp_path: Path) -> None:
    escaping = _repository(tmp_path / "escaping")
    (escaping / "file.txt").write_bytes(b"inside\n")
    (escaping / "escape").symlink_to("../outside.txt")
    _commit(escaping)
    with pytest.raises(SnapshotError) as escape_error:
        capture_git_snapshot(escaping)
    assert escape_error.value.code == "snapshot.symlink_escape"
    assert escape_error.value.path == "escape"

    noncanonical = _repository(tmp_path / "noncanonical")
    (noncanonical / "dir").mkdir()
    (noncanonical / "dir" / "keep.txt").write_bytes(b"keep\n")
    (noncanonical / "target.txt").write_bytes(b"target\n")
    (noncanonical / "link").symlink_to("dir/../target.txt")
    _commit(noncanonical)
    with pytest.raises(SnapshotError) as target_error:
        capture_git_snapshot(noncanonical)
    assert target_error.value.code == "snapshot.invalid_symlink"
    assert target_error.value.path == "link"

    unrepresentable = _repository(tmp_path / "unrepresentable")
    decomposed_path = "cafe\N{COMBINING ACUTE ACCENT}.txt"
    (unrepresentable / decomposed_path).write_bytes(b"not NFC\n")
    _commit(unrepresentable)
    with pytest.raises(SnapshotError) as path_error:
        capture_git_snapshot(unrepresentable)
    assert path_error.value.code == "snapshot.invalid_path"
    assert path_error.value.path == decomposed_path

    parent = _repository(tmp_path / "gitlink")
    nested = parent / "vendor"
    subprocess.run(
        ["git", "init", os.fspath(nested)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _git(nested, "config", "user.name", "Snapshot Tests")
    _git(nested, "config", "user.email", "snapshot@example.invalid")
    (nested / "nested.txt").write_bytes(b"nested\n")
    _commit(nested, "nested")
    nested_head = _git(nested, "rev-parse", "HEAD").decode().strip()
    _git(parent, "update-index", "--add", "--cacheinfo", f"160000,{nested_head},vendor")
    _git(parent, "commit", "-m", "gitlink")
    assert _git(parent, "status", "--porcelain=v1", "--untracked-files=all") == b""

    with pytest.raises(SnapshotError) as unsupported_error:
        capture_git_snapshot(parent)
    assert unsupported_error.value.code == "snapshot.unsupported_gitlink"
    assert unsupported_error.value.path == "vendor"


def test_post_execution_add_remove_mode_and_byte_mutations_are_detected(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path / "source")
    (repo / "src").mkdir()
    (repo / "src" / "main.c").write_bytes(b"original\n")
    (repo / "source-link").symlink_to("src/main.c")
    _commit(repo)
    snapshot = capture_git_snapshot(repo)

    def workspace(name: str) -> Path:
        result = tmp_path / name
        materialize_snapshot(snapshot, result)
        verify_materialized_snapshot(snapshot, result)
        return result

    mutations = {
        "addition": lambda root: (root / "added.txt").write_bytes(b"added\n"),
        "removal": lambda root: (root / "src" / "main.c").unlink(),
        "mode": lambda root: (root / "src" / "main.c").chmod(0o755),
        "bytes": lambda root: (root / "src" / "main.c").write_bytes(b"changed\n"),
        "type": lambda root: (
            (root / "src" / "main.c").unlink(),
            (root / "src" / "main.c").mkdir(),
        ),
        "symlink-target": lambda root: (
            (root / "source-link").unlink(),
            (root / "source-link").symlink_to("added.txt"),
        ),
    }
    for name, mutate in mutations.items():
        root = workspace(f"workspace-{name}")
        mutate(root)
        with pytest.raises(SnapshotError) as changed:
            verify_materialized_snapshot(snapshot, root)
        assert changed.value.code == "snapshot.materialization_changed", name


def test_capture_rejects_head_change_during_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repository(tmp_path)
    (repo / "value.txt").write_bytes(b"first\n")
    _commit(repo, "first")
    first = _git(repo, "rev-parse", "HEAD").decode().strip()
    (repo / "value.txt").write_bytes(b"second\n")
    _commit(repo, "second")
    second = _git(repo, "rev-parse", "HEAD").decode().strip()
    _git(repo, "reset", "--hard", first)

    original_git = snapshot_module._git
    switched = False

    def racing_git(repository: Path, *args: str) -> bytes:
        nonlocal switched
        if not switched and args[:4] == ("ls-tree", "-r", "-z", "--full-tree"):
            switched = True
            _git(repo, "reset", "--hard", second)
        return original_git(repository, *args)

    monkeypatch.setattr(snapshot_module, "_git", racing_git)
    with pytest.raises(SnapshotError) as race:
        capture_git_snapshot(repo)
    assert switched
    assert race.value.code == "snapshot.capture_race"


def test_materialized_directory_modes_are_umask_independent(tmp_path: Path) -> None:
    repo = _repository(tmp_path / "source")
    (repo / "nested").mkdir()
    (repo / "nested" / "file.txt").write_bytes(b"content\n")
    _commit(repo)
    snapshot = capture_git_snapshot(repo)
    workspace = tmp_path / "workspace"

    previous_umask = os.umask(0o077)
    try:
        materialize_snapshot(snapshot, workspace)
    finally:
        os.umask(previous_umask)

    assert stat_mode(workspace / "nested") == 0o755
    verify_materialized_snapshot(snapshot, workspace)


def test_capture_ignores_git_replacement_refs(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    tracked = repo / "value.txt"
    tracked.write_bytes(b"first\n")
    _commit(repo, "first")
    first_commit = _git(repo, "rev-parse", "HEAD").decode().strip()
    first_tree = _git(repo, "rev-parse", "HEAD^{tree}").decode().strip()

    tracked.write_bytes(b"replacement\n")
    _commit(repo, "replacement")
    replacement_commit = _git(repo, "rev-parse", "HEAD").decode().strip()
    _git(repo, "reset", "--hard", first_commit)
    _git(repo, "replace", first_commit, replacement_commit)

    captured = capture_git_snapshot(repo)

    assert captured.manifest["source"]["commit"] == first_commit
    assert captured.manifest["source"]["tree"] == first_tree
    assert captured.files == (
        {
            "path": "value.txt",
            "kind": "file",
            "mode": "100644",
            "size": "6",
            "identity": {"sha256": hashlib.sha256(b"first\n").hexdigest()},
        },
    )


def test_materialization_filesystem_failures_are_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repository(tmp_path / "source")
    (repo / "nested").mkdir()
    (repo / "nested" / "file.txt").write_bytes(b"content\n")
    _commit(repo)
    snapshot = capture_git_snapshot(repo)

    existing = tmp_path / "existing"
    existing.mkdir()
    original_iterdir = Path.iterdir

    def failing_iterdir(path: Path):
        if path == existing:
            raise PermissionError("injected workspace inspection failure")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", failing_iterdir)
    with pytest.raises(SnapshotError) as inspection:
        materialize_snapshot(snapshot, existing)
    assert inspection.value.code == "snapshot.workspace_inspection_failed"
    monkeypatch.setattr(Path, "iterdir", original_iterdir)

    workspace = tmp_path / "parent-failure"
    original_mkdir = Path.mkdir

    def failing_mkdir(
        path: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        if path == workspace / "nested":
            raise PermissionError("injected parent creation failure")
        original_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)

    monkeypatch.setattr(Path, "mkdir", failing_mkdir)
    with pytest.raises(SnapshotError) as materialization:
        materialize_snapshot(snapshot, workspace)
    assert materialization.value.code == "snapshot.materialization_failed"


@pytest.mark.skipif(os.name == "nt", reason="raw byte filenames are POSIX-specific")
def test_unrepresentable_workspace_filename_is_typed(tmp_path: Path) -> None:
    repo = _repository(tmp_path / "source")
    (repo / "file.txt").write_bytes(b"content\n")
    _commit(repo)
    snapshot = capture_git_snapshot(repo)
    workspace = tmp_path / "workspace"
    materialize_snapshot(snapshot, workspace)

    descriptor = os.open(
        os.fsencode(workspace) + b"/\xff",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o644,
    )
    os.close(descriptor)

    with pytest.raises(SnapshotError) as changed:
        verify_materialized_snapshot(snapshot, workspace)
    assert changed.value.code == "snapshot.materialization_changed"
