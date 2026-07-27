from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

from osqar_inspector import verify
from osqar_inspector.verify import VerificationError


FIXTURES = Path(__file__).parent / "fixtures"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def make_bundle(root: Path) -> str:
    payloads = {
        "index.html": b"<h1>Inspection</h1>\n",
        "reports/run.json": b'{"status":"succeeded"}',
    }
    for name, content in payloads.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    manifest = canonical(
        {
            "entries": [
                {
                    "path": name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": str(len(content)),
                }
                for name, content in sorted(payloads.items())
            ],
            "entry_points": {
                "index": "index.html",
                "run_report": "reports/run.json",
            },
            "schema": "osqar.inspector.bundle-manifest.v1",
        }
    )
    (root / "manifest.json").write_bytes(manifest)
    checksums = b"".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n".encode()
        for name, content in sorted({**payloads, "manifest.json": manifest}.items())
    )
    (root / "checksums.sha256").write_bytes(checksums)
    identity = canonical(
        {
            "identity": {
                "checksums_sha256": hashlib.sha256(checksums).hexdigest(),
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            },
            "kind": "bundle",
        }
    )
    return f"bundle:sha256:{hashlib.sha256(identity).hexdigest()}"


def run_verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "osqar_inspector.cli", "verify", "--bundle", str(bundle)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_valid_bundle(tmp_path: Path) -> None:
    bundle_id = make_bundle(tmp_path)
    result = run_verify(tmp_path)
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"bundle_id": bundle_id, "valid": True}


def test_altered_payload_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "index.html").write_bytes(b"altered")
    result = run_verify(tmp_path)
    assert result.returncode != 0
    assert result.stdout == ""
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "payload.size_mismatch"


def assert_failure(bundle: Path, code: str) -> None:
    result = run_verify(bundle)
    assert result.returncode != 0
    assert result.stdout == ""
    output = json.loads(result.stderr)
    assert output["valid"] is False
    assert output["diagnostics"][0]["code"] == code


def test_extra_file_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "extra.txt").write_text("extra")
    assert_failure(tmp_path, "inventory.extra_file")


def test_missing_payload_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "index.html").unlink()
    assert_failure(tmp_path, "inventory.missing_file")


def test_malformed_manifest_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"{")
    assert_failure(tmp_path, "manifest.invalid_json")


def test_oversized_integer_manifest_fails_with_typed_cli_json(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"9" * 5000)

    result = run_verify(tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "manifest.invalid_json"


def test_canonical_recursion_error_is_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)

    def fail_dumps(*args: object, **kwargs: object) -> str:
        raise RecursionError("deterministic recursion failure")

    monkeypatch.setattr(verify.json, "dumps", fail_dumps)

    with pytest.raises(VerificationError) as caught:
        verify.verify_bundle(tmp_path)

    assert caught.value.diagnostic()["code"] == "manifest.invalid_json"


def test_huge_manifest_size_fails_with_typed_cli_json(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(
        tmp_path,
        lambda value: value["entries"][0].update({"size": "9" * 5000}),
    )

    result = run_verify(tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "payload.size_mismatch"


def test_deep_manifest_json_fails_with_typed_cli_json(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"[" * 10_000 + b"]" * 10_000)

    result = run_verify(tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "manifest.invalid_json"


def test_unreadable_directory_entry_stat_has_typed_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UnreadableEntry:
        name = "blocked.txt"
        path = str(tmp_path / name)

        def stat(self, *, follow_symlinks: bool) -> object:
            assert follow_symlinks is False
            raise OSError("deterministic stat failure")

    monkeypatch.setattr(verify.os, "scandir", lambda directory: [UnreadableEntry()])

    with pytest.raises(VerificationError) as caught:
        verify._inventory(tmp_path)

    assert caught.value.diagnostic() == {
        "code": "inventory.unreadable_entry",
        "message": "bundle directory entry cannot be inspected",
        "path": "blocked.txt",
    }


def test_checksum_mismatch_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    checksum_path = tmp_path / "checksums.sha256"
    checksum_path.write_bytes(b"0" + checksum_path.read_bytes()[1:])
    assert_failure(tmp_path, "checksums.noncanonical")


def test_path_escape_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["entries"][0]["path"] = "../escape"
    manifest_path.write_bytes(canonical(manifest))
    assert_failure(tmp_path, "path.invalid")


def test_symlink_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "index.html").unlink()
    (tmp_path / "index.html").symlink_to("reports/run.json")
    assert_failure(tmp_path, "inventory.forbidden_object")


def test_empty_directory_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "empty").mkdir()
    assert_failure(tmp_path, "inventory.extra_directory")


def rewrite_manifest(bundle: Path, change: Callable[[dict[str, Any]], None]) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    change(manifest)
    manifest_path.write_bytes(canonical(manifest))


def test_same_size_payload_hash_mismatch_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    payload = tmp_path / "index.html"
    payload.write_bytes(b"x" * len(payload.read_bytes()))
    assert_failure(tmp_path, "payload.hash_mismatch")


def test_payload_verification_only_byte_reads_identity_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)
    original = verify._read_regular
    reads: list[str] = []

    def track_read(root: Path, relative: str) -> bytes:
        reads.append(relative)
        return original(root, relative)

    monkeypatch.setattr(verify, "_read_regular", track_read)

    verify.verify_bundle(tmp_path)

    assert reads == ["manifest.json", "checksums.sha256"]


def test_payload_hashing_reads_in_bounded_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)
    original_open = Path.open
    payload_read_sizes: list[int] = []

    class TrackedFile:
        def __init__(self, handle: object) -> None:
            self.handle = handle

        def __enter__(self) -> "TrackedFile":
            self.handle.__enter__()
            return self

        def __exit__(self, *args: object) -> object:
            return self.handle.__exit__(*args)

        def read(self, size: int = -1) -> bytes:
            payload_read_sizes.append(size)
            return self.handle.read(size)

    def track_open(path: Path, *args: object, **kwargs: object) -> object:
        handle = original_open(path, *args, **kwargs)
        if path.name == "index.html":
            return TrackedFile(handle)
        return handle

    monkeypatch.setattr(Path, "open", track_open)

    verify.verify_bundle(tmp_path)

    assert payload_read_sizes
    assert all(0 < size <= 1024 * 1024 for size in payload_read_sizes)


def test_duplicate_manifest_member_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    manifest = (tmp_path / "manifest.json").read_bytes()
    (tmp_path / "manifest.json").write_bytes(
        manifest[:-1] + b',"schema":"osqar.inspector.bundle-manifest.v1"}'
    )
    assert_failure(tmp_path, "manifest.duplicate_member")


def test_noncanonical_manifest_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    value = json.loads(manifest_path.read_bytes())
    manifest_path.write_text(json.dumps(value, indent=2))
    assert_failure(tmp_path, "manifest.noncanonical")


def test_unknown_manifest_member_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(tmp_path, lambda value: value.update({"unknown": "value"}))
    assert_failure(tmp_path, "manifest.invalid_shape")


def test_unsorted_entries_fail(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(tmp_path, lambda value: value["entries"].reverse())
    assert_failure(tmp_path, "manifest.unsorted_entries")


def test_duplicate_entries_fail(tmp_path: Path) -> None:
    make_bundle(tmp_path)

    def duplicate(value: dict[str, object]) -> None:
        entries = value["entries"]
        assert isinstance(entries, list)
        entries.insert(0, entries[0])

    rewrite_manifest(tmp_path, duplicate)
    assert_failure(tmp_path, "manifest.duplicate_entry")


def test_invalid_entry_point_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(
        tmp_path,
        lambda value: value["entry_points"].update({"index": "missing.html"}),
    )
    assert_failure(tmp_path, "manifest.invalid_entry_points")


def test_static_unicode_interoperability_fixture() -> None:
    bundle = FIXTURES / "valid-unicode-bundle"
    assert (bundle / "manifest.json").read_bytes() == (
        '{"entries":[{"path":"café.txt","sha256":'
        '"4ca8f61495094240e190464c3321ad29a653a2b5f84e17a88f8cb001f5c53201",'
        '"size":"16"},{"path":"index.html","sha256":'
        '"11eba706ac3521b05f03e7879c573bf80ad595e1410f5f69d4abb764b79058d1",'
        '"size":"30"}],"entry_points":{"index":"index.html","run_report":"café.txt"},'
        '"schema":"osqar.inspector.bundle-manifest.v1"}'
    ).encode("utf-8")
    assert (bundle / "checksums.sha256").read_bytes() == (
        "4ca8f61495094240e190464c3321ad29a653a2b5f84e17a88f8cb001f5c53201  café.txt\n"
        "11eba706ac3521b05f03e7879c573bf80ad595e1410f5f69d4abb764b79058d1  index.html\n"
        "48804eb057dc5ed339357b1cd06af0010cffa79e50d836499c179615039b365d  manifest.json\n"
    ).encode("utf-8")

    result = run_verify(bundle)

    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "bundle_id": "bundle:sha256:5ad62a553dda53987ddf7a4de07121823d7990dad3a06c9eb6a7925a34e60ba6",
        "valid": True,
    }
