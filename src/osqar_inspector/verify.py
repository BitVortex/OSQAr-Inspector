"""Independent verification of the closed bundle contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HEX = re.compile(r"[0-9a-f]{64}\Z")
SIZE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SCHEMA = "osqar.inspector.bundle-manifest.v1"
HASH_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class VerificationError(Exception):
    code: str
    message: str
    path: str | None = None

    def diagnostic(self) -> dict[str, str]:
        result = {"code": self.code, "message": self.message}
        if self.path is not None:
            result["path"] = self.path
        return result


def _fail(code: str, message: str, path: str | None = None) -> None:
    raise VerificationError(code, message, path)


def _canonical(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        _fail("manifest.invalid_json", "manifest contains unsupported JSON values")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("manifest.duplicate_member", f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _normalized_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail("path.invalid", "path must be a non-empty string")
    if (
        value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(segment in ("", ".", "..") for segment in value.split("/"))
    ):
        _fail("path.invalid", "path does not satisfy the normalized path profile", value)
    return value


def _exact_keys(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code, f"object must contain exactly: {', '.join(sorted(keys))}")
    return value


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_regular(root: Path, relative: str) -> bytes:
    path = root.joinpath(*relative.split("/"))
    try:
        info = path.lstat()
    except OSError:
        _fail("inventory.missing_file", "listed file is missing", relative)
    if not stat.S_ISREG(info.st_mode):
        _fail("inventory.forbidden_object", "bundle members must be regular files", relative)
    try:
        return path.read_bytes()
    except OSError:
        _fail("inventory.unreadable_file", "bundle member cannot be read", relative)


def _hash_regular(root: Path, relative: str) -> tuple[int, str]:
    path = root.joinpath(*relative.split("/"))
    try:
        info = path.lstat()
    except OSError:
        _fail("inventory.missing_file", "listed file is missing", relative)
    if not stat.S_ISREG(info.st_mode):
        _fail("inventory.forbidden_object", "bundle members must be regular files", relative)

    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as payload:
            while chunk := payload.read(HASH_CHUNK_SIZE):
                size += len(chunk)
                digest.update(chunk)
    except OSError:
        _fail("inventory.unreadable_file", "bundle member cannot be read", relative)
    return size, digest.hexdigest()


def _inventory(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError:
            _fail("bundle.unreadable", "bundle directory cannot be read", prefix or None)
        for child in children:
            relative = f"{prefix}/{child.name}" if prefix else child.name
            try:
                relative.encode("utf-8")
            except UnicodeEncodeError:
                _fail("path.invalid", "filesystem path is not valid UTF-8", relative)
            _normalized_path(relative)
            try:
                info = child.stat(follow_symlinks=False)
            except OSError:
                _fail(
                    "inventory.unreadable_entry",
                    "bundle directory entry cannot be inspected",
                    relative,
                )
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
                stack.append((Path(child.path), relative))
            elif stat.S_ISREG(info.st_mode):
                files.add(relative)
            else:
                _fail("inventory.forbidden_object", "symlinks and non-regular objects are forbidden", relative)
    return files, directories


def verify_bundle(root: Path) -> str:
    try:
        root_info = root.lstat()
    except OSError:
        _fail("bundle.not_found", "bundle path does not exist")
    if not stat.S_ISDIR(root_info.st_mode):
        _fail("bundle.not_directory", "bundle path must be a directory")

    files, directories = _inventory(root)
    manifest_bytes = _read_regular(root, "manifest.json")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_object)
    except VerificationError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail("manifest.invalid_json", "manifest must be valid UTF-8 JSON")
    if _canonical(manifest) != manifest_bytes:
        _fail("manifest.noncanonical", "manifest bytes are not canonical JSON")

    manifest = _exact_keys(
        manifest, {"entries", "entry_points", "schema"}, "manifest.invalid_shape"
    )
    if manifest["schema"] != SCHEMA:
        _fail("manifest.unsupported_schema", "unsupported bundle manifest schema")
    entries_value = manifest["entries"]
    if not isinstance(entries_value, list):
        _fail("manifest.invalid_shape", "entries must be an array")

    entries: list[tuple[str, str, str]] = []
    for value in entries_value:
        entry = _exact_keys(value, {"path", "sha256", "size"}, "manifest.invalid_entry")
        path = _normalized_path(entry["path"])
        digest, size = entry["sha256"], entry["size"]
        if not isinstance(digest, str) or not HEX.fullmatch(digest):
            _fail("manifest.invalid_entry", "entry sha256 must be lowercase hexadecimal", path)
        if not isinstance(size, str) or not SIZE.fullmatch(size):
            _fail("manifest.invalid_entry", "entry size must be canonical decimal", path)
        if path in ("manifest.json", "checksums.sha256"):
            _fail("manifest.reserved_path", "reserved files cannot be payload entries", path)
        entries.append((path, digest, size))
    paths = [entry[0] for entry in entries]
    if paths != sorted(paths, key=lambda path: path.encode("utf-8")):
        _fail("manifest.unsorted_entries", "entries are not sorted by path bytes")
    if len(paths) != len(set(paths)):
        _fail("manifest.duplicate_entry", "payload paths must be unique")

    points = _exact_keys(
        manifest["entry_points"], {"index", "run_report"}, "manifest.invalid_entry_points"
    )
    for name in ("index", "run_report"):
        target = _normalized_path(points[name])
        if target not in set(paths):
            _fail("manifest.invalid_entry_points", f"{name} does not name a payload", target)

    expected_files = set(paths) | {"manifest.json", "checksums.sha256"}
    missing = sorted(expected_files - files, key=str.encode)
    if missing:
        _fail("inventory.missing_file", "expected bundle file is missing", missing[0])
    extra = sorted(files - expected_files, key=str.encode)
    if extra:
        _fail("inventory.extra_file", "unlisted bundle file exists", extra[0])
    implicit_directories = {
        "/".join(path.split("/")[:index])
        for path in expected_files
        for index in range(1, len(path.split("/")))
    }
    additional = sorted(directories - implicit_directories, key=str.encode)
    if additional:
        _fail("inventory.extra_directory", "empty or additional directory exists", additional[0])

    payload_digests: dict[str, str] = {}
    for path, digest, size in entries:
        actual_size, actual_digest = _hash_regular(root, path)
        payload_digests[path] = actual_digest
        if str(actual_size) != size:
            _fail("payload.size_mismatch", "payload size does not match manifest", path)
        if actual_digest != digest:
            _fail("payload.hash_mismatch", "payload hash does not match manifest", path)

    checksum_bytes = _read_regular(root, "checksums.sha256")
    checksum_members = {**payload_digests, "manifest.json": _sha256(manifest_bytes)}
    expected_checksums = b"".join(
        f"{digest}  {path}\n".encode("utf-8")
        for path, digest in sorted(checksum_members.items(), key=lambda item: item[0].encode())
    )
    if checksum_bytes != expected_checksums:
        _fail("checksums.noncanonical", "checksums.sha256 bytes do not match the canonical records")

    identity = {
        "identity": {
            "checksums_sha256": _sha256(checksum_bytes),
            "manifest_sha256": _sha256(manifest_bytes),
        },
        "kind": "bundle",
    }
    return f"bundle:sha256:{_sha256(_canonical(identity))}"
