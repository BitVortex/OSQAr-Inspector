"""Deterministic closure and independent verification of finalized bundle payloads."""

from __future__ import annotations

import hashlib
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .configuration import canonical_json

SCHEMA = "osqar.inspector.bundle-manifest.v1"
_INDEX_PATH = "navigation/index.html"
_RUN_REPORT_PATH = "reports/run.json"
_RESERVED_PATHS = frozenset({"manifest.json", "checksums.sha256"})


@dataclass(frozen=True)
class BundleGenerationError(Exception):
    """Typed failure while closing a bundle candidate."""

    code: str
    message: str
    path: str | None = None


@dataclass(frozen=True)
class GeneratedBundle:
    """Exact control bytes and identity of an independently verified bundle."""

    root: Path
    bundle_id: str
    manifest_bytes: bytes
    checksums_bytes: bytes


class FinalizedCandidate(Protocol):
    """Shared boundary supplied by the build orchestrator."""

    @property
    def payloads(self) -> tuple[tuple[str, bytes], ...]: ...

    @property
    def candidate_ready(self) -> bool: ...


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise BundleGenerationError(
            "bundle.invalid_path", "payload path must be non-empty"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise BundleGenerationError(
            "bundle.invalid_path", "payload path must be valid UTF-8", value
        ) from error
    if (
        value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise BundleGenerationError(
            "bundle.invalid_path",
            "payload path does not satisfy the normalized path profile",
            value,
        )
    if value in _RESERVED_PATHS:
        raise BundleGenerationError(
            "bundle.reserved_path", "payload path is reserved for bundle closure", value
        )
    return value


def _closed_payloads(candidate: FinalizedCandidate) -> tuple[tuple[str, bytes], ...]:
    if candidate.candidate_ready is not True:
        raise BundleGenerationError(
            "bundle.candidate_not_ready",
            "required-stage policy did not produce a closable candidate",
        )
    try:
        supplied = candidate.payloads
    except AttributeError as error:
        raise BundleGenerationError(
            "bundle.invalid_candidate", "candidate does not expose finalized payloads"
        ) from error
    if not isinstance(supplied, tuple):
        raise BundleGenerationError(
            "bundle.invalid_candidate",
            "candidate payload inventory must be an immutable tuple",
        )

    payloads: list[tuple[str, bytes]] = []
    for item in supplied:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[1], bytes)
        ):
            raise BundleGenerationError(
                "bundle.invalid_payload",
                "each payload must be an exact (path, bytes) tuple",
            )
        payloads.append((_validate_path(item[0]), item[1]))

    paths = [path for path, _ in payloads]
    if len(paths) != len(set(paths)):
        raise BundleGenerationError(
            "bundle.path_collision", "payload paths must be unique"
        )
    reserved_ancestor = next(
        (
            reserved
            for path in paths
            for reserved in _RESERVED_PATHS
            if path.startswith(reserved + "/")
        ),
        None,
    )
    if reserved_ancestor is not None:
        raise BundleGenerationError(
            "bundle.path_collision",
            "a payload path collides with a reserved bundle control file",
            reserved_ancestor,
        )
    path_set = set(paths)
    for path in paths:
        components = path.split("/")
        for index in range(1, len(components)):
            ancestor = "/".join(components[:index])
            if ancestor in path_set:
                raise BundleGenerationError(
                    "bundle.path_collision",
                    "a payload path collides with another payload's directory",
                    ancestor,
                )
    for entry_point in (_INDEX_PATH, _RUN_REPORT_PATH):
        if entry_point not in path_set:
            raise BundleGenerationError(
                "bundle.missing_entry_point",
                "candidate omits a required bundle entry point",
                entry_point,
            )
    return tuple(sorted(payloads, key=lambda item: item[0].encode("utf-8")))


def _ensure_new_root(root: Path) -> None:
    try:
        root.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise BundleGenerationError(
            "bundle.destination_unavailable", "bundle destination cannot be inspected"
        ) from error
    else:
        raise BundleGenerationError(
            "bundle.destination_exists",
            "bundle destination must not already exist",
        )
    try:
        root.mkdir()
    except FileExistsError as error:
        raise BundleGenerationError(
            "bundle.destination_exists", "bundle destination was concurrently created"
        ) from error
    except OSError as error:
        raise BundleGenerationError(
            "bundle.destination_unavailable", "bundle destination cannot be created"
        ) from error
    try:
        info = root.lstat()
    except OSError as error:
        raise BundleGenerationError(
            "bundle.destination_unavailable", "bundle destination cannot be inspected"
        ) from error
    if not stat.S_ISDIR(info.st_mode):
        raise BundleGenerationError(
            "bundle.destination_invalid", "bundle destination is not a directory"
        )


def _write_payload(root: Path, path: str, content: bytes) -> None:
    """Write one prevalidated member exclusively beneath a newly created root."""

    destination = root.joinpath(*path.split("/"))
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write(content)
    except FileExistsError as error:
        raise BundleGenerationError(
            "bundle.path_collision", "bundle member already exists", path
        ) from error
    except OSError as error:
        raise BundleGenerationError(
            "bundle.write_failed", "bundle member could not be written", path
        ) from error


def _expected_bundle_id(manifest_bytes: bytes, checksums_bytes: bytes) -> str:
    identity = canonical_json(
        {
            "identity": {
                "checksums_sha256": _sha256(checksums_bytes),
                "manifest_sha256": _sha256(manifest_bytes),
            },
            "kind": "bundle",
        }
    )
    return f"bundle:sha256:{_sha256(identity)}"


def generate_bundle(
    candidate: FinalizedCandidate, destination: Path
) -> GeneratedBundle:
    """Close finalized payload bytes and accept only independent re-verification.

    This establishes exact inventory and digest consistency. It does not establish
    artifact authenticity, substantive adequacy, approval, or qualification.
    """

    payloads = _closed_payloads(candidate)
    root = Path(destination)
    _ensure_new_root(root)

    for path, content in payloads:
        _write_payload(root, path, content)

    entries = [
        {"path": path, "sha256": _sha256(content), "size": str(len(content))}
        for path, content in payloads
    ]
    manifest_bytes = canonical_json(
        {
            "entries": entries,
            "entry_points": {
                "index": _INDEX_PATH,
                "run_report": _RUN_REPORT_PATH,
            },
            "schema": SCHEMA,
        }
    )
    _write_payload(root, "manifest.json", manifest_bytes)

    checksum_members = [(path, _sha256(content)) for path, content in payloads] + [
        ("manifest.json", _sha256(manifest_bytes))
    ]
    checksums_bytes = b"".join(
        f"{digest}  {path}\n".encode()
        for path, digest in sorted(
            checksum_members, key=lambda item: item[0].encode("utf-8")
        )
    )
    _write_payload(root, "checksums.sha256", checksums_bytes)

    expected_id = _expected_bundle_id(manifest_bytes, checksums_bytes)
    from . import verify as independent_verifier

    try:
        verified_id = independent_verifier.verify_bundle(root)
    except independent_verifier.VerificationError as error:
        raise BundleGenerationError(
            "bundle.self_verification_failed",
            f"independent bundle verification failed: {error.code}",
            error.path,
        ) from error
    if not isinstance(verified_id, str) or not re.fullmatch(
        r"bundle:sha256:[0-9a-f]{64}", verified_id
    ):
        raise BundleGenerationError(
            "bundle.verification_mismatch",
            "independent verifier did not return a canonical bundle ID",
        )
    if verified_id != expected_id:
        raise BundleGenerationError(
            "bundle.verification_mismatch",
            "independent verifier returned a different bundle ID",
        )

    return GeneratedBundle(root, expected_id, manifest_bytes, checksums_bytes)
