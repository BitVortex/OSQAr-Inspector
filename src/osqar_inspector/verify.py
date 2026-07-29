"""Independent verification of the closed bundle contract."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import unicodedata
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import unquote_to_bytes, urlsplit

HEX = re.compile(r"[0-9a-f]{64}\Z")
SIZE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SCHEMA = "osqar.inspector.bundle-manifest.v1"
RUN_SCHEMA = "osqar.inspector.run.v1"
RUN_KEYS = {
    "artifact_counts",
    "claim_boundary",
    "configuration_identity",
    "diagnostics",
    "inspector",
    "optional_stages",
    "plan_sha256",
    "required_stage_decision",
    "schema",
    "snapshot_id",
    "stage_result_digests",
}
CLAIM_BOUNDARY = {
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
}
TOKEN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
KIND = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
VERSION = re.compile(r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*\Z")
POSITIVE_SIZE = re.compile(r"[1-9][0-9]*\Z")
SAFE_INTEGER = 9007199254740991
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


def _fail(code: str, message: str, path: str | None = None) -> NoReturn:
    raise VerificationError(code, message, path)


def _jcs_order(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _jcs_order(value[key])
            for key in sorted(value, key=lambda item: item.encode("utf-16-be"))
        }
    if isinstance(value, list):
        return [_jcs_order(item) for item in value]
    return value


def _canonical(
    value: Any,
    invalid_code: str = "manifest.invalid_json",
    invalid_message: str = "manifest contains unsupported JSON values",
) -> bytes:
    try:
        text = json.dumps(
            _jcs_order(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        _fail(invalid_code, invalid_message)


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


def _run_invalid() -> None:
    _fail("run_report.invalid_shape", "run report does not conform to osqar.inspector.run.v1")


def _run_object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _run_invalid()
    return value


def _safe_json(value: Any) -> bool:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return True
    if isinstance(value, int):
        return -SAFE_INTEGER <= value <= SAFE_INTEGER
    if isinstance(value, list):
        return all(_safe_json(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _safe_json(item) for key, item in value.items())
    return False


def _pointer_tokens(pointer: Any) -> tuple[str, ...]:
    if not isinstance(pointer, str) or not pointer.startswith("/") or pointer == "":
        _run_invalid()
    tokens: list[str] = []
    for encoded in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|\Z)", encoded):
            _run_invalid()
        decoded = encoded.replace("~1", "/").replace("~0", "~")
        canonical = decoded.replace("~", "~0").replace("/", "~1")
        if canonical != encoded:
            _run_invalid()
        tokens.append(decoded)
    return tuple(tokens)


def _validate_configuration_identity(value: Any) -> None:
    identity = _run_object(
        value, {"controlled_input", "defaults", "overrides", "resolved", "schema"}
    )
    controlled = _run_object(identity["controlled_input"], {"path", "sha256", "size"})
    _normalized_path(controlled["path"])
    if (
        not isinstance(controlled["sha256"], str)
        or not HEX.fullmatch(controlled["sha256"])
        or not isinstance(controlled["size"], str)
        or not SIZE.fullmatch(controlled["size"])
    ):
        _run_invalid()
    defaults = _run_object(identity["defaults"], {"id", "sha256"})
    schema = _run_object(identity["schema"], {"id", "sha256"})
    resolved = _run_object(identity["resolved"], {"sha256"})
    if (
        not isinstance(defaults["id"], str)
        or not defaults["id"]
        or not isinstance(defaults["sha256"], str)
        or not HEX.fullmatch(defaults["sha256"])
        or schema["id"] != "osqar.inspector.config.v1"
        or not isinstance(schema["sha256"], str)
        or not HEX.fullmatch(schema["sha256"])
        or not isinstance(resolved["sha256"], str)
        or not HEX.fullmatch(resolved["sha256"])
    ):
        _run_invalid()
    overrides = identity["overrides"]
    if not isinstance(overrides, list):
        _run_invalid()
    pointers: list[str] = []
    decoded: list[tuple[str, ...]] = []
    for value in overrides:
        record = _run_object(value, {"pointer", "value"})
        decoded.append(_pointer_tokens(record["pointer"]))
        pointers.append(record["pointer"])
        if not _safe_json(record["value"]):
            _run_invalid()
    if pointers != sorted(pointers, key=str.encode) or len(pointers) != len(set(pointers)):
        _run_invalid()
    for index, left in enumerate(decoded):
        for right in decoded[index + 1 :]:
            if left[: len(right)] == right or right[: len(left)] == left:
                _run_invalid()


def _validate_run_semantics(report: dict[str, Any]) -> None:
    if report["claim_boundary"] != CLAIM_BOUNDARY:
        _run_invalid()
    _validate_configuration_identity(report["configuration_identity"])

    counts = report["artifact_counts"]
    if not isinstance(counts, list):
        _run_invalid()
    kinds: list[str] = []
    for value in counts:
        record = _run_object(value, {"count", "kind"})
        if (
            not isinstance(record["count"], str)
            or not POSITIVE_SIZE.fullmatch(record["count"])
            or not isinstance(record["kind"], str)
            or not KIND.fullmatch(record["kind"])
        ):
            _run_invalid()
        kinds.append(record["kind"])
    if kinds != sorted(kinds, key=str.encode) or len(kinds) != len(set(kinds)):
        _run_invalid()

    optional = _run_object(report["optional_stages"], {"degraded", "skipped"})
    stage_sets: list[set[str]] = []
    for name in ("degraded", "skipped"):
        values = optional[name]
        if (
            not isinstance(values, list)
            or any(not isinstance(item, str) or not TOKEN.fullmatch(item) for item in values)
            or values != sorted(values, key=str.encode)
            or len(values) != len(set(values))
        ):
            _run_invalid()
        stage_sets.append(set(values))
    if stage_sets[0] & stage_sets[1]:
        _run_invalid()

    diagnostics = report["diagnostics"]
    if not isinstance(diagnostics, list):
        _run_invalid()
    for value in diagnostics:
        diagnostic = _run_object(value, {"code", "message", "path", "severity"})
        path = diagnostic["path"]
        if (
            not isinstance(diagnostic["code"], str)
            or not TOKEN.fullmatch(diagnostic["code"])
            or not isinstance(diagnostic["message"], str)
            or not diagnostic["message"]
            or any(unicodedata.category(char) == "Cc" for char in diagnostic["message"])
            or not isinstance(diagnostic["severity"], str)
            or diagnostic["severity"] not in {"info", "warning", "error"}
        ):
            _run_invalid()
        if path is not None:
            _normalized_path(path)

    inspector = _run_object(report["inspector"], {"version"})
    if not isinstance(inspector["version"], str) or not VERSION.fullmatch(inspector["version"]):
        _run_invalid()
    digests = report["stage_result_digests"]
    if (
        not isinstance(digests, list)
        or any(not isinstance(item, str) or not HEX.fullmatch(item) for item in digests)
        or len(digests) != len(set(digests))
        or not isinstance(report["plan_sha256"], str)
        or not HEX.fullmatch(report["plan_sha256"])
        or not isinstance(report["snapshot_id"], str)
        or not re.fullmatch(r"snapshot:sha256:[0-9a-f]{64}", report["snapshot_id"])
        or not isinstance(report["required_stage_decision"], str)
        or report["required_stage_decision"] not in {"satisfied", "blocked"}
    ):
        _run_invalid()


def _validate_run_report(content: bytes) -> None:
    def run_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("run_report.duplicate_member", f"duplicate JSON member: {key}")
            result[key] = value
        return result

    try:
        report = json.loads(content.decode("utf-8"), object_pairs_hook=run_object)
    except VerificationError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail("run_report.invalid_json", "run report must be valid UTF-8 JSON")
    if (
        _canonical(
            report,
            "run_report.invalid_json",
            "run report contains unsupported JSON values",
        )
        != content
    ):
        _fail("run_report.noncanonical", "run-report bytes are not canonical JSON")
    if not isinstance(report, dict) or report.get("schema") != RUN_SCHEMA:
        _fail("run_report.unsupported_schema", "unsupported run-report schema")
    if set(report) != RUN_KEYS:
        _fail("run_report.invalid_shape", "run report has missing or unknown members")
    _validate_run_semantics(report)


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


def _validate_payload_bytes(
    relative: str, content: bytes, expected_digest: str, expected_size: str
) -> None:
    if str(len(content)) != expected_size:
        _fail("payload.size_mismatch", "payload size does not match manifest", relative)
    if _sha256(content) != expected_digest:
        _fail("payload.hash_mismatch", "payload hash does not match manifest", relative)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []
        self.anchors: list[str] = []
        self.has_base_href = False
        self.has_srcset = False

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        for name, value in attrs:
            if tag == "base" and name == "href":
                self.has_base_href = True
            if name == "srcset":
                self.has_srcset = True
            is_reference = (
                name in {"href", "src"}
                or (tag == "object" and name == "data")
                or (tag == "video" and name == "poster")
            )
            if is_reference and value is not None:
                self.references.append(value)
            if name == "id" and value is not None:
                self.anchors.append(value)
            if tag == "a" and name == "name" and value is not None:
                self.anchors.append(value)


def _validate_links(
    root: Path, paths: set[str], expectations: dict[str, tuple[str, str]]
) -> None:
    documents: dict[str, _LinkParser] = {}
    for source in sorted((path for path in paths if path.endswith(".html")), key=str.encode):
        parser = _LinkParser()
        content = _read_regular(root, source)
        _validate_payload_bytes(source, content, *expectations[source])
        try:
            html = content.decode("utf-8")
        except UnicodeDecodeError:
            _fail(
                "link.invalid_html_utf8",
                "HTML payload must be valid UTF-8",
                source,
            )
        parser.feed(html)
        if parser.has_base_href:
            _fail(
                "link.unsupported_base",
                "base href is unsupported in bundle HTML",
                source,
            )
        if parser.has_srcset:
            _fail(
                "link.unsupported_srcset",
                "srcset is unsupported in bundle HTML",
                source,
            )
        if any(count > 1 for count in Counter(parser.anchors).values()):
            _fail(
                "link.ambiguous_fragment",
                "HTML payload contains a duplicate anchor identity",
                source,
            )
        documents[source] = parser

    for source, parser in documents.items():
        for reference in parser.references:
            try:
                components = urlsplit(reference)
            except ValueError:
                _fail(
                    "link.invalid_reference",
                    "HTML reference is not a valid URI reference",
                    source,
                )
            if components.scheme or components.netloc:
                continue
            if re.search(r"%(?![0-9A-Fa-f]{2})", reference):
                _fail(
                    "link.malformed_percent",
                    "internal link contains a malformed percent escape",
                    source,
                )
            try:
                decoded_path = unquote_to_bytes(components.path).decode("utf-8")
                unquote_to_bytes(components.query).decode("utf-8")
            except UnicodeDecodeError:
                _fail(
                    "link.invalid_percent_utf8",
                    "internal link percent escapes do not decode as UTF-8",
                    source,
                )
            resolved_reference = (
                f"{decoded_path}index.html"
                if decoded_path.endswith("/")
                else decoded_path
            )
            if not decoded_path:
                target = source
            elif decoded_path.startswith("/"):
                target = posixpath.normpath(resolved_reference.removeprefix("/"))
            else:
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(source), resolved_reference)
                )
            if target == ".." or target.startswith("../"):
                _fail(
                    "link.root_escape",
                    "internal link escapes the bundle root",
                    source,
                )
            _normalized_path(target)
            if target not in paths:
                _fail("link.missing_target", "internal link target is not a payload", target)
            if components.fragment:
                if target not in documents:
                    _fail(
                        "link.non_html_fragment",
                        "fragment target is not an HTML payload",
                        target,
                    )
                try:
                    fragment = unquote_to_bytes(components.fragment).decode("utf-8")
                except UnicodeDecodeError:
                    _fail(
                        "link.invalid_percent_utf8",
                        "internal link percent escapes do not decode as UTF-8",
                        source,
                    )
                if fragment not in documents[target].anchors:
                    _fail(
                        "link.missing_fragment",
                        "HTML fragment does not name an anchor",
                        target,
                    )


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
    expectations = {path: (digest, size) for path, digest, size in entries}
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

    run_report_path = points["run_report"]
    run_report_bytes = _read_regular(root, run_report_path)
    _validate_payload_bytes(run_report_path, run_report_bytes, *expectations[run_report_path])
    _validate_run_report(run_report_bytes)
    _validate_links(root, set(paths), expectations)

    if _read_regular(root, "manifest.json") != manifest_bytes:
        _fail(
            "manifest.changed",
            "manifest.json changed during bundle verification",
            "manifest.json",
        )
    if _read_regular(root, "checksums.sha256") != checksum_bytes:
        _fail(
            "checksums.changed",
            "checksums.sha256 changed during bundle verification",
            "checksums.sha256",
        )

    for path, digest, size in entries:
        final_size, final_digest = _hash_regular(root, path)
        if str(final_size) != size:
            _fail("payload.size_mismatch", "payload size does not match manifest", path)
        if final_digest != digest:
            _fail("payload.hash_mismatch", "payload hash does not match manifest", path)

    final_files, final_directories = _inventory(root)
    final_missing = sorted(expected_files - final_files, key=str.encode)
    if final_missing:
        _fail(
            "inventory.missing_file",
            "expected bundle file disappeared during verification",
            final_missing[0],
        )
    final_extra = sorted(final_files - expected_files, key=str.encode)
    if final_extra:
        _fail(
            "inventory.extra_file",
            "unlisted bundle file appeared during verification",
            final_extra[0],
        )
    final_additional = sorted(final_directories - implicit_directories, key=str.encode)
    if final_additional:
        _fail(
            "inventory.extra_directory",
            "empty or additional directory appeared during verification",
            final_additional[0],
        )
    identity = {
        "identity": {
            "checksums_sha256": _sha256(checksum_bytes),
            "manifest_sha256": _sha256(manifest_bytes),
        },
        "kind": "bundle",
    }
    return f"bundle:sha256:{_sha256(_canonical(identity))}"
