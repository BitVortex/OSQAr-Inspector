"""Strict deterministic resolution for ``osqar.inspector.config.v1``."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, NoReturn

SCHEMA_ID = "osqar.inspector.config.v1"
DEFAULTS_ID = "builtin-v1"
SAFE_INTEGER = 9007199254740991
NAMESPACE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")


@dataclass
class ConfigurationError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ResolvedConfiguration:
    value: dict[str, Any]
    canonical: bytes
    identity: dict[str, Any]
    identity_bytes: bytes
    defaults: dict[str, Any]
    defaults_bytes: bytes
    schema_bytes: bytes
    controlled_bytes: bytes
    controlled_path: str


def _fail(code: str, message: str) -> NoReturn:
    raise ConfigurationError(code, message)


def _reject_float(token: str) -> NoReturn:
    _fail("configuration.invalid_number", f"v1 forbids number token {token!r}")


def _parse_integer(token: str) -> int:
    if token == "-0" or not re.fullmatch(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)", token):
        _fail("configuration.invalid_number", f"invalid v1 integer token {token!r}")
    try:
        value = int(token)
    except (ValueError, RecursionError):
        _fail("configuration.invalid_number", "integer token cannot be represented")
    if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
        _fail("configuration.invalid_number", "integer is outside the v1 safe range")
    return value


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("configuration.duplicate_member", f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _valid_unicode(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            _fail("configuration.invalid_unicode", "unpaired Unicode surrogate")
    elif isinstance(value, list):
        for item in value:
            _valid_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _valid_unicode(key)
            _valid_unicode(item)


def parse_json(content: bytes, *, require_object: bool = True) -> Any:
    """Parse the strict UTF-8 and integer-only JSON profile used by config v1."""
    if content.startswith(b"\xef\xbb\xbf"):
        _fail("configuration.bom", "UTF-8 byte-order marks are forbidden")
    try:
        text = content.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except ConfigurationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _fail("configuration.invalid_json", "input must be one complete UTF-8 JSON value")
    try:
        _valid_unicode(value)
    except RecursionError:
        _fail("configuration.invalid_json", "JSON nesting exceeds the supported limit")
    if require_object and not isinstance(value, dict):
        _fail("configuration.non_object", "top-level configuration must be an object")
    return value


def _safe_value(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
            _fail("configuration.invalid_number", "integer is outside the v1 safe range")
        return
    if isinstance(value, float):
        _fail("configuration.invalid_number", "v1 permits integer numbers only")
    if isinstance(value, str):
        _valid_unicode(value)
        return
    if isinstance(value, list):
        for item in value:
            _safe_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("configuration.invalid_value", "object member names must be strings")
            _valid_unicode(key)
            _safe_value(item)
        return
    _fail("configuration.invalid_value", "value is not representable as JSON")


def _ordered(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _ordered(value[key])
            for key in sorted(value, key=lambda item: item.encode("utf-16-be"))
        }
    if isinstance(value, list):
        return [_ordered(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    """Return RFC 8785 bytes for the v1 JSON subset (safe integers, no floats)."""
    try:
        _safe_value(value)
        return json.dumps(
            _ordered(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        _fail("configuration.invalid_value", "value cannot be canonicalized")


def _merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        result = copy.deepcopy(base)
        for key, value in overlay.items():
            result[key] = _merge(result[key], value) if key in result else copy.deepcopy(value)
        return result
    return copy.deepcopy(overlay)


def _pointer_tokens(pointer: Any) -> tuple[str, ...]:
    if not isinstance(pointer, str) or not pointer or not pointer.startswith("/"):
        _fail("configuration.invalid_pointer", "override pointer must be non-empty")
    tokens: list[str] = []
    for encoded in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|\Z)", encoded):
            _fail("configuration.invalid_pointer", "malformed JSON Pointer escape")
        decoded = encoded.replace("~1", "/").replace("~0", "~")
        if decoded.replace("~", "~0").replace("/", "~1") != encoded:
            _fail("configuration.invalid_pointer", "JSON Pointer is not canonical")
        tokens.append(decoded)
    return tuple(tokens)


def _overrides(records: Any) -> list[tuple[str, tuple[str, ...], Any]]:
    if records is None:
        records = []
    if not isinstance(records, list):
        _fail("configuration.invalid_override", "overrides must be an array")
    result: list[tuple[str, tuple[str, ...], Any]] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"pointer", "value"}:
            _fail("configuration.invalid_override", "override records are closed")
        _safe_value(record["value"])
        result.append((record["pointer"], _pointer_tokens(record["pointer"]), record["value"]))
    result.sort(key=lambda item: item[0].encode("utf-8"))
    for index, (_, left, _) in enumerate(result):
        for _, right, _ in result[index + 1 :]:
            if left == right:
                _fail("configuration.duplicate_pointer", "duplicate override pointer")
            if left[: len(right)] == right or right[: len(left)] == left:
                _fail("configuration.overlapping_pointer", "override pointers overlap")
    return result


def _apply(value: dict[str, Any], overrides: list[tuple[str, tuple[str, ...], Any]]) -> None:
    for _, tokens, replacement in overrides:
        parent: Any = value
        for token in tokens[:-1]:
            if not isinstance(parent, dict) or token not in parent:
                _fail("configuration.invalid_pointer_target", "override parent does not exist")
            parent = parent[token]
            if not isinstance(parent, dict):
                _fail("configuration.invalid_pointer_target", "override traverses a non-object")
        if not isinstance(parent, dict):
            _fail("configuration.invalid_pointer_target", "override parent is not an object")
        parent[tokens[-1]] = copy.deepcopy(replacement)


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail("configuration.invalid_path", "configured path must be a non-empty string")
    if (
        value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _fail("configuration.invalid_path", f"path does not satisfy profile: {value!r}")
    return value


def _closed(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("configuration.invalid_schema", f"{name} must contain exactly {sorted(keys)}")
    return value


def _boolean(value: Any) -> None:
    if not isinstance(value, bool):
        _fail("configuration.invalid_schema", "expected boolean")


def _validate(value: Any) -> dict[str, Any]:
    top = _closed(
        value,
        {"schema", "project", "publication", "stages", "doxygen", "coverage", "extensions"},
        "configuration",
    )
    if top["schema"] != SCHEMA_ID:
        _fail("configuration.unsupported_schema", f"schema must be {SCHEMA_ID}")
    project = _closed(top["project"], {"include", "exclude", "require_clean_git"}, "project")
    for name in ("include", "exclude"):
        paths = project[name]
        if not isinstance(paths, list):
            _fail("configuration.invalid_schema", f"project.{name} must be an array")
        checked = [_path(item) for item in paths]
        if len(checked) != len(set(checked)):
            _fail("configuration.invalid_path", f"project.{name} contains duplicate paths")
    _boolean(project["require_clean_git"])
    publication = _closed(
        top["publication"], {"destination", "reproducible"}, "publication"
    )
    _path(publication["destination"])
    _boolean(publication["reproducible"])
    stages = _closed(top["stages"], {"doxygen", "coverage"}, "stages")
    for name in ("doxygen", "coverage"):
        stage = _closed(stages[name], {"enabled", "required"}, f"stages.{name}")
        _boolean(stage["enabled"])
        _boolean(stage["required"])
    doxygen = _closed(
        top["doxygen"], {"configuration", "output", "warnings_as_errors"}, "doxygen"
    )
    _path(doxygen["configuration"])
    _path(doxygen["output"])
    _boolean(doxygen["warnings_as_errors"])
    coverage = _closed(top["coverage"], {"report", "mapping", "attestation"}, "coverage")
    for name in ("report", "mapping", "attestation"):
        if coverage[name] is not None:
            _path(coverage[name])
    extensions = top["extensions"]
    if not isinstance(extensions, dict):
        _fail("configuration.invalid_schema", "extensions must be an object")
    for namespace, extension in extensions.items():
        if not NAMESPACE.fullmatch(namespace) or not isinstance(extension, dict):
            _fail("configuration.invalid_schema", "extensions require dotted namespaces and objects")
        _safe_value(extension)
    return top


def _resource(name: str) -> bytes:
    return files("osqar_inspector").joinpath("resources", name).read_bytes()


def _resolve_configuration(
    controlled_bytes: bytes,
    controlled_path: str,
    overrides: list[dict[str, Any]] | None = None,
) -> ResolvedConfiguration:
    _path(controlled_path)
    defaults_bytes = _resource("defaults-v1.json")
    schema_bytes = _resource("config-v1.schema.json")
    defaults = parse_json(defaults_bytes)
    controlled = parse_json(controlled_bytes)
    accepted = _overrides(overrides)
    merged = _merge(defaults, controlled)
    _apply(merged, accepted)
    resolved = _validate(merged)
    canonical = canonical_json(resolved)
    override_identity = [
        {"pointer": pointer, "value": copy.deepcopy(value)}
        for pointer, _, value in accepted
    ]
    digest = lambda content: hashlib.sha256(content).hexdigest()
    identity = {
        "controlled_input": {
            "path": controlled_path,
            "sha256": digest(controlled_bytes),
            "size": str(len(controlled_bytes)),
        },
        "defaults": {"id": DEFAULTS_ID, "sha256": digest(canonical_json(defaults))},
        "overrides": override_identity,
        "resolved": {"sha256": digest(canonical)},
        "schema": {"id": SCHEMA_ID, "sha256": digest(schema_bytes)},
    }
    return ResolvedConfiguration(
        value=resolved,
        canonical=canonical,
        identity=identity,
        identity_bytes=canonical_json(identity),
        defaults=defaults,
        defaults_bytes=canonical_json(defaults),
        schema_bytes=schema_bytes,
        controlled_bytes=controlled_bytes,
        controlled_path=controlled_path,
    )


def resolve_configuration(
    controlled_bytes: bytes,
    controlled_path: str,
    overrides: list[dict[str, Any]] | None = None,
) -> ResolvedConfiguration:
    """Resolve exact controlled bytes and explicit overrides into v1 identity."""
    try:
        return _resolve_configuration(controlled_bytes, controlled_path, overrides)
    except RecursionError:
        _fail("configuration.nesting_limit", "configuration nesting exceeds the supported limit")
