"""Detached Ed25519 signatures bound to exact closed Inspector bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .configuration import canonical_json
from .verify import VerificationError, verify_bundle

SCHEMA = "osqar.inspector.detached-signature.v1"
ALGORITHM = "ed25519"
_KEY_ID = re.compile(r"[A-Za-z0-9]+(?:[._:+-][A-Za-z0-9]+)*\Z")
_STATEMENT_TYPE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ENVELOPE_KEYS = {"algorithm", "binding", "key_id", "public_key", "schema", "signature"}
_SIGNED_KEYS = _ENVELOPE_KEYS - {"signature"}
_BINDING_KEYS = {
    "bundle_id",
    "checksums_sha256",
    "manifest_sha256",
    "payload_sha256",
    "statement_type",
}


@dataclass(frozen=True)
class SignatureError(Exception):
    """Typed signer-side failure."""

    code: str
    message: str


@dataclass(frozen=True)
class DetachedSignature:
    """Canonical detached envelope plus the exact bytes covered by Ed25519."""

    envelope_bytes: bytes
    signed_bytes: bytes
    public_key_bytes: bytes
    bundle_id: str


@dataclass(frozen=True)
class SignatureVerificationResult:
    """Closed verification outcome; validity does not establish statement truth."""

    status: str
    valid: bool = False
    trusted: bool = False
    bundle_id: str | None = None
    key_id: str | None = None
    statement_type: str | None = None


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _b64encode(content: bytes) -> str:
    return base64.urlsafe_b64encode(content).rstrip(b"=").decode("ascii")


def _b64decode(value: object, expected_size: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("not canonical unpadded base64url")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url alphabet")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if len(decoded) != expected_size or _b64encode(decoded) != value:
        raise ValueError("invalid encoded size or noncanonical encoding")
    return decoded


def _control_binding(root: Path, bundle_id: str, statement_type: str, payload: bytes) -> dict[str, str]:
    try:
        manifest_bytes = (root / "manifest.json").read_bytes()
        checksums_bytes = (root / "checksums.sha256").read_bytes()
    except OSError as error:
        raise SignatureError("signature.bundle_unreadable", "bundle control files cannot be read") from error
    return {
        "bundle_id": bundle_id,
        "checksums_sha256": _sha256(checksums_bytes),
        "manifest_sha256": _sha256(manifest_bytes),
        "payload_sha256": _sha256(payload),
        "statement_type": statement_type,
    }


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_bundle(
    root: Path,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    statement_type: str,
    payload: bytes,
    include_public_key: bool = False,
) -> DetachedSignature:
    """Sign a caller-selected statement binding without modifying bundle bytes."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignatureError("signature.invalid_private_key", "an Ed25519 private key is required")
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise SignatureError("signature.invalid_key_id", "key_id does not satisfy the v1 token profile")
    if not isinstance(statement_type, str) or not _STATEMENT_TYPE.fullmatch(statement_type):
        raise SignatureError(
            "signature.invalid_statement_type",
            "statement_type does not satisfy the v1 token profile",
        )
    if not isinstance(payload, bytes):
        raise SignatureError("signature.invalid_payload", "statement payload must be exact bytes")
    try:
        bundle_id = verify_bundle(Path(root))
    except VerificationError as error:
        raise SignatureError("signature.invalid_bundle", f"bundle verification failed: {error.code}") from error

    public_key_bytes = _raw_public_key(private_key)
    binding = _control_binding(Path(root), bundle_id, statement_type, payload)
    signed_object: dict[str, Any] = {
        "algorithm": ALGORITHM,
        "binding": binding,
        "key_id": key_id,
        "public_key": _b64encode(public_key_bytes) if include_public_key else None,
        "schema": SCHEMA,
    }
    signed_bytes = canonical_json(signed_object)
    envelope_bytes = canonical_json(
        {**signed_object, "signature": _b64encode(private_key.sign(signed_bytes))}
    )

    try:
        terminal_binding = _control_binding(Path(root), bundle_id, statement_type, payload)
        terminal_bundle_id = verify_bundle(Path(root))
    except (VerificationError, SignatureError) as error:
        code = error.code
        raise SignatureError(
            "signature.bundle_changed", f"bundle changed while signing: {code}"
        ) from error
    if terminal_bundle_id != bundle_id or terminal_binding != binding:
        raise SignatureError("signature.bundle_changed", "bundle changed while signing")
    return DetachedSignature(
        envelope_bytes=envelope_bytes,
        signed_bytes=signed_bytes,
        public_key_bytes=public_key_bytes,
        bundle_id=bundle_id,
    )


def _malformed() -> SignatureVerificationResult:
    return SignatureVerificationResult("malformed_envelope")


def _parse_envelope(envelope_bytes: bytes) -> dict[str, Any] | None:
    if not isinstance(envelope_bytes, bytes):
        return None

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        envelope = json.loads(
            envelope_bytes.decode("utf-8"), object_pairs_hook=reject_duplicates
        )
        if canonical_json(envelope) != envelope_bytes:
            return None
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None
    return envelope if isinstance(envelope, dict) else None


def verify_detached_signature(
    root: Path,
    envelope_bytes: bytes,
    payload: bytes,
    *,
    trust_anchors: Mapping[str, bytes],
) -> SignatureVerificationResult:
    """Verify one detached envelope using only caller-supplied trust anchors."""

    envelope = _parse_envelope(envelope_bytes)
    if envelope is None or set(envelope) != _ENVELOPE_KEYS:
        return _malformed()
    if not isinstance(envelope.get("schema"), str):
        return _malformed()
    if envelope["schema"] != SCHEMA:
        return SignatureVerificationResult("unsupported_version")
    if not isinstance(envelope.get("algorithm"), str):
        return _malformed()
    if envelope["algorithm"] != ALGORITHM:
        return SignatureVerificationResult("unsupported_algorithm")
    if not isinstance(trust_anchors, Mapping):
        return SignatureVerificationResult("invalid_trust_anchor")

    binding = envelope.get("binding")
    key_id = envelope.get("key_id")
    public_key_value = envelope.get("public_key")
    if (
        not isinstance(binding, dict)
        or set(binding) != _BINDING_KEYS
        or not isinstance(key_id, str)
        or not _KEY_ID.fullmatch(key_id)
        or not isinstance(payload, bytes)
        or not isinstance(binding.get("bundle_id"), str)
        or not re.fullmatch(r"bundle:sha256:[0-9a-f]{64}", binding["bundle_id"])
        or any(
            not isinstance(binding.get(name), str) or not _HEX.fullmatch(binding[name])
            for name in ("checksums_sha256", "manifest_sha256", "payload_sha256")
        )
        or not isinstance(binding.get("statement_type"), str)
        or not _STATEMENT_TYPE.fullmatch(binding["statement_type"])
        or (public_key_value is not None and not isinstance(public_key_value, str))
    ):
        return _malformed()

    try:
        signature = _b64decode(envelope["signature"], 64)
        embedded_key = (
            _b64decode(public_key_value, 32) if public_key_value is not None else None
        )
    except (ValueError, TypeError):
        return _malformed()

    signed_object = {key: envelope[key] for key in _SIGNED_KEYS}
    signed_bytes = canonical_json(signed_object)
    has_anchor = key_id in trust_anchors
    anchor = trust_anchors[key_id] if has_anchor else None
    if has_anchor and (not isinstance(anchor, bytes) or len(anchor) != 32):
        return SignatureVerificationResult(
            "invalid_trust_anchor",
            key_id=key_id,
            statement_type=binding["statement_type"],
        )
    if anchor is None and embedded_key is None:
        return SignatureVerificationResult(
            "unknown_key", key_id=key_id, statement_type=binding["statement_type"]
        )
    key_bytes = anchor if anchor is not None else embedded_key
    try:
        if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
            return _malformed()
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, signed_bytes)
    except InvalidSignature:
        return SignatureVerificationResult(
            "invalid_signature", key_id=key_id, statement_type=binding["statement_type"]
        )
    except (TypeError, ValueError):
        return _malformed()

    try:
        actual_bundle_id = verify_bundle(Path(root))
        actual_binding = _control_binding(
            Path(root), actual_bundle_id, binding["statement_type"], payload
        )
    except (VerificationError, SignatureError, TypeError):
        return SignatureVerificationResult(
            "invalid_signature", key_id=key_id, statement_type=binding["statement_type"]
        )
    if actual_binding != binding:
        return SignatureVerificationResult(
            "invalid_signature", key_id=key_id, statement_type=binding["statement_type"]
        )
    try:
        terminal_binding = _control_binding(
            Path(root), actual_bundle_id, binding["statement_type"], payload
        )
        terminal_bundle_id = verify_bundle(Path(root))
    except (VerificationError, SignatureError, TypeError):
        return SignatureVerificationResult(
            "invalid_signature", key_id=key_id, statement_type=binding["statement_type"]
        )
    if terminal_bundle_id != actual_bundle_id or terminal_binding != actual_binding:
        return SignatureVerificationResult(
            "invalid_signature", key_id=key_id, statement_type=binding["statement_type"]
        )
    if anchor is None:
        return SignatureVerificationResult(
            "untrusted_key",
            valid=True,
            trusted=False,
            bundle_id=actual_bundle_id,
            key_id=key_id,
            statement_type=binding["statement_type"],
        )
    return SignatureVerificationResult(
        "valid_trusted_signature",
        valid=True,
        trusted=True,
        bundle_id=actual_bundle_id,
        key_id=key_id,
        statement_type=binding["statement_type"],
    )


def verify_detached_signatures(
    root: Path,
    envelopes: tuple[tuple[bytes, bytes], ...],
    *,
    trust_anchors: Mapping[str, bytes],
) -> tuple[SignatureVerificationResult, ...]:
    """Verify multiple independent envelopes without changing the closed bundle."""

    return tuple(
        verify_detached_signature(
            root, envelope_bytes, payload, trust_anchors=trust_anchors
        )
        for envelope_bytes, payload in envelopes
    )
