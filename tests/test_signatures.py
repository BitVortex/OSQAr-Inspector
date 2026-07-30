from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from osqar_inspector.bundle_generation import generate_bundle
from osqar_inspector.signatures import (
    SignatureError,
    sign_bundle,
    verify_detached_signature,
    verify_detached_signatures,
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def valid_run_report() -> bytes:
    digest = "0" * 64
    return canonical(
        {
            "artifact_counts": [{"count": "1", "kind": "api-page"}],
            "claim_boundary": {
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
            },
            "configuration_identity": {
                "controlled_input": {
                    "path": "inspector.json",
                    "sha256": digest,
                    "size": "1",
                },
                "defaults": {"id": "builtin-v1", "sha256": digest},
                "overrides": [],
                "resolved": {"sha256": digest},
                "schema": {"id": "osqar.inspector.config.v1", "sha256": digest},
            },
            "diagnostics": [],
            "inspector": {"version": "0.1.0"},
            "optional_stages": {"degraded": [], "skipped": []},
            "plan_sha256": digest,
            "required_stage_decision": "satisfied",
            "schema": "osqar.inspector.run.v1",
            "snapshot_id": f"snapshot:sha256:{digest}",
            "stage_result_digests": [digest],
        }
    )


@dataclass(frozen=True)
class Candidate:
    payloads: tuple[tuple[str, bytes], ...]
    candidate_ready: bool = True


def fixed_bundle(tmp_path: Path, name: str = "bundle"):
    return generate_bundle(
        Candidate(
            (
                ("artifacts/data.txt", b"fixed interoperability payload\n"),
                ("navigation/index.html", b"<h1>Inspection</h1>\n"),
                ("reports/run.json", valid_run_report()),
            )
        ),
        tmp_path / name,
    )


def decode_vector(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_fixed_signature_vector_verifies_exact_bundle_binding(tmp_path: Path) -> None:
    fixture_path = files("osqar_inspector").joinpath(
        "resources", "interoperability", "signatures-v1-ed25519.json"
    )
    vector = json.loads(fixture_path.read_bytes())
    bundle_root = tmp_path / "fixture-bundle"
    for relative, encoded in vector["bundle_files"].items():
        destination = bundle_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(decode_vector(encoded))

    envelope_bytes = decode_vector(vector["envelope_base64url"])
    statement = decode_vector(vector["statement_payload_base64url"])
    envelope = json.loads(envelope_bytes)
    signature = envelope.pop("signature")
    independently_reproduced_signed_bytes = canonical(envelope)

    assert signature == vector["signature_base64url"]
    assert independently_reproduced_signed_bytes == decode_vector(
        vector["signed_bytes_base64url"]
    )
    result = verify_detached_signature(
        bundle_root,
        envelope_bytes,
        statement,
        trust_anchors={
            vector["key_id"]: decode_vector(vector["public_key_base64url"])
        },
    )
    assert result.status == "valid_trusted_signature"
    assert result.trusted is True
    assert result.valid is True
    assert result.bundle_id == vector["bundle_id"]


def tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_multiple_detached_envelopes_do_not_change_bundle_bytes_or_id(
    tmp_path: Path,
) -> None:
    bundle = fixed_bundle(tmp_path)
    before = tree_hashes(bundle.root)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    first = sign_bundle(
        bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.review.v1",
        payload=b"first",
    )
    second = sign_bundle(
        bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.release.v1",
        payload=b"second",
    )
    results = verify_detached_signatures(
        bundle.root,
        ((first.envelope_bytes, b"first"), (second.envelope_bytes, b"second")),
        trust_anchors={"test-key-2026": first.public_key_bytes},
    )

    assert [result.status for result in results] == [
        "valid_trusted_signature",
        "valid_trusted_signature",
    ]
    assert tree_hashes(bundle.root) == before
    assert all(result.bundle_id == bundle.bundle_id for result in results)


def test_bundle_manifest_and_statement_mutations_fail(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    payload = b'{"decision":"reviewed"}'

    statement_bundle = fixed_bundle(tmp_path, "statement-bundle")
    signed = sign_bundle(
        statement_bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.review.v1",
        payload=payload,
    )
    anchors = {"test-key-2026": signed.public_key_bytes}
    assert verify_detached_signature(
        statement_bundle.root,
        signed.envelope_bytes,
        b'{"decision":"rejected"}',
        trust_anchors=anchors,
    ).status == "invalid_signature"

    statement_envelope = json.loads(signed.envelope_bytes)
    statement_envelope["binding"]["statement_type"] = "osqar.inspector.release.v1"
    assert verify_detached_signature(
        statement_bundle.root,
        canonical(statement_envelope),
        payload,
        trust_anchors=anchors,
    ).status == "invalid_signature"

    manifest_bundle = fixed_bundle(tmp_path, "manifest-bundle")
    manifest_signature = sign_bundle(
        manifest_bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.review.v1",
        payload=payload,
    )
    (manifest_bundle.root / "manifest.json").write_bytes(b"{}")
    assert verify_detached_signature(
        manifest_bundle.root,
        manifest_signature.envelope_bytes,
        payload,
        trust_anchors=anchors,
    ).status == "invalid_signature"


@pytest.mark.parametrize("control_name", ("manifest.json", "checksums.sha256"))
def test_transient_control_file_mutation_during_signing_fails_closed(
    tmp_path: Path, monkeypatch, control_name: str
) -> None:
    from osqar_inspector import signatures

    bundle = fixed_bundle(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    control_path = bundle.root / control_name
    original_control = control_path.read_bytes()
    original_binding = signatures._control_binding
    binding_calls = 0

    def bind_transient_control(root, bundle_id, statement_type, payload):
        nonlocal binding_calls
        binding_calls += 1
        if binding_calls != 1:
            return original_binding(root, bundle_id, statement_type, payload)
        control_path.write_bytes(b"{}")
        try:
            return original_binding(root, bundle_id, statement_type, payload)
        finally:
            control_path.write_bytes(original_control)

    monkeypatch.setattr(signatures, "_control_binding", bind_transient_control)

    with pytest.raises(SignatureError) as raised:
        sign_bundle(
            bundle.root,
            key,
            key_id="test-key-2026",
            statement_type="osqar.inspector.review.v1",
            payload=b"statement",
        )

    assert raised.value.code == "signature.bundle_changed"


@pytest.mark.parametrize("control_name", ("manifest.json", "checksums.sha256"))
def test_transient_control_file_mutation_during_verification_fails_closed(
    tmp_path: Path, monkeypatch, control_name: str
) -> None:
    from osqar_inspector import signatures

    bundle = fixed_bundle(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    payload = b"statement"
    signed = sign_bundle(
        bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.review.v1",
        payload=payload,
    )
    envelope = json.loads(signed.envelope_bytes)
    digest_member = (
        "manifest_sha256" if control_name == "manifest.json" else "checksums_sha256"
    )
    envelope["binding"][digest_member] = hashlib.sha256(b"{}").hexdigest()
    signed_object = {name: value for name, value in envelope.items() if name != "signature"}
    envelope["signature"] = base64.urlsafe_b64encode(
        key.sign(canonical(signed_object))
    ).rstrip(b"=").decode("ascii")

    control_path = bundle.root / control_name
    original_control = control_path.read_bytes()
    original_binding = signatures._control_binding
    binding_calls = 0

    def bind_transient_control(root, bundle_id, statement_type, statement_payload):
        nonlocal binding_calls
        binding_calls += 1
        if binding_calls != 1:
            return original_binding(root, bundle_id, statement_type, statement_payload)
        control_path.write_bytes(b"{}")
        try:
            return original_binding(root, bundle_id, statement_type, statement_payload)
        finally:
            control_path.write_bytes(original_control)

    monkeypatch.setattr(signatures, "_control_binding", bind_transient_control)
    result = verify_detached_signature(
        bundle.root,
        canonical(envelope),
        payload,
        trust_anchors={"test-key-2026": signed.public_key_bytes},
    )

    assert result.status == "invalid_signature"
    assert result.valid is False
    assert control_path.read_bytes() == original_control


@pytest.mark.parametrize("mutation_kind", ("payload", "extra-file"))
def test_filesystem_mutation_during_terminal_control_reread_fails_closed(
    tmp_path: Path, monkeypatch, mutation_kind: str
) -> None:
    from osqar_inspector import signatures

    bundle = fixed_bundle(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    payload_path = bundle.root / "navigation/index.html"
    original_binding = signatures._control_binding
    binding_calls = 0

    def mutate_payload_on_terminal_binding(root, bundle_id, statement_type, payload):
        nonlocal binding_calls
        binding_calls += 1
        binding = original_binding(root, bundle_id, statement_type, payload)
        if binding_calls == 2:
            if mutation_kind == "payload":
                payload_path.write_bytes(b"late payload mutation")
            else:
                (bundle.root / "late-extra.txt").write_bytes(b"late inventory mutation")
        return binding

    monkeypatch.setattr(
        signatures, "_control_binding", mutate_payload_on_terminal_binding
    )

    with pytest.raises(SignatureError) as raised:
        sign_bundle(
            bundle.root,
            key,
            key_id="test-key-2026",
            statement_type="osqar.inspector.review.v1",
            payload=b"statement",
        )

    assert raised.value.code == "signature.bundle_changed"


def test_terminal_bundle_mutation_during_verification_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    from osqar_inspector import signatures

    bundle = fixed_bundle(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signed = sign_bundle(
        bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.review.v1",
        payload=b"statement",
    )
    original = signatures._control_binding

    def mutate_after_binding(root, bundle_id, statement_type, payload):
        binding = original(root, bundle_id, statement_type, payload)
        (root / "navigation/index.html").write_bytes(b"late mutation")
        return binding

    monkeypatch.setattr(signatures, "_control_binding", mutate_after_binding)
    result = verify_detached_signature(
        bundle.root,
        signed.envelope_bytes,
        b"statement",
        trust_anchors={"test-key-2026": signed.public_key_bytes},
    )

    assert result.status == "invalid_signature"
    assert result.valid is False


def test_embedded_or_unknown_key_is_not_implicitly_trusted(tmp_path: Path) -> None:
    bundle = fixed_bundle(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    payload = b"statement"
    embedded = sign_bundle(
        bundle.root,
        key,
        key_id="untrusted-key",
        statement_type="osqar.inspector.review.v1",
        payload=payload,
        include_public_key=True,
    )
    detached = sign_bundle(
        bundle.root,
        key,
        key_id="unknown-key",
        statement_type="osqar.inspector.review.v1",
        payload=payload,
    )

    untrusted = verify_detached_signature(
        bundle.root, embedded.envelope_bytes, payload, trust_anchors={}
    )
    unknown = verify_detached_signature(
        bundle.root, detached.envelope_bytes, payload, trust_anchors={}
    )
    explicit_null_anchor = verify_detached_signature(
        bundle.root,
        embedded.envelope_bytes,
        payload,
        trust_anchors={"untrusted-key": None},  # type: ignore[dict-item]
    )

    assert (untrusted.status, untrusted.valid, untrusted.trusted) == (
        "untrusted_key",
        True,
        False,
    )
    assert (unknown.status, unknown.valid, unknown.trusted) == (
        "unknown_key",
        False,
        False,
    )
    assert (
        explicit_null_anchor.status,
        explicit_null_anchor.valid,
        explicit_null_anchor.trusted,
    ) == ("invalid_trust_anchor", False, False)
    assert verify_detached_signature(
        bundle.root,
        embedded.envelope_bytes,
        b"different statement",
        trust_anchors={},
    ).status == "invalid_signature"


def test_malformed_and_unsupported_envelopes_fail_closed(tmp_path: Path) -> None:
    bundle = fixed_bundle(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signed = sign_bundle(
        bundle.root,
        key,
        key_id="test-key-2026",
        statement_type="osqar.inspector.review.v1",
        payload=b"statement",
    )
    anchors = {"test-key-2026": signed.public_key_bytes}
    envelope = json.loads(signed.envelope_bytes)

    unsupported_version = {**envelope, "schema": "osqar.inspector.detached-signature.v2"}
    unsupported_algorithm = {**envelope, "algorithm": "ed448"}
    invalid_version_type = {**envelope, "schema": None}
    invalid_algorithm_type = {**envelope, "algorithm": 1}
    malformed_signature = {**envelope, "signature": "not+base64"}

    cases = (
        (b"{}", "malformed_envelope"),
        (b'{"x":NaN}', "malformed_envelope"),
        (b'{"schema":1,"schema":1}', "malformed_envelope"),
        (canonical(unsupported_version), "unsupported_version"),
        (canonical(unsupported_algorithm), "unsupported_algorithm"),
        (canonical(invalid_version_type), "malformed_envelope"),
        (canonical(invalid_algorithm_type), "malformed_envelope"),
        (canonical(malformed_signature), "malformed_envelope"),
    )
    for envelope_bytes, expected in cases:
        result = verify_detached_signature(
            bundle.root,
            envelope_bytes,
            b"statement",
            trust_anchors=anchors,
        )
        assert result.status == expected
        assert result.valid is False
        assert result.trusted is False

    invalid_anchor = verify_detached_signature(
        bundle.root,
        signed.envelope_bytes,
        b"statement",
        trust_anchors={"test-key-2026": b"too-short"},
    )
    missing_anchor_mapping = verify_detached_signature(
        bundle.root,
        signed.envelope_bytes,
        b"statement",
        trust_anchors=None,  # type: ignore[arg-type]
    )
    invalid_root = verify_detached_signature(
        None,  # type: ignore[arg-type]
        signed.envelope_bytes,
        b"statement",
        trust_anchors=anchors,
    )
    assert invalid_anchor.status == "invalid_trust_anchor"
    assert missing_anchor_mapping.status == "invalid_trust_anchor"
    assert invalid_root.status == "invalid_signature"
    assert invalid_anchor.valid is False
    assert invalid_anchor.trusted is False
