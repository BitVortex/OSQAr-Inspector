# Detached signature envelope v1

## Scope and claim boundary

`osqar.inspector.detached-signature.v1` is a canonical, detached Ed25519 envelope for a caller-selected statement and one exact, independently verified Inspector bundle. Signing and verification do not write beneath the bundle root. Any number of envelopes may therefore refer to the same bundle without changing its bytes or bundle ID.

A `valid_trusted_signature` result establishes only that:

- the envelope signature verifies under the caller-supplied Ed25519 trust anchor named by `key_id`;
- the supplied statement payload has the signed SHA-256 digest; and
- the currently verified closed bundle has the signed bundle ID, manifest digest, and checksum-file digest.

It does not establish signer authority, key governance, statement truth, evidence adequacy, approval, qualification, certification, standards compliance, functional safety, security, or project acceptance.

## Algorithm profile

Version 1 supports only Ed25519 as specified by RFC 8032 through the `cryptography` Ed25519 API:

- `algorithm`: `ed25519`
- private key material: a 32-byte Ed25519 private seed
- library signing input: a `cryptography` `Ed25519PrivateKey` object (for raw seed material, construct it with `Ed25519PrivateKey.from_private_bytes(seed)`)
- public key: 32-byte raw Ed25519 public key
- signature: 64 bytes
- binary encodings: canonical unpadded base64url
- content digests: lowercase SHA-256 hexadecimal
- JSON serialization: the project RFC 8785-compatible canonical JSON subset

Unsupported schema versions and algorithms fail closed. Version negotiation or algorithm fallback is not attempted.

## Closed envelope

The envelope contains exactly these members:

```json
{
  "algorithm": "ed25519",
  "binding": {
    "bundle_id": "bundle:sha256:<64 lowercase hex>",
    "checksums_sha256": "<64 lowercase hex>",
    "manifest_sha256": "<64 lowercase hex>",
    "payload_sha256": "<64 lowercase hex>",
    "statement_type": "<v1 lowercase token>"
  },
  "key_id": "<v1 key token>",
  "public_key": null,
  "schema": "osqar.inspector.detached-signature.v1",
  "signature": "<unpadded base64url Ed25519 signature>"
}
```

`public_key` is either `null` or the raw 32-byte public key encoded as unpadded base64url. An embedded key is transport information only. It is never a trust anchor.

The envelope itself remains outside the closed bundle.

## Exact signed bytes

The Ed25519 input is the canonical JSON encoding of the complete envelope after removing only the `signature` member. The signed object therefore contains exactly:

- `algorithm`
- `binding`
- `key_id`
- `public_key`
- `schema`

No prefix, suffix, newline, pre-hash, or implicit metadata is added. `payload_sha256` binds the caller-supplied statement bytes; the payload is not embedded in the envelope.

`bundle_id`, `manifest_sha256`, and `checksums_sha256` are independently reconstructed from the closed bundle. A signature over an envelope that names different values is not accepted for the current bundle. Signing performs initial bundle verification and binding construction; before returning, it reconstructs the control binding and then performs terminal complete bundle verification. Verification likewise requires two matching control-binding reconstructions, with terminal complete bundle verification following the second reconstruction. Each operation refuses success if the bundle identity or exact control-file digests differ within that bounded operation.

## Trust processing

The verifier accepts a caller-supplied mapping from `key_id` to raw Ed25519 public-key bytes.

- A matching caller-supplied key that verifies and whose binding matches the current bundle produces `valid_trusted_signature`.
- A missing caller key and no embedded key produces `unknown_key`.
- A missing caller key with a cryptographically valid embedded key produces `untrusted_key`; it never produces a trusted result.
- A caller key takes precedence over any embedded key. An envelope cannot replace or override the caller anchor.

## Typed results

- `malformed_envelope`: invalid UTF-8/JSON, noncanonical JSON, duplicate/unknown/missing members, invalid token/digest/base64 shape, or invalid embedded key encoding.
- `unsupported_version`: the canonical envelope names a schema other than v1.
- `unsupported_algorithm`: the v1 envelope names an algorithm other than Ed25519.
- `invalid_signature`: the Ed25519 equation fails, the statement payload differs, or the current bundle/control binding differs or cannot be verified.
- `invalid_trust_anchor`: the caller does not supply a key mapping, or supplies a value for `key_id` that is not a raw 32-byte Ed25519 public key.
- `unknown_key`: no caller anchor or embedded verification key is available for `key_id`.
- `untrusted_key`: the signature verifies with only the embedded key; the result is cryptographically valid but not trusted.
- `valid_trusted_signature`: the signature and exact binding verify with the caller-supplied trust anchor.

## Library interface

```python
from osqar_inspector.signatures import sign_bundle, verify_detached_signature

signed = sign_bundle(
    bundle_root,
    private_key,
    key_id="release-key-2026",
    statement_type="example.review.v1",
    payload=statement_bytes,
)
result = verify_detached_signature(
    bundle_root,
    signed.envelope_bytes,
    statement_bytes,
    trust_anchors={"release-key-2026": trusted_public_key_bytes},
)
```

`verify_detached_signatures` applies the same independent operation to an ordered tuple of `(envelope_bytes, payload_bytes)` pairs.

## Interoperability vector

[`tests/fixtures/signatures/v1-ed25519.json`](../tests/fixtures/signatures/v1-ed25519.json) publishes:

- every exact closed-bundle file as unpadded base64url;
- the expected bundle ID;
- statement payload;
- private seed and public key for test use only;
- canonical envelope;
- exact signed bytes; and
- detached signature.

The published private seed is deliberately public and must never be used outside interoperability testing. The acceptance test reconstructs the bundle, independently removes only `signature`, reproduces the canonical signed bytes, and verifies the envelope against an explicitly supplied trust anchor. Mutation tests cover the bundle manifest, statement payload/type, embedded/unknown keys, malformed envelopes, unsupported version, and unsupported algorithm.
