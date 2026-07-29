# OSQAr Inspector

**OSQAr Inspector** is a companion tool for acquiring and structuring implementation evidence for OSQAr workflows. The implemented foundation resolves strict, reproducibly identified configuration, captures and materializes immutable clean-Git snapshots, emits deterministic side-effect-free execution plans, executes Doxygen through an owned-workspace adapter with validated source/API mappings, ingests byte-preserved pre-generated coverage reports with independent mapping and attestation validation, builds a deterministic typed artifact graph, renders byte-preserving Inspector-owned navigation, generates deterministic closed bundles from finalized candidates, independently validates bundle inventory, payload digests, run reports, internal links, and identity, applies caller-trusted detached Ed25519 signatures to exact bundle and statement bindings, and publishes immutable Linux releases through an atomic-pointer durability protocol with explicit filesystem assumptions of use.

> **Project status:** `osqar.inspector.config.v1` resolution, `osqar.inspector.snapshot.v1` clean-Git capture/materialization, `osqar.inspector.plan.v1`, the library-level `builtin.doxygen.v1` producer adapter, generic pre-generated coverage ingestion with `osqar.inspector.coverage-map.v1` and `osqar.inspector.coverage-attestation.v1`, `osqar.inspector.artifact-graph.v1`, Inspector-owned navigation rendering, deterministic bundle generation, independent bundle verification, `osqar.inspector.detached-signature.v1`, the Linux `osqar.inspector.publication-result.v1` protocol, and the public `build` command are implemented. The graph and navigation expose mechanically validated identities, relationships, stage states, and provenance states; they do not review or approve linked artifacts. Coverage-producer execution and OSQAr integration remain design targets.

## Purpose

The proposed system will:

- bind inspection results to one completely inventoried source snapshot;
- orchestrate versioned producer adapters in owned workspaces;
- normalize source, API-documentation, coverage, log, and artifact records;
- construct a typed artifact graph and separate navigation layer;
- publish a closed, checksum-protected bundle; and
- provide a versioned handoff to OSQAr.

## Claim boundary

An eventual mechanical inspection result will describe only the configured stages and structural or integrity checks that were executed. It will not establish evidence adequacy, software or tool qualification, standards compliance, certification, functional safety, security, or fitness for use. OSQAr remains responsible for project-specific evidence lifecycle, traceability, review, findings, deviations, acceptance, and shipment governance.

## Design documentation

- [Architecture](docs/architecture.md) — system context, layers, components, pipeline, invariants, and failure model.
- [Design contracts](docs/design.md) — command, configuration, identity, adapter, graph, bundle, and publication contracts.
- [Detached signatures](docs/signatures.md) — canonical Ed25519 envelope, exact signed bytes, caller-supplied trust, typed results, and interoperability vector.
- [Integration with OSQAr](docs/osqar-integration.md) — responsibility split, process boundary, identity binding, evidence-state mapping, and packaging flow.

## Quick start

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required for development:

```sh
uv sync
uv run osqar-inspector plan --project <path> --configuration <project-relative-file>
uv run osqar-inspector build --project <path> --configuration <project-relative-file>
uv run osqar-inspector verify --bundle <path>
```

`plan` writes canonical `osqar.inspector.plan.v1` JSON to standard output. It resolves the strict configuration and clean-Git snapshot, calls only adapter declaration operations, records producer capabilities as unresolved, and returns nonzero when a required prerequisite is statically unsatisfied. Repeatable typed overrides use `--override 'JSON_POINTER=JSON_VALUE'` or `--override JSON_POINTER 'JSON_VALUE'`. Planning does not probe or execute producers, materialize a snapshot, create a workspace, or write project/output files.

Successful verification writes deterministic JSON containing `valid: true` and the recomputed `bundle_id` to standard output. Verification parses listed `.html` payloads as UTF-8 after inventory, digest, checksum, and run-report validation; internal targets and fragments must resolve within the closed manifest inventory, while external references are not fetched. Failure exits nonzero and writes deterministic JSON containing `valid: false` and a typed diagnostic to standard error.

The `build` command resolves the same controlled configuration and snapshot, executes enabled built-in stages through owned workspaces, closes and independently verifies a bundle, and then publishes it beneath `publication.destination`. It writes canonical `osqar.inspector.publication-result.v1` JSON to standard output. Exit zero is limited to `durable-success` and `recovered-durable-success`; exit codes 10–14 represent the other closed publication/reconciliation states. On startup, the command serializes under the publication lock, synchronizes the root, and independently verifies whichever immutable release the sole `current` commit pointer names. The durability claim assumes a qualified local Linux filesystem with atomic same-filesystem replacement and working file/directory `fsync`; network and synthetic filesystems require separate assessment. After any unexpected storage or synchronization error, automatic retry is prohibited until the operator has re-established those assumptions. The journal-free protocol cannot prove that external action across process invocations: starting another build asserts that the operator has restored the AoU, while startup reconciliation checks only the observable publication state and not device health. Publication success records Linux filesystem placement and durability only; it does not establish review, authorization, evidence adequacy, qualification, certification, compliance, or fitness.

Finalized orchestrator output can also be closed through the library interface:

```python
from osqar_inspector.bundle_generation import generate_bundle

generated = generate_bundle(candidate, destination)
print(generated.bundle_id)
```

The destination must not already exist. Generation accepts only a candidate whose required-stage policy is satisfied, writes the exact immutable payload inventory plus canonical `manifest.json` and `checksums.sha256`, and calls the independent filesystem verifier before returning. The returned bundle ID must equal the generator's expected ID. Closure establishes exact inventory and digest consistency only; it does not establish artifact authenticity, substantive adequacy, approval, or qualification.

Detached signing remains outside the bundle and is available through the library interface:

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

The v1 profile signs canonical envelope bytes using Ed25519 and binds the exact verified bundle ID, `manifest.json` digest, `checksums.sha256` digest, statement type, and statement-payload digest. Trust comes only from the caller-supplied key mapping; an embedded key can produce only `untrusted_key`. See [Detached signatures](docs/signatures.md) for the exact byte contract, typed results, and fixed interoperability vector. Cryptographic verification does not establish signer authority, statement truth, approval, or project acceptance.

Clean-Git snapshot capture underpins the implemented `build` command and remains independently callable as a library interface:

```python
from osqar_inspector.snapshot import (
    capture_git_snapshot,
    materialize_snapshot,
    verify_materialized_snapshot,
)

snapshot = capture_git_snapshot(project, include=["src", "include"])
materialize_snapshot(snapshot, workspace)
verify_materialized_snapshot(snapshot, workspace)
```

The snapshot ID establishes only the recorded Git commit/tree, selection policy, and selected entry-byte binding. Snapshot v1 permits internal relative symlinks only when they resolve directly to a selected regular file. Its canonical manifest includes the Inspector version but excludes wall-clock capture time so repeated captures remain byte-identical. It does not establish source quality, review status, or suitability.

Coverage ingestion is currently a library interface. It inventories the closed
parent tree of the configured report entry point, preserves every report byte,
retains exact mapping and attestation sidecar bytes as separate evidence
artifacts, and emits deterministic artifact and explicit source-relation
records. Sidecars must be independently configured outside the report tree; no
mapping or provenance is inferred from report filenames. A valid mapping does
not establish provenance. Only an independently configured
attestation whose report, snapshot, and complete configuration-identity bindings all
match produces `externally-attested`; otherwise provenance remains
`unknown-origin`. This validation establishes internal binding consistency, not
declarant authenticity or independent test reproduction.

The Inspector build command is implemented as:

```text
osqar-inspector build --project <path> --configuration <file>
```

## Initial design scope

The first usable integration is deliberately bounded to typed configuration and planning, clean-Git snapshot capture, owned execution workspaces, Doxygen output, generic pre-generated coverage ingestion, a normalized artifact graph, closed-bundle publication, independent bundle verification, and a first-class OSQAr adapter.
