# OSQAr Inspector

**OSQAr Inspector** is a companion tool for acquiring and structuring implementation evidence for OSQAr workflows. The implemented foundation resolves strict, reproducibly identified configuration, captures and materializes immutable clean-Git snapshots, emits deterministic side-effect-free execution plans, executes Doxygen through an owned-workspace adapter with validated source/API mappings, ingests byte-preserved pre-generated coverage reports with independent mapping and attestation validation, builds a deterministic typed artifact graph, renders byte-preserving Inspector-owned navigation, generates deterministic closed bundles from finalized candidates, and independently validates bundle inventory, payload digests, run reports, internal links, and identity.

> **Project status:** `osqar.inspector.config.v1` resolution, `osqar.inspector.snapshot.v1` clean-Git capture/materialization, `osqar.inspector.plan.v1`, the library-level `builtin.doxygen.v1` producer adapter, generic pre-generated coverage ingestion with `osqar.inspector.coverage-map.v1` and `osqar.inspector.coverage-attestation.v1`, `osqar.inspector.artifact-graph.v1`, Inspector-owned navigation rendering, library-level deterministic bundle generation, and `osqar-inspector verify --bundle PATH` are implemented. The graph and navigation expose mechanically validated identities, relationships, stage states, and provenance states; they do not review or approve linked artifacts. CLI-level `build`, publication, coverage-producer execution, signatures, and OSQAr integration remain design targets.

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
- [Integration with OSQAr](docs/osqar-integration.md) — responsibility split, process boundary, identity binding, evidence-state mapping, and packaging flow.

## Quick start

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required for development:

```sh
uv sync
uv run osqar-inspector plan --project <path> --configuration <project-relative-file>
uv run osqar-inspector verify --bundle <path>
```

`plan` writes canonical `osqar.inspector.plan.v1` JSON to standard output. It resolves the strict configuration and clean-Git snapshot, calls only adapter declaration operations, records producer capabilities as unresolved, and returns nonzero when a required prerequisite is statically unsatisfied. Repeatable typed overrides use `--override 'JSON_POINTER=JSON_VALUE'` or `--override JSON_POINTER 'JSON_VALUE'`. Planning does not probe or execute producers, materialize a snapshot, create a workspace, or write project/output files.

Successful verification writes deterministic JSON containing `valid: true` and the recomputed `bundle_id` to standard output. Verification parses listed `.html` payloads as UTF-8 after inventory, digest, checksum, and run-report validation; internal targets and fragments must resolve within the closed manifest inventory, while external references are not fetched. Failure exits nonzero and writes deterministic JSON containing `valid: false` and a typed diagnostic to standard error.

Finalized orchestrator output is closed through the library interface:

```python
from osqar_inspector.bundle_generation import generate_bundle

generated = generate_bundle(candidate, destination)
print(generated.bundle_id)
```

The destination must not already exist. Generation accepts only a candidate whose required-stage policy is satisfied, writes the exact immutable payload inventory plus canonical `manifest.json` and `checksums.sha256`, and calls the independent filesystem verifier before returning. The returned bundle ID must equal the generator's expected ID. Closure establishes exact inventory and digest consistency only; it does not establish artifact authenticity, substantive adequacy, approval, or qualification.

Clean-Git snapshot capture is currently a library interface used by the future `build` command:

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

The remaining Inspector build command is a design target, not an implemented interface:

```text
osqar-inspector build --project <path> --configuration <file>
```

## Initial design scope

The first usable integration is deliberately bounded to typed configuration and planning, clean-Git snapshot capture, owned execution workspaces, Doxygen output, generic pre-generated coverage ingestion, a normalized artifact graph, closed-bundle publication, independent bundle verification, and a first-class OSQAr adapter.
