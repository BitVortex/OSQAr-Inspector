# OSQAr Inspector

**OSQAr Inspector** is a companion tool for acquiring and structuring implementation evidence for OSQAr workflows. The implemented foundation resolves strict, reproducibly identified configuration and independently validates the inventory, payload digests, run report, internal links, and deterministic identity of an existing closed inspection bundle.

> **Project status:** `osqar.inspector.config.v1` resolution and `osqar-inspector verify --bundle PATH` are implemented. `plan`, `build`, publication, producers, signatures, and OSQAr integration remain design targets.

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
uv run osqar-inspector verify --bundle <path>
```

Successful verification writes deterministic JSON containing `valid: true` and the recomputed `bundle_id` to standard output. Verification parses listed `.html` payloads as UTF-8 after inventory, digest, checksum, and run-report validation; internal targets and fragments must resolve within the closed manifest inventory, while external references are not fetched. Failure exits nonzero and writes deterministic JSON containing `valid: false` and a typed diagnostic to standard error.

The remaining Inspector commands are design targets, not implemented interfaces:

```text
osqar-inspector plan --project <path> --configuration <file>
osqar-inspector build --project <path> --configuration <file>
```

## Initial design scope

The first usable integration is deliberately bounded to typed configuration and planning, clean-Git snapshot capture, owned execution workspaces, Doxygen output, generic pre-generated coverage ingestion, a normalized artifact graph, closed-bundle publication, independent bundle verification, and a first-class OSQAr adapter.
