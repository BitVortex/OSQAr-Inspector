# OSQAr Inspector

**OSQAr Inspector** is a proposed companion tool for acquiring and structuring implementation evidence for OSQAr workflows. It is designed to examine immutable software snapshots, coordinate documentation and coverage producers, and emit a deterministic inspection bundle with machine-readable identity and integrity records.

> **Project status:** architecture and design phase. No implementation, released package, stable schema, or supported CLI exists yet.

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

## Intended command model

These command names are design targets, not implemented interfaces:

```text
osqar-inspector plan --project <path> --configuration <file>
osqar-inspector build --project <path> --configuration <file>
osqar-inspector verify --bundle <path>
```

The proposed OSQAr integration adds `osqar inspect` and extends the existing `osqar shipment prepare` orchestration when inspection is enabled:

```text
osqar inspect --project <path>
osqar shipment prepare --project <path>
```

Projects that do not enable inspection are intended to retain existing OSQAr behavior.

## Initial design scope

The first usable integration is deliberately bounded to typed configuration and planning, clean-Git snapshot capture, owned execution workspaces, Doxygen output, generic pre-generated coverage ingestion, a normalized artifact graph, closed-bundle publication, independent bundle verification, and a first-class OSQAr adapter.
