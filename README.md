# OSQAr Inspector

OSQAr Inspector turns a reviewed, clean Git revision into a deterministic, independently verifiable inspection bundle. It runs or ingests documentation and coverage producers in controlled workspaces, preserves their outputs, connects them through a typed artifact graph, and publishes only a closed bundle whose inventory, digests, run report, and internal links verify.

[Documentation](https://bitvortex.github.io/OSQAr-Inspector/) · [Quickstart](https://bitvortex.github.io/OSQAr-Inspector/getting-started.html) · [OSQAr integration](https://bitvortex.github.io/OSQAr-Inspector/osqar-integration.html) · [Release policy](https://bitvortex.github.io/OSQAr-Inspector/release.html)

> **Status:** Alpha (`0.1.0`). The standalone `plan`, `build`, and `verify` workflows and the versioned process handoff are implemented for Linux with Python 3.12 and 3.13. The OSQAr-side adapter and automatic shipment import are specified but not yet implemented.

## Problems it solves

Evidence-producing tools usually answer different questions and produce unrelated files. That creates four recurring problems:

- **Source drift:** generated material can be mistaken for evidence about a different source revision.
- **Fragmented outputs:** API documentation, coverage reports, logs, and stage results have no shared identity or navigation model.
- **Weak package boundaries:** copied files and checksums do not necessarily prove that the package is complete, internally linked, or free of extra content.
- **Unsafe handoff assumptions:** a successful producer exit is too weak a contract for OSQAr to import candidate evidence.

OSQAr Inspector addresses those problems mechanically:

1. resolves a strict, reproducibly identified configuration;
2. captures one completely inventoried clean-Git snapshot;
3. plans without probing or executing external producers;
4. executes enabled adapters in Inspector-owned workspaces during `build`;
5. preserves producer bytes and constructs typed artifact and provenance relations;
6. renders a separate navigation layer without rewriting producer output;
7. closes and independently verifies the exact bundle inventory; and
8. publishes an immutable Linux release through a defined durability protocol.

This gives operators and downstream tools a stable answer to: **which source, configuration, tools, outputs, relationships, and mechanical checks does this bundle represent?**

## Quickstart

### Prerequisites

- Linux
- Python 3.12 or 3.13
- [uv](https://docs.astral.sh/uv/)
- a clean Git project
- Doxygen when the default required Doxygen stage is enabled

Clone Inspector and install its locked environment:

```sh
git clone https://github.com/BitVortex/OSQAr-Inspector.git
cd OSQAr-Inspector
uv sync --locked
```

In the project to inspect, commit a `Doxyfile` and an `inspector.json` such as:

```json
{
  "schema": "osqar.inspector.config.v1",
  "project": {
    "include": ["src", "Doxyfile"],
    "exclude": []
  },
  "publication": {
    "destination": "build/osqar-inspector"
  }
}
```

The controlled configuration is merged with the packaged defaults. The example keeps the default required Doxygen stage, selects the tracked `Doxyfile`, and publishes beneath `build/osqar-inspector`. Adapt `project.include` to the source and producer-input paths tracked by your project.

From the Inspector checkout, replace `/path/to/project` with the clean Git project:

```sh
uv run osqar-inspector plan \
  --project /path/to/project \
  --configuration inspector.json

uv run osqar-inspector build \
  --project /path/to/project \
  --configuration inspector.json
```

`plan` prints deterministic JSON and does not run Doxygen or create project/output files. `build` prints an `osqar.inspector.publication-result.v1` object. On success, join the configured publication destination with its `release_path`, then verify that exact release:

```sh
uv run osqar-inspector verify \
  --bundle /path/to/project/build/osqar-inspector/releases/<bundle-id>
```

Verification succeeds only when the closed inventory, payload digests, run report, required entry points, and internal links are valid. See the [full Quickstart](https://bitvortex.github.io/OSQAr-Inspector/getting-started.html) for configuration variants, outputs, and failure handling.

## Basic functionality

- **`plan`** validates configuration and snapshot prerequisites and emits a deterministic execution plan. Producer capabilities remain explicitly unresolved.
- **`build`** captures the snapshot, probes and runs enabled adapters in owned workspaces, constructs navigation and a closed bundle, verifies it, and publishes an immutable release.
- **`verify`** independently checks an existing bundle without executing producers or trusting the producing run.
- **Coverage ingestion** preserves a pre-generated report tree. Optional mapping and attestation sidecars are validated independently; Inspector does not infer either from filenames.
- **Detached signatures** can bind a caller-selected statement and caller-trusted Ed25519 key to one exact verified bundle without modifying it.
- **Process protocol** provides closed, versioned machine results for OSQAr or other callers; human CLI stdout is not used as protocol data.

Read [Using the CLI](https://bitvortex.github.io/OSQAr-Inspector/cli.html) for command behavior and [Design contracts](https://bitvortex.github.io/OSQAr-Inspector/design.html) for exact schemas and failure semantics.

## How it works with OSQAr

OSQAr Inspector is an optional companion, not part of OSQAr core and not a replacement for OSQAr governance.

- **Inspector owns mechanical acquisition and packaging:** source/configuration binding, producer orchestration, byte-preserved artifacts, typed relations, bundle closure, and machine-readable results.
- **OSQAr owns project assurance decisions:** trusted project anchors, requirements and traceability, evidence lifecycle, review, findings, deviations, acceptance, and shipment governance.
- **The handoff is deliberately narrow:** OSQAr independently negotiates supported protocol/schema versions, checks source and configuration identities against its own trust anchors, verifies the exact bundle, and imports no state stronger than mechanically generated or validated candidate records.
- **Current limitation:** Inspector implements the standalone process side of this boundary; the first-class OSQAr adapter and shipment orchestration changes remain future integration work.

The intended sequence and exact responsibility split are in [Integration with OSQAr](https://bitvortex.github.io/OSQAr-Inspector/osqar-integration.html).

## Claim boundary

Inspector reports configured execution and structural, identity, provenance, integrity, and link checks. It does **not** establish evidence adequacy, authenticity without separately governed trust anchors, software or tool qualification, standards compliance, certification, functional safety, security, approval, project acceptance, or fitness for use.

## Documentation

Start with the [documentation home](https://bitvortex.github.io/OSQAr-Inspector/), then move from operation to deeper contracts:

- [Getting started](https://bitvortex.github.io/OSQAr-Inspector/getting-started.html)
- [CLI and operator workflows](https://bitvortex.github.io/OSQAr-Inspector/cli.html)
- [Architecture](https://bitvortex.github.io/OSQAr-Inspector/architecture.html)
- [Design contracts](https://bitvortex.github.io/OSQAr-Inspector/design.html)
- [Integration with OSQAr](https://bitvortex.github.io/OSQAr-Inspector/osqar-integration.html)
- [Detached signatures](https://bitvortex.github.io/OSQAr-Inspector/signatures.html)
- [Release policy](https://bitvortex.github.io/OSQAr-Inspector/release.html)
