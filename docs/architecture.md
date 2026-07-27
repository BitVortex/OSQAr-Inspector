# Architecture

## 1. Status and scope

This document defines the target architecture for OSQAr Inspector. The implemented subset is stated in the repository README; components not listed there remain design targets rather than descriptions of available behavior. Schema names, command shapes, and component boundaries remain provisional until implemented and protected by contract tests.

The first usable integration targets Linux and Python 3.12 or newer. It inspects a reviewed clean Git snapshot, generates or ingests API and coverage artifacts, creates a normalized graph and navigation layer, and publishes a closed bundle for optional OSQAr import.

## 2. Architectural drivers

The architecture is driven by six requirements:

1. **Snapshot identity:** every generated claim about source must be bound to one immutable, completely inventoried snapshot.
2. **Explicit orchestration:** every stage has typed inputs, outputs, status, dependency policy, and failure semantics.
3. **Producer independence:** Doxygen and coverage tools remain external producers behind adapters.
4. **Semantic integration:** cross-navigation uses normalized identities and machine-readable producer mappings, not guessed filenames or generated-HTML rewriting.
5. **Closed publication:** a bundle is not published until its complete inventory, checksums, required entry points, and internal links validate.
6. **Claim restraint:** mechanical validation remains separate from semantic evidence review, qualification, compliance, certification, and safety judgment.

## 3. System context

```text
                     reviewed project/configuration
                                 |
                                 v
+----------------+      +---------------------+      +--------------------+
| Operator or CI |----->| OSQAr Inspector     |----->| Inspection bundle  |
+----------------+      |                     |      | + run report       |
                        | snapshot + pipeline |      +----------+---------+
                        +----+-----------+----+                 |
                             |           |                      |
                     invokes |           | ingests              | typed contract
                             v           v                      v
                        +---------+  +----------+          +-----------+
                        | Doxygen |  | Coverage |          | OSQAr     |
                        +---------+  | artifacts|          | adapter   |
                                     +----------+          +-----+-----+
                                                                  |
                                                                  v
                                                     OSQAr-governed evidence,
                                                     review, gaps, traceability,
                                                     and shipment packaging
```

Inspector is separately installed and separately versioned. OSQAr does not import Inspector implementation internals. The integration boundary is a versioned process protocol plus a closed bundle/report contract.

## 4. Layered decomposition

### 4.1 Interface layer

The CLI parses stable commands and returns defined exit statuses. It delegates to application services and contains no snapshot, producer, graph, or publication logic.

Target commands:

- `plan`: resolve and validate declaratively, without external executable invocation or filesystem mutation except stdout/stderr;
- `build`: execute required and permitted optional stages, validate, and publish;
- `verify`: independently validate an existing closed bundle.

### 4.2 Application orchestration layer

The workflow planner converts resolved configuration and declared capability requirements into a deterministic dependency graph without executing producers. During `build`, the orchestrator probes actual capabilities in owned workspaces, resolves command plans, records each stage result, enforces required/optional policy, and prevents publication after a required-stage failure.

### 4.3 Domain contract layer

This layer owns immutable models and rules for:

- resolved configuration;
- snapshot manifest and identity;
- execution plan;
- stage result and diagnostics;
- artifact and provenance records;
- artifact graph;
- run report;
- bundle manifest and verification result; and
- external publication result and recovery state.

Domain models must not depend on CLI parsing, subprocess APIs, Doxygen, OSQAr, or host-specific publication code.

### 4.4 Adapter layer

Each producer adapter implements the same lifecycle:

1. validate configuration and declare capability requirements without external execution;
2. produce a declarative stage plan;
3. probe capability and version in an owned workspace during `build`;
4. resolve a command plan;
5. execute through the shared process runner;
6. validate expected outputs;
7. inventory artifacts; and
8. emit normalized records and mappings.

The initial adapters are Doxygen and generic coverage ingestion. The OSQAr bridge is a downstream adapter, not a producer adapter.

### 4.5 Infrastructure layer

Infrastructure services implement streaming hashing, canonical JSON, deterministic path handling, snapshot materialization, owned workspaces, subprocess execution, log redaction, HTML/URI validation, and atomic Linux publication.

## 5. Pipeline

```text
resolve configuration + exact identity components
        |
        v
capture + materialize snapshot -----> snapshot manifest
        |
        v
create declarative plan
        |
        v
probe capabilities in owned workspaces
        |
        v
run producers in isolated workspaces
        |
        v
ingest + validate producer outputs
        |
        v
build normalized artifact graph
        |
        v
render separate navigation layer
        |
        v
validate closed candidate bundle
        |
        v
atomically publish immutable release + update current pointer
```

The snapshot is verified before producer execution and reverified afterward using the complete sorted record set. Producers never inspect the live project after capture.

## 6. Core components

### Configuration resolver

- validates a versioned configuration schema;
- rejects unknown fields outside declared extension namespaces;
- applies precedence `defaults < configuration file < CLI override`;
- produces exact controlled-input, schema/default-set, explicit-override, and resolved-semantic identity components;
- includes every validated configuration field in identity, treats redaction as presentation only, and forbids v1 hidden behavior-affecting values; and
- performs no generator templating or project mutation.

### Snapshot service

The first integration accepts only a clean Git worktree whose commit and tree can be independently recorded. The service enumerates the exact selected tree, materializes it in an owned execution directory, records file kind/mode/size/digest, and rejects capture races or unsupported entries.

Dirty Git and non-Git modes may be designed later for exploratory use, but they must never masquerade as a reviewed Git revision.

### Workflow planner

The planner represents each stage as a node with statically decidable prerequisites, required/optional policy, adapter selector and declared version constraint, owned-workspace requirement, expected outputs, and publication effect. Public planning executes no producer; runtime availability remains explicitly unresolved. During `build`, capability probes run only through the process runner in owned workspaces, and an unsatisfied required capability blocks producer execution and publication.

### Workspace manager and process runner

Every run and stage receives an owned path outside the source project. Commands are argument vectors, never shell-concatenated strings. Results record exit status, timeout, duration, executable version, redacted arguments, stdout/stderr paths, and output validation. Existing files cannot satisfy a new stage.

### Doxygen adapter

The initial producer adapter generates configuration in its stage workspace and requests HTML plus XML and/or a tag file. Machine-readable output provides compound/member IDs, normalized source paths, declarations, pages, and anchors. Duplicate or ambiguous mappings fail ingestion; the adapter never guesses a Doxygen HTML filename.

### Generic coverage adapter

The initial coverage path ingests a pre-generated report. A mapping sidecar may bind report pages to normalized source paths. A separate attestation may bind report bytes to source snapshot, tests, instrumentation, configuration, and producer identity. Mapping and provenance are independent: either can be absent without being guessed.

### Artifact graph

Graph nodes represent snapshot, source files, symbols when known, producer artifacts, API pages, coverage pages/summaries, logs, and stage results. Every node has a deterministic identifier. Edges are typed and validated; ambiguous identities are rejected.

### Renderer

The renderer creates only Inspector-owned integration pages. It links to byte-preserved producer artifacts and visibly presents succeeded, failed, blocked, skipped, and degraded stages plus provenance state. It does not rewrite Doxygen or coverage HTML.

### Bundle validator and publisher

The validator requires an exact closed inventory, canonical manifest, checksum file, expected entry points, non-empty payloads, and resolvable internal links. The bundle ID is derived only after all payloads, the manifest, and the checksum file are final; no payload embeds that final ID. Publication writes an immutable versioned release and atomically replaces a `current` pointer only after validation. An external publication result binds the bundle ID to the run-report digest without entering the bundle. A closed top-level state machine distinguishes no attempt, definite pre-commit failure, commit-indeterminate, durable success, recovered durable success, recovered no-commit, and blocked recovery; each state has a defined exit class and OSQAr policy.

### OSQAr bridge

The bridge invokes or verifies Inspector through a versioned process and bundle contract. It confirms source/configuration bindings, imports candidate records without approval, keeps the Inspector bundle byte-identical, and includes it inside OSQAr’s outer shipment integrity boundary. See [OSQAr integration](osqar-integration.md).

## 7. Dependency rules

- CLI depends on application services, not concrete producers.
- The orchestrator depends on domain contracts and adapter interfaces.
- Concrete adapters depend on domain contracts and infrastructure.
- Renderers depend on the artifact graph, never subprocess state.
- The OSQAr bridge depends on the public process/bundle contract, never Inspector internals.
- Inspector must not import OSQAr lifecycle or approval logic.
- Producer adapters must not import CLI parsing code.

## 8. Invariants

The following are publication-blocking invariants:

1. All producer stages consume the same materialized snapshot.
2. The complete snapshot inventory is equal before and after producer execution.
3. A required stage has status `succeeded`.
4. Every bundle payload is listed exactly once and matches its digest.
5. No unlisted regular file exists in the release.
6. Every internal link resolves inside the candidate bundle.
7. Producer artifacts remain byte-identical after ingestion.
8. No credential appears in configuration snapshots, logs, manifests, or rendered pages.
9. An artifact’s provenance is not upgraded merely because it was copied in the current run.
10. Inspector never emits organization-specific approval.

## 9. Failure model

Stage status is one of `succeeded`, `failed`, `blocked`, `skipped`, or `degraded`.

Publication state is separate from stage status and follows the closed state machine in [Design contracts](design.md#publication-result-and-state-machine).

- A required stage not in `succeeded` blocks publication and returns non-zero.
- An optional stage may be skipped or degraded only when policy permits and the final index reports it prominently.
- Zero process exit with missing or malformed required output is failure.
- Existing/stale output is never accepted as current-run output.
- A failed candidate never replaces the current published bundle.
- Recovery never infers publication from an unpointed candidate directory.
- Zero exit is permitted only after a durable or recovered-durable publication of the requested exact bundle.

## 10. Deployment and portability

The first supported deployment is a locally installed Python CLI on Linux. External producers are discovered at runtime and remain optional unless selected as required stages. Network access is not required for ordinary deterministic operation.

macOS and Windows support require native acceptance lanes before being claimed. Windows publication semantics remain an explicit design decision because the first atomic publication protocol is Linux-specific.

## 11. Architecture decisions and deferred scope

Accepted initial decisions:

- Python 3.12 or newer;
- standard `pyproject.toml` packaging and `uv` workflow;
- UTF-8 JSON with RFC 8785 canonicalization;
- SHA-256 lowercase hexadecimal digests;
- standard-library `argparse` unless a dependency is justified;
- Markdown documentation; and
- Linux-first CI.

Deferred until the core contracts are stable:

1. automated CMake or Meson coverage execution;
2. clang-uml and PlantUML integration; and
3. deterministic source-comment proposal and transactional application.

## 12. Verification strategy

Tests are layered:

- **unit:** canonicalization, identities, state rules, path normalization, graph rules;
- **contract:** each adapter against fake executables and malformed outputs;
- **integration:** real Doxygen and controlled coverage fixtures;
- **end-to-end:** installed CLI outside the checkout, immutable source fixture, complete publication, independent verify, and OSQAr handoff.

Every external adapter must cover missing executable, unsupported version, non-zero exit, timeout, zero exit with missing output, malformed output, stale output, redaction, and cleanup failure. A fake producer that writes a cache during `--version` must prove that public `plan` never invokes it and that runtime probing confines the write to an owned build workspace. Publication tests cover every state and fault boundary separately from stage states.
