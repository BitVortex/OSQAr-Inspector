---
layout: default
title: CLI and operator workflows
---

# CLI and operator workflows

The human CLI exposes `plan`, `build`, and `verify`. A separate versioned process mode supplies closed machine results to OSQAr or another caller. Do not parse ordinary human stdout as the integration protocol.

## Common command shape

```text
osqar-inspector plan  --project <path> --configuration <project-relative-file>
osqar-inspector build --project <path> --configuration <project-relative-file>
osqar-inspector verify --bundle <path>
```

The configuration path is relative to the inspected project. `plan` and `build` resolve the same controlled file, packaged defaults, and explicit overrides.

## `plan`: validate before execution

Use `plan` in review or CI before allowing producer execution:

```sh
uv run osqar-inspector plan \
  --project /path/to/project \
  --configuration inspector.json
```

It emits canonical `osqar.inspector.plan.v1` JSON. A required prerequisite that can be evaluated without a runtime probe blocks the plan and returns nonzero. Producer availability and version remain unresolved by design.

## `build`: acquire, close, verify, and publish

```sh
uv run osqar-inspector build \
  --project /path/to/project \
  --configuration inspector.json
```

Build performs runtime probes and stage execution only in Inspector-owned workspaces. Required-stage failure blocks publication. Existing files cannot satisfy a new stage, and producer output must match the declared current-run inventory.

Exit zero is limited to publication state `durable-success` or `recovered-durable-success`. Closed nonzero states use exit codes 10–14; see the [publication state machine](design.html#publication-result-and-state-machine) for exact meanings.

### Linux publication assumptions

The durability protocol assumes a local Linux filesystem assessed to satisfy the documented atomic same-filesystem replacement and file/directory `fsync` assumptions. Network and synthetic filesystems require separate assessment.

After an unexpected storage or synchronization error, do not automatically retry. Re-establish the filesystem assumptions first. A later `build` invocation asserts that this external operator action occurred; startup reconciliation can verify observable publication state but cannot establish device health.

## `verify`: consume an exact immutable release

```sh
uv run osqar-inspector verify --bundle /absolute/path/to/release
```

Verification independently checks the closed bundle and never executes a producer. External HTML references are not fetched. A successful result establishes the implemented structural and integrity checks only; it is not evidence approval.

## Typed overrides

Overrides accept either one `JSON_POINTER=JSON_VALUE` argument or separate pointer and JSON-value arguments:

```sh
uv run osqar-inspector plan \
  --project /path/to/project \
  --configuration inspector.json \
  --override '/doxygen/warnings_as_errors=true'

uv run osqar-inspector plan \
  --project /path/to/project \
  --configuration inspector.json \
  --override /stages/coverage/enabled true
```

Values are parsed as JSON, not strings by default. Override pointers must use the canonical JSON Pointer profile. Duplicate and ancestor/descendant pointer combinations are rejected rather than made order-dependent.

Do not place credentials, tokens, or protected values in controlled configuration, extension objects, or overrides. V1 commits the complete resolved semantic object and explicit override records to identity.

## Coverage ingestion

Inspector ingests a pre-generated coverage report; it does not run a coverage producer. Configure:

- `coverage.report` for the report entry point;
- optional `coverage.mapping` to connect exact report targets to exact selected source paths; and
- optional `coverage.attestation` to bind the report tree to snapshot, configuration, producer, and test identities.

Mapping and provenance are independent. A valid mapping does not prove provenance. Without a matching independently supplied attestation, provenance remains `unknown-origin`. Sidecars must be outside the report-tree root and are preserved as exact evidence artifacts.

The exact sidecar schemas and tree-closure rules are in [Design contracts](design.html#11-coverage-ingestion-design).

## Machine-process handoff

Protocol callers use `osqar-inspector-run-v1`, negotiate exact supported schemas, provide a caller-owned result file, and read only the canonical JSON bytes from that file. The supported operations are `capabilities`, `plan`, `build`, and `verify`.

The protocol defines bounded result-file and console handling, caller-owned run identity, process timeout, descendant cleanup, closed result objects, and result/exit agreement. See [Integration with OSQAr](osqar-integration.html#6-process-protocol) for the exact argument vectors and caller obligations.

## Detached signatures

Bundle signing is currently a library interface, not a CLI command. It leaves the bundle unchanged and binds a caller-selected statement to the exact verified bundle. Trust is supplied only by the caller's key mapping; an embedded public key is not a trust anchor. See [Detached signatures](signatures.html).

## Troubleshooting order

1. Confirm the project is a clean Git worktree and selected paths are tracked.
2. Run `plan` and resolve configuration or static prerequisite diagnostics.
3. Confirm required producer executables are available in the build environment.
4. Run `build` once and retain its complete typed publication result.
5. If storage or synchronization failed, re-establish the documented filesystem assumptions before another invocation.
6. Verify the exact returned immutable release path independently.

Do not weaken required-stage policy or provenance expectations merely to obtain exit zero; any intentional relaxation belongs in reviewed project policy.
