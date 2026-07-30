---
layout: default
title: Getting started
---

# Getting started

This chapter walks through the smallest supported standalone workflow: configure one clean Git project, create a side-effect-free plan, build and publish an inspection bundle, and verify the published release.

## Prerequisites

The advertised support set is:

- Linux;
- Python 3.12 or 3.13;
- [uv](https://docs.astral.sh/uv/); and
- Doxygen when the default required Doxygen stage is enabled.

The inspected project must be a Git worktree with no uncommitted tracked changes or disallowed untracked files. Commit the Inspector configuration, selected source, and producer configuration before planning or building.

## Install for development or evaluation

```sh
git clone https://github.com/BitVortex/OSQAr-Inspector.git
cd OSQAr-Inspector
uv sync --locked
```

The commands below run the package from this locked environment. Published package installation is not yet the recommended path for the alpha repository.

## Create the configuration

Create `inspector.json` in the project to inspect:

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

The controlled file is recursively merged over packaged defaults and then explicit CLI overrides are applied. With the example above, the effective defaults still:

- require a clean Git project;
- enable Doxygen as a required stage;
- read `Doxyfile` from the project;
- place Doxygen output at `build/doxygen` within the owned snapshot workspace; and
- disable coverage ingestion.

`project.include` must identify the tracked source and producer-input content needed by the enabled stages. The example selects `Doxyfile` because the Doxygen adapter reads it from the materialized snapshot. Use an empty list only when you intentionally want the default full-selection policy. Configuration paths are normalized project-relative paths; absolute paths, `..`, backslashes, and non-normalized forms are rejected.

Commit `inspector.json`, `Doxyfile`, and the selected source before continuing.

## Plan

Run from the Inspector checkout:

```sh
uv run osqar-inspector plan \
  --project /path/to/project \
  --configuration inspector.json
```

`plan` validates the controlled configuration, computes all configuration-identity components, captures the clean-Git snapshot identity, and emits canonical `osqar.inspector.plan.v1` JSON.

Planning deliberately does **not**:

- execute Doxygen or another producer;
- probe executable versions or availability;
- materialize the source snapshot;
- create a stage workspace; or
- write project or publication files.

A nonzero exit indicates a statically known blocking prerequisite or invalid input. Runtime producer capability remains unresolved until `build`.

## Build

```sh
uv run osqar-inspector build \
  --project /path/to/project \
  --configuration inspector.json
```

`build` re-resolves the controlled inputs, captures and materializes the snapshot, probes enabled adapters in owned workspaces, executes the stage plan, constructs the artifact graph and navigation, closes the exact bundle, independently verifies it, and publishes it beneath `publication.destination`.

Successful stdout is canonical `osqar.inspector.publication-result.v1` JSON. Important fields include:

- `state`: `durable-success` or `recovered-durable-success` for exit zero;
- `bundle_id`: the verified bundle identity;
- `release_path`: the immutable path relative to the publication destination; and
- `run_report_sha256`: the digest binding the external publication result to the in-bundle run report.

For the example destination, the complete release path is:

```text
/path/to/project/build/osqar-inspector/<release_path>
```

The publication root also contains the sole `current` commit pointer. Consumers should still retain and verify the exact immutable release identity rather than treating a mutable pointer lookup as evidence.

## Verify

Use the `release_path` returned by `build`:

```sh
uv run osqar-inspector verify \
  --bundle /path/to/project/build/osqar-inspector/releases/<bundle-id>
```

On success, `verify` prints deterministic JSON containing `valid: true` and the recomputed `bundle_id`. It checks exact inventory equality, payload and control-file digests, the run report, required entry points, and internal HTML links and fragments. It does not execute producers or fetch external links.

On failure, the command exits nonzero and writes deterministic JSON containing `valid: false` and a typed diagnostic to standard error.

## Optional: disable producers for a structural pipeline trial

To exercise configuration, snapshot, navigation, bundle closure, publication, and verification without Doxygen, explicitly disable the stage:

```json
{
  "schema": "osqar.inspector.config.v1",
  "stages": {
    "doxygen": {
      "enabled": false,
      "required": false
    }
  }
}
```

This is a mechanical pipeline trial, not an API-documentation inspection. The resulting run report visibly records the configured stage policy.

## Next steps

- Read [CLI and operator workflows](cli.html) for overrides, coverage ingestion, exit states, and operational constraints.
- Read [Integration with OSQAr](osqar-integration.html) before designing a downstream handoff.
- Read [Architecture](architecture.html) for system boundaries and [Design contracts](design.html) for exact identities and schemas.
