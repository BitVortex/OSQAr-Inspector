---
layout: default
title: OSQAr Inspector documentation
---

# OSQAr Inspector documentation

OSQAr Inspector creates deterministic, independently verifiable inspection bundles from reviewed clean-Git projects. This documentation begins with the operator workflow and separates deeper architecture, contract, integration, and release material into focused chapters.

> **Status:** Alpha (`0.1.0`). Standalone inspection and the versioned process handoff are implemented. The OSQAr-side adapter and automatic shipment import are specified future work.

## Start here

- [Getting started](getting-started.html) — prerequisites, minimal configuration, first plan/build/verify cycle, and expected outputs.
- [CLI and operator workflows](cli.html) — command behavior, overrides, coverage ingestion, publication states, and recovery constraints.

## Use the tool

A normal standalone workflow is:

1. select and commit the source and controlled Inspector configuration;
2. run `plan` to validate static prerequisites without invoking producers;
3. run `build` to acquire artifacts in owned workspaces and publish a verified release; and
4. run `verify` against the exact immutable release before consumption.

For downstream assurance workflows, read [Integration with OSQAr](osqar-integration.html). It identifies what Inspector supplies, what OSQAr must verify independently, and which integration work remains unimplemented.

## Understand the contracts

- [Architecture](architecture.html) — system context, layers, pipeline, invariants, and failure model.
- [Design contracts](design.html) — configuration, snapshot, plan, stage, graph, bundle, publication, and process contracts.
- [Detached signatures](signatures.html) — exact signed bytes, trust processing, result types, and interoperability data.
- [Release policy](release.html) — supported platform/package set, compatibility rules, and release gates.

## Interpretation boundary

Inspector establishes only the mechanical properties represented by its typed results and verifiers. It does not establish evidence adequacy, authenticity without separately governed trust anchors, approval, software or tool qualification, standards compliance, certification, functional safety, security, project acceptance, or fitness for use.

[Repository](https://github.com/BitVortex/OSQAr-Inspector) · [OSQAr](https://github.com/BitVortex/OSQAr)
