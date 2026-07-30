# Release policy

This document defines the tested package-compatibility boundary for OSQAr Inspector. The machine-readable source of truth is `src/osqar_inspector/resources/release-policy-v1.json`; every wheel and source distribution includes it and the release gate verifies its bound contract-asset digests.

## Supported set

- **Operating system:** Linux. Non-Linux publication is not advertised because no native release lane exists.
- **Python:** Python 3.12 and 3.13. Other Python versions are outside the advertised support set.
- **Process protocol:** `osqar-inspector-run-v1`.
- **Commands:** `capabilities`, `plan`, `build`, and `verify`.
- **Package version:** `0.1.0`.
- **Fixture revision:** `1`.

The supported v1 schema identifiers are:

- `osqar.inspector.artifact-graph.v1`
- `osqar.inspector.build-process-result.v1`
- `osqar.inspector.bundle-manifest.v1`
- `osqar.inspector.capabilities-result.v1`
- `osqar.inspector.config.v1`
- `osqar.inspector.configuration.interoperability.v1`
- `osqar.inspector.coverage-attestation.v1`
- `osqar.inspector.coverage-inventory.v1`
- `osqar.inspector.coverage-map.v1`
- `osqar.inspector.coverage-report-tree.v1`
- `osqar.inspector.detached-signature.v1`
- `osqar.inspector.doxygen-artifact.v1`
- `osqar.inspector.doxygen-mapping.v1`
- `osqar.inspector.plan-process-result.v1`
- `osqar.inspector.plan.v1`
- `osqar.inspector.protocol-error.v1`
- `osqar.inspector.publication-result.v1`
- `osqar.inspector.release-policy.v1`
- `osqar.inspector.run.v1`
- `osqar.inspector.signature-vector.v1`
- `osqar.inspector.snapshot.v1`
- `osqar.inspector.stage-result.v1`
- `osqar.inspector.verify-process-result.v1`

## Contract-change rule

A change to a public schema, defaults file, protocol contract, or interoperability fixture requires all of the following in the same change:

1. update the package version according to the compatibility effect;
2. increment `fixture_revision`;
3. update or add the canonical interoperability fixture and its digest binding;
4. update the supported schema/protocol sets when applicable;
5. add a changelog entry describing the compatibility effect.

The release gate fails closed when packaged assets are absent, fixture digests differ, package metadata contradicts the policy, or a contract-change comparison lacks both the package-version and fixture-revision updates.

## Release checklist

Run from a clean Linux checkout:

```sh
rm -rf dist
uv sync --locked
uv build
uv run pytest -q
uv run python -m osqar_inspector.release_gate dist/*
uv run python tests/probes/installed_package.py dist/*.whl
CI=1 uv run pytest -q tests/integration/test_doxygen.py
sha256sum dist/*.whl dist/*.tar.gz > SHA256SUMS
```

Before publishing, verify that:

1. CI passed on Python 3.12 and 3.13 from clean checkouts;
2. the real-Doxygen lane passed on Linux;
3. the wheel probe executed outside the checkout and exercised planning, building, verification, publication recovery, detached signatures, and process-result conformance;
4. wheel and sdist package names, versions, and contents agree with this policy;
5. `CHANGELOG.md` contains the release entry; and
6. the published wheel, sdist, and `SHA256SUMS` bytes match the locally verified artifacts.

## Claim boundary

A passing release gate establishes package integrity and tested compatibility for the listed set. It does not establish project suitability, evidence adequacy, tool qualification, standards compliance, certification, functional safety, security, approval, or fitness for use.
