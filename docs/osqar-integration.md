# Integration with OSQAr

## 1. Purpose and baseline

OSQAr Inspector is an optional evidence-acquisition companion to [OSQAr](https://github.com/BitVortex/OSQAr). It is not an OSQAr replacement and is not installed as part of the OSQAr core package by default.

This design was checked against public OSQAr commit [`59aa0a6d9d754b47bd636c4ff7507d2f6997fadf`](https://github.com/BitVortex/OSQAr/tree/59aa0a6d9d754b47bd636c4ff7507d2f6997fadf), the immediate child of the annotated `v0.10.2` tag target `4003c4041d7cb273bec78d95fb8980b2d0bb013f`. The cited integration-relevant files are byte-identical to the `v0.10.2` tag; the child changes only README navigation and its documentation-navigation test. `osqar shipment prepare` already exists in both baselines. The new targets are `osqar inspect`, the typed `inspection` configuration and adapter, and modification of existing shipment-preparation orchestration to invoke that adapter before final checksums.

## 2. Responsibility split

### OSQAr Inspector owns

- capture and complete verification of an immutable source snapshot;
- producer capability discovery and orchestration;
- Doxygen and coverage artifact acquisition/ingestion;
- producer logs and mechanical stage results;
- normalized source/artifact identities and relations;
- integration navigation that leaves producer bytes unchanged;
- closed bundle manifests and checksums; and
- machine-readable run and provenance reports.

### OSQAr owns

- the trusted project source and configuration anchors;
- requirements, architecture, verification, implementation, and standards-claim models;
- evidence lifecycle and typed traceability;
- project/organization-specific applicability and acceptance policy;
- human review, approval, gaps, deviations, and findings;
- tool-reliance and qualification decisions; and
- final shipment assembly, integrity, intake, and governance.

### Neither tool establishes by itself

- evidence adequacy;
- software-component or tool qualification;
- standards compliance or certification;
- functional safety; or
- fitness for use.

## 3. Why a first-class adapter is required

The cited integration surfaces, which are byte-identical in OSQAr `v0.10.2` and commit `59aa0a6d9d754b47bd636c4ff7507d2f6997fadf`, provide project hooks around `shipment.prepare` and execute configured commands without an implicit shell. This is useful for experiments, but it is not the final integration contract:

- project configuration currently ignores unknown keys rather than validating an Inspector schema;
- hooks communicate primarily through command exit status and environment paths;
- hooks do not negotiate protocol/schema versions;
- hooks do not validate Inspector bundle closure, snapshot identity, provenance, or stage policy; and
- a post-prepare hook runs after OSQAr has announced the shipment as ready, which is too late for governed evidence acquisition.

Relevant OSQAr baseline surfaces:

- [CLI command registration](https://github.com/BitVortex/OSQAr/blob/59aa0a6d9d754b47bd636c4ff7507d2f6997fadf/tools/osqar_cli.py#L34-L57)
- [`shipment prepare` orchestration](https://github.com/BitVortex/OSQAr/blob/59aa0a6d9d754b47bd636c4ff7507d2f6997fadf/tools/osqar_cmd_shipment.py#L644-L929)
- [project configuration and hook execution](https://github.com/BitVortex/OSQAr/blob/59aa0a6d9d754b47bd636c4ff7507d2f6997fadf/tools/osqar_cli_util.py#L129-L215)
- [OSQAr evidence-state boundary](https://github.com/BitVortex/OSQAr/blob/59aa0a6d9d754b47bd636c4ff7507d2f6997fadf/docs/evidence_acceptance.rst#L1-L81)

The production design therefore adds an OSQAr-owned adapter and validator. A temporary hook-based spike may test operator ergonomics, but its output cannot be treated as the final typed integration.

## 4. Intended operator experience

Standalone use remains available:

```text
osqar-inspector plan --project . --configuration inspector.json
osqar-inspector build --project . --configuration inspector.json
osqar-inspector verify --bundle <bundle>
```

OSQAr integration adds the new `osqar inspect` command and extends the existing `osqar shipment prepare` command:

```text
osqar inspect --project .
osqar shipment prepare --project .
```

`osqar shipment prepare` is not a new command; its current baseline implementation is cited above. Future integration modifies its orchestration so that, when inspection is enabled, it invokes the separately installed provider through the first-class adapter before final checksums. When disabled or absent from configuration, existing OSQAr projects behave as before.

## 5. Proposed OSQAr configuration surface

The reserved top-level namespace is `inspection`. This example is illustrative and not yet a supported schema:

```json
{
  "inspection": {
    "enabled": true,
    "provider": "osqar-inspector",
    "protocol": "osqar-inspector-run-v1",
    "required": true,
    "configuration": "inspector.json",
    "import": {
      "bundle": true,
      "candidate_records": true
    }
  }
}
```

Design rules:

- OSQAr validates this block under its own project-configuration contract.
- `configuration` is project-relative; OSQAr hashes its exact controlled bytes and independently computes the schema/default-set, explicit-override, and resolved-semantic identity components defined by the shared contract fixtures.
- `provider` selects an installed adapter; it is not an arbitrary shell command.
- `required: true` means any unavailable provider, unsupported protocol, Inspector failure, or invalid bundle stops shipment preparation.
- Optional inspection may permit shipment preparation only with a prominent recorded skipped/degraded state.
- No configuration option allows Inspector to set evidence to `approved`.

## 6. Process protocol

OSQAr invokes Inspector using argument vectors and an owned staging directory. The protocol must provide:

1. a machine-readable capability/version handshake;
2. explicit supported run-report and bundle schema sets;
3. a side-effect-free plan request that executes no external producer or capability probe;
4. a build request bound to project and configuration inputs;
5. a machine-readable final result on a dedicated output channel or file;
6. defined exit statuses; and
7. no dependence on parsing human console prose.

Reserved format identifier:

```text
osqar-inspector-run-v1
```

OSQAr must reject unsupported versions rather than attempting permissive interpretation.

### `osqar-inspector-run-v1` argv

The reference caller uses these exact argument vectors (each bracketed value is
one argument; no shell is involved):

```text
[osqar-inspector] [capabilities]
  [--protocol] [osqar-inspector-run-v1]
  [--result-file] [<caller-owned-path>]

[osqar-inspector] [plan]
  [--protocol] [osqar-inspector-run-v1]
  [--result-schema] [osqar.inspector.plan-process-result.v1]
  [--result-file] [<caller-owned-path>]
  [--project] [<absolute-project-path>]
  [--configuration] [<project-relative-controlled-path>]

[osqar-inspector] [build]
  [--protocol] [osqar-inspector-run-v1]
  [--result-schema] [osqar.inspector.build-process-result.v1]
  [--result-file] [<caller-owned-path>]
  [--project] [<absolute-project-path>]
  [--configuration] [<project-relative-controlled-path>]
  [--run-id] [<caller-owned-run-id>]

[osqar-inspector] [verify]
  [--protocol] [osqar-inspector-run-v1]
  [--result-schema] [osqar.inspector.verify-process-result.v1]
  [--result-file] [<caller-owned-path>]
  [--bundle] [<absolute-bundle-path>]
```

The existing standalone argv without `--protocol`, `--result-schema`, and
`--result-file` remains a human CLI. Its stdout/stderr is not protocol data.
Protocol callers read only the exact canonical JSON bytes in `--result-file`.
The caller must supply a path that does not exist; Inspector creates it and
never replaces an existing file or symbolic link. The reference caller accepts
the returned object only when no symbolic link was followed and the opened
result is a singly linked regular file, excluding hard-linked pre-existing
content. Producer and reference caller retain an opened descriptor for the
caller-owned parent directory and perform result creation/opening relative to
that descriptor; the caller rejects parent-directory substitution during
execution. The reference caller uses a finite configurable process timeout
(300 seconds by default), retains at most the first 1 MiB of each console
stream, and rejects result files larger than 16 MiB. Its Linux subprocess
supervisor acts as a child subreaper and kills and reaps producer descendants,
including descendants that create a new session, before accepting a result. For
`plan`, the result file
is the sole requested filesystem output and
must be outside the inspected project, so producer probing and project-tree
mutation remain prohibited.

### Capability and result contracts

The capability result is the closed
`osqar.inspector.capabilities-result.v1` object with exactly
`inspector_version`, `protocol`, `schema`, and `supported_schemas`.
`supported_schemas` has exactly these singleton sets:

```json
{
  "bundle": ["osqar.inspector.bundle-manifest.v1"],
  "config": ["osqar.inspector.config.v1"],
  "plan": ["osqar.inspector.plan.v1"],
  "publication-result": ["osqar.inspector.publication-result.v1"],
  "run-report": ["osqar.inspector.run.v1"],
  "signature-envelope": ["osqar.inspector.detached-signature.v1"],
  "snapshot": ["osqar.inspector.snapshot.v1"],
  "stage-result": ["osqar.inspector.stage-result.v1"]
}
```

All process-result objects are closed:

- `plan-process-result.v1` contains exactly `configuration_identity`,
  `diagnostics`, `plan`, `protocol`, `schema`, `source`, and `status`.
  `status` is `succeeded`, `blocked`, or `failed`. Successful and blocked
  results carry the complete config-v1 identity and the snapshot Git source
  object; failed results carry null bindings.
- `build-process-result.v1` contains exactly `configuration_identity`,
  `protocol`, `publication`, `schema`, `source`, and `status`. A successful
  result carries the complete config-v1 identity, Git commit/tree source
  object, and the closed publication-result-v1 object.
- `verify-process-result.v1` contains exactly `bundle_id`, `diagnostics`,
  `protocol`, `schema`, `status`, and `valid`.
- Pre-dispatch version rejection uses the closed
  `osqar.inspector.protocol-error.v1` object with exactly `diagnostics`,
  `protocol`, `schema`, and `status`.

Diagnostic objects are closed: they contain string `code` and `message`
members and may contain one string `path` member identifying an associated
failure location or the offending path value. No other diagnostic members are
accepted.

Canonical means the same RFC 8785 profile used by Inspector configuration and
identity records, with no trailing newline. Duplicate members, extra members,
noncanonical bytes, unsupported schemas/protocols, and result/exit
disagreement are rejected.

Exit `0` means only: a successful plan, successful verification, or a build
whose publication state is `durable-success` or
`recovered-durable-success`. Plan/verify failure uses `1`; protocol negotiation
rejection uses `2`. Build publication exits are closed by state:
`not-attempted=10`, `definite-pre-commit-failure=11`,
`commit-indeterminate=12`, `recovered-no-commit=13`, and
`recovery-blocked=14`. Console prose cannot change any of these decisions.
For ordinary build states, the publication result `run_id` must equal the
caller-owned `--run-id`; validation rejects an ordinary result if that expected
caller identity is omitted. Reconciliation states use the reserved value
`recovery` and are rejected with any other run identity. A caller-owned run ID
must be one non-empty path component: the reserved `recovery` value, `.`, `..`,
slash, backslash, and NUL are rejected during protocol negotiation before build
dispatch.

## 7. Integrated preparation sequence

The intended sequence is:

1. **Load trusted OSQAr configuration.** Validate the `inspection` declaration and determine required/optional policy.
2. **Establish OSQAr trust anchors.** Resolve the reviewed source revision, exact controlled configuration bytes/path, schema/default-set identity, and explicit overrides independently of Inspector output.
3. **Plan inspection.** Ask Inspector for its deterministic declarative plan; reject statically unsatisfied required prerequisites before ordinary shipment mutation while retaining runtime capabilities as unresolved.
4. **Build in an owned stage.** Inspector probes runtime capabilities in owned workspaces, blocks incompatible required capabilities before producer execution, captures the source snapshot, runs producers, validates the graph/bundle, and publishes an immutable Inspector release in an OSQAr-owned staging root.
5. **Validate the handoff.** The OSQAr adapter independently verifies the Inspector bundle and run report under supported contract versions.
6. **Bind identity.** Confirm the Inspector snapshot commit/tree and every configuration-identity component correspond to the independently computed OSQAr trust anchors and declaration.
7. **Derive candidate records.** Map validated Inspector artifacts to OSQAr candidate implementation/evidence records. The initial state is no stronger than `generated` or mechanically `validated`; never `approved`.
8. **Build OSQAr documentation and traceability.** OSQAr renders its own summary and references the imported candidate records without changing the Inspector bundle.
9. **Include the bundle.** Copy the exact closed Inspector bundle beneath a stable OSQAr shipment path such as `inspection/<bundle-id>/`.
10. **Run OSQAr gates.** Execute OSQAr traceability, gap/deviation, evidence-state, doctor, and checksum stages under OSQAr policy.
11. **Publish the OSQAr shipment.** The outer OSQAr integrity inventory includes every Inspector bundle byte; Inspector’s inner closure remains independently verifiable.

Inspector must complete before OSQAr’s final checksum generation. No adapter or hook may mutate the OSQAr shipment afterward without regenerating and reverifying the outer integrity inventory.

## 8. Identity binding

Inspector and OSQAr use related but distinct identities:

- OSQAr’s trusted source revision remains the reviewing caller’s anchor.
- Inspector’s snapshot ID binds the Git commit/tree plus the complete selected source-file inventory and relevant input identities.
- OSQAr validates that the Inspector Git identity equals the reviewed source revision and that the selected content policy is the one declared by the project.
- OSQAr independently computes and checks the exact controlled-input, schema/default-set, explicit-override, and resolved-semantic configuration identity components using shared interoperability fixtures; it does not reproduce identity by trusting Inspector-reported values.
- An Inspector run or artifact is not accepted merely because its own report repeats expected values.

Trust anchors must be supplied or derived by OSQAr independently; they must not be copied from the artifact being validated.

## 9. Evidence-state mapping

### Inspector stage and artifact states

- `succeeded` records mechanical producer/validation success.
- `failed` or `blocked` prevents import as valid current evidence.
- `skipped` and `degraded` remain visible limitations.
- `verified-current-snapshot`, `externally-attested`, and `unknown-origin` describe provenance strength.

### OSQAr lifecycle mapping

- Valid Inspector output may create a candidate `generated` record.
- Independent schema, identity, digest, and closure checks may support a `validated` mechanical state.
- `approved` requires an OSQAr-governed human or organizational disposition.
- Superseded source/configuration invalidates or supersedes the binding; it is not silently refreshed.

A mechanical Inspector PASS cannot satisfy OSQAr evidence acceptance by itself. OSQAr’s current public boundary explicitly separates generated/package state from approval and semantic adequacy.

## 10. Failure policy

Required inspection blocks shipment preparation when:

- the provider is absent or its version is unsupported;
- plan prerequisites are unsatisfied;
- Inspector returns non-zero;
- Inspector publication is anything other than independently reverified `durable-success` or `recovered-durable-success` for the requested bundle;
- a required Inspector stage is not `succeeded`;
- bundle or checksum verification fails;
- the bundle contains extra, missing, duplicate, escaping, or altered content;
- source or configuration identity does not match OSQAr trust anchors;
- provenance is weaker than project policy permits; or
- imported identities are ambiguous.

Optional inspection may continue only when OSQAr policy explicitly permits the observed state and the shipment visibly records the limitation. Silent fallback is prohibited.

## 11. Packaging boundary

Inspector publishes its own immutable closed bundle. OSQAr treats that bundle as an opaque, byte-preserved subtree plus validated typed metadata. OSQAr may render links and summaries outside the subtree but must not edit Inspector payloads.

The final OSQAr shipment has nested integrity:

- the inner Inspector manifest proves closure under the Inspector bundle contract; and
- the outer OSQAr checksum inventory binds the exact Inspector bytes into the governed shipment.

These integrity checks do not establish authenticity unless a separate signature/trust mechanism is applied.

## 12. Integration acceptance tests

The OSQAr adapter is not complete until tests cover:

- inspection disabled preserves existing behavior;
- required provider absent;
- protocol too old, too new, or malformed;
- plan reports a statically unsatisfied required prerequisite without executing a producer;
- build reports a missing or incompatible required runtime capability from an owned probe workspace before producer execution;
- Inspector non-zero exit;
- successful API-only bundle;
- generic coverage with valid attestation;
- unknown-origin coverage remains visibly unbound;
- snapshot commit/tree mismatch;
- controlled configuration path/bytes, schema/default-set, override, or one-field resolved-semantic mutation;
- every publication state and exit mapping, including indeterminate and blocked recovery;
- altered payload, altered manifest, extra file, and missing file;
- required stage degraded/skipped/failed;
- no Inspector artifact is imported as approved;
- Inspector subtree remains byte-identical after OSQAr packaging;
- outer shipment checksum includes every Inspector byte; and
- installed OSQAr and Inspector packages interoperate outside either source checkout.

## 13. Migration strategy

1. Stabilize Inspector’s standalone contracts and bundle verifier.
2. Implement a read-only OSQAr validator for existing Inspector bundles.
3. Add `osqar inspect` as an explicit operator command.
4. Add the typed `inspection` configuration block.
5. Integrate required/optional invocation into `shipment prepare` before final OSQAr checksums.
6. Add candidate-record projection without approval promotion.
7. Keep hook-based experiments documented as non-authoritative and remove them from the recommended path once the adapter is available.
