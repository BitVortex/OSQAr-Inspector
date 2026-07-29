# Design contracts

## 1. Status

This document defines the intended public contracts. The development implementation currently covers strict `osqar.inspector.config.v1` resolution and identity, `osqar.inspector.snapshot.v1` clean-Git capture/materialization and complete materialized-record comparison, deterministic side-effect-free `osqar.inspector.plan.v1` construction, byte-preserving pre-generated coverage-report ingestion with independent mapping and attestation validation as specified in Section 11, the deterministic artifact graph and separately rendered navigation layer specified in Section 12, deterministic closure of finalized candidate payloads, `verify`, `osqar.inspector.bundle-manifest.v1`, `osqar.inspector.run.v1`, and the v1 internal-link contract as summarized in the README; the other sections remain design targets. Identifiers ending in `.v1` remain provisional until their schemas, validators, interoperability tests, and release policy land together as a supported interface.

## 2. Command contract

### `plan`

```text
osqar-inspector plan --project <path> --configuration <file>
```

Responsibilities:

- parse and validate configuration;
- resolve the clean-Git snapshot identity without materializing producer workspaces;
- validate declared producer selectors and version constraints without executing external programs;
- emit a deterministic declarative execution plan, unresolved capability requirements, and diagnostics; and
- exit non-zero when a statically decidable required prerequisite is unsatisfied.

`plan` may write only to stdout and stderr. It must not execute configured producers or capability probes and must not create temporary files, caches, project files, output directories, or persistent state. Producer availability and versions remain unresolved until `build`, which probes them in an owned workspace before producer execution.

### `build`

```text
osqar-inspector build --project <path> --configuration <file>
```

Responsibilities:

- capture and materialize the selected snapshot;
- execute the plan in owned workspaces;
- validate and normalize producer outputs;
- render integration navigation;
- validate a closed candidate bundle; and
- publish atomically if required-stage policy is satisfied.

Exit zero means the requested build satisfied required-stage policy and a validated bundle was published. It does not mean evidence approval or qualification.

### `verify`

```text
osqar-inspector verify --bundle <path>
```

Responsibilities:

- parse the manifest and run report under their declared schema versions;
- require exact inventory equality;
- recompute payload and manifest digests;
- validate checksum-file bytes;
- validate required entry points and internal links; and
- report structural/provenance results without executing producers.

## 3. Configuration contract

Reserved schema: `osqar.inspector.config.v1`.

Top-level design areas:

- `schema` — exact schema identifier;
- `project` — include/exclude policy and clean-Git requirement;
- `publication` — destination and reproducibility controls;
- `stages` — required/optional policy and adapter blocks;
- `doxygen` — producer options and warning policy;
- `coverage` — generic report, mapping, and attestation inputs;
- `extensions` — explicitly namespaced future fields.

Unknown fields fail validation unless owned by a declared extension namespace. Positive booleans such as `enabled` are preferred. Host project roots, publication roots, and workspaces are invocation context and must not enter deterministic identities as host-absolute strings. Any path value inside configuration must already satisfy the project-relative path profile in Section 4 or validation fails.

Configuration precedence is:

```text
defaults < configuration file < explicit CLI overrides
```

The v1 composition algorithm is normative:

1. Parse the identified default-set bytes and controlled configuration bytes as UTF-8 JSON without a byte-order mark. Reject duplicate object member names, unpaired Unicode surrogates, invalid UTF-8, trailing non-whitespace data, and any top-level value other than an object. Every number token in defaults, controlled configuration, and override values must use the integer grammar `0|-?[1-9][0-9]*`, must not be `-0`, and must have mathematical value in `[-9007199254740991, 9007199254740991]`. Fractions, exponents, and values outside that range are invalid in v1; configurations needing decimal quantities represent them using schema-defined strings.
2. Compute `merge(defaults, controlled)` recursively. For each controlled-file member, recurse only when both the existing default value and controlled value are objects. Otherwise the controlled value replaces the default value in full. An absent controlled member preserves the default. Arrays are atomic values and never concatenate or merge; an overriding array replaces the complete prior array. `null`, booleans, numbers, strings, and object/non-object type changes likewise replace the complete prior value.
3. Validate the complete override set before applying any override. Each `pointer` is a non-empty RFC 6901 JSON Pointer. Decode only `~0` as `~` and `~1` as `/`; any other `~` sequence is invalid. Re-encode the decoded tokens by replacing `~` with `~0`, then `/` with `~1`, and prefixing every token with `/`; the result must byte-equal the supplied pointer. Reject duplicate decoded token sequences and every pair in which either decoded token sequence is a proper prefix of the other. Thus ancestor/descendant combinations such as `/stages/doxygen` and `/stages/doxygen/enabled` are invalid rather than order-dependent.
4. Sort accepted override records by unsigned lexicographic comparison of their pointer UTF-8 bytes and apply them in that order to the merged object. Every non-final pointer token must name an existing object member whose value is an object; traversal through arrays or scalars and a missing parent are errors. The final token may replace an existing object member or add an absent member. The supplied JSON value replaces that complete member; objects and arrays supplied by an override are not recursively merged.
5. Validate the resulting object against the identified configuration schema, including the requirement that every configured path already satisfies Section 4. Do not normalize, coerce, default, redact, or exclude any field after this validation. The validated merged object in full is the resolved semantic object. Serialize it as RFC 8785 canonical JSON and hash those exact bytes.

Because overlapping pointers are rejected, sorted application order is normative but cannot change another accepted override's target. Any parse, merge, pointer, path-profile, or final-schema error fails configuration resolution before planning.

Configuration identity is a closed object containing all of the following independently computable values:

- `controlled_input`: normalized project-relative configuration path, exact-byte size, and SHA-256 of the exact controlled file bytes;
- `schema`: exact configuration-schema identifier and digest of the shipped schema bytes;
- `defaults`: exact default-set identifier and digest of its canonical JSON object;
- `overrides`: an RFC 8785 canonical JSON array of explicit CLI override records, sorted by JSON Pointer, with each pointer occurring once; and
- `resolved`: SHA-256 of the complete RFC 8785 canonical semantic configuration after applying the identified defaults, controlled file, and overrides.

The exact v1 identity-object shape is:

```json
{
  "controlled_input": {"path": "<normalized project-relative path>", "sha256": "<digest>", "size": "<canonical decimal byte count>"},
  "defaults": {"id": "<default-set identifier>", "sha256": "<digest>"},
  "overrides": [{"pointer": "<JSON Pointer>", "value": null}],
  "resolved": {"sha256": "<digest>"},
  "schema": {"id": "osqar.inspector.config.v1", "sha256": "<digest>"}
}
```

The shown `null` is an example; each `value` is the actual typed JSON value accepted by the schema. Override records have exactly `pointer` and `value`, are sorted by unsigned lexicographic comparison of JSON Pointer UTF-8 bytes, and reject duplicate pointers. Every shown object is closed. Sizes use `0|[1-9][0-9]*`; digests use 64 lowercase hexadecimal characters. The complete object is serialized as RFC 8785 canonical JSON whenever it contributes to another identity.

The resolved semantic object contains every configuration field and uses only already-normalized project-relative configured paths. Redaction is a display operation and never changes this identity object. V1 defines no core credential or secret fields, and resolution derives no behavior from the environment. Extension objects and explicit override values are caller-controlled; the schema cannot determine whether arbitrary values are semantically secret. Those values survive resolution without redaction and are committed verbatim through the canonical resolved object and explicit override records. They therefore **MUST NOT** contain credentials, secrets, tokens, or other protected values. A future adapter requiring behavior-affecting protected values needs a new contract that defines a caller-reproducible, non-disclosing commitment; it may neither disclose nor silently omit them.

The run identity commits to the complete configuration-identity object, not only the resolved digest. The packaged `resources/interoperability/vectors.json` publication contains exact controlled-input, default-set, schema, and override bytes; expected typed error codes; and, for every successful vector, exact canonical semantic bytes, component digests, and configuration-identity bytes so OSQAr can compute and compare identity without importing or trusting Inspector's resolver. Its executable vectors cover recursive nested-object merge, object-to-scalar and scalar-to-object type replacement, complete array replacement, existing-member replacement, final-member addition, successful `~0`/`~1` access to object member names containing `~` and `/`, missing-parent rejection, scalar/array traversal rejection, duplicate pointers, ancestor/descendant pointers in both supplied record orders, malformed/non-canonical pointer forms, UTF-8 byte-order marks, trailing data, non-object top-level values, invalid UTF-8/Unicode/duplicate members, rejected number grammar classes and boundary safe integers, invalid override-value numbers, non-normalized configured paths, final-schema rejection, and successful exact canonical bytes/digests. The same publication includes exact identity-mutation evidence for controlled-input, default-set, and override changes.

## 4. Path profile

Machine-readable project and bundle paths are:

- relative;
- `/`-separated;
- Unicode NFC;
- without a leading `/`;
- without empty, `.`, or `..` segments;
- without backslash or control characters; and
- unique after normalization.

Inputs that cannot be represented uniquely under this profile fail before producer execution or publication.

## 5. Canonical encoding and IDs

Machine-readable contracts use UTF-8 JSON canonicalized according to RFC 8785. Digests use SHA-256 encoded as 64 lowercase hexadecimal characters.

A domain identifier has the form:

```text
<kind>:sha256:<digest>
```

The digest covers canonical JSON containing the kind and its kind-specific identity object. Volatile timestamps, absolute workspace paths, hostnames, and log display metadata never contribute to deterministic IDs.

Required ID kinds for the first integration:

- `snapshot`;
- `source-file`;
- `artifact`;
- `run`; and
- `bundle`.

`symbol` is required when the Doxygen adapter emits symbol mappings. Producer-native IDs are always scoped by snapshot and adapter identity.

## 6. Snapshot manifest

Reserved schema: `osqar.inspector.snapshot.v1`.

Minimum content:

- source kind `git-clean`;
- Git object format, commit, and tree IDs;
- normalized include/exclude policy;
- sorted file records;
- deterministic snapshot ID;
- Inspector version as non-identity metadata; and
- a dedicated selected compilation-database digest when an explicit snapshot
  policy identifies such an input.

The current library capture API has no compilation-database selector, so that
conditional field is not yet applicable. The canonical snapshot manifest also
deliberately excludes the wall-clock capture timestamp: issue #2 requires two
captures of the same commit and policy to be byte-identical. A future execution
or observation envelope may record its timestamp as non-identity data without
changing the canonical snapshot manifest or snapshot ID.

Each file record contains normalized path, closed kind, canonical mode, size, and kind-specific identity payload. Initial implementation supports regular files, executables, and internal relative symlinks that resolve directly to a selected regular file, with exact target identity. Gitlinks and unsupported filesystem objects fail capture.

A complete pre/post comparison covers the sorted record set, not only file content digests. Added, removed, replaced, retargeted, mode-changed, or byte-changed entries block publication.

## 7. Execution plan

Reserved schema: `osqar.inspector.plan.v1`.

The plan contains:

- the complete configuration-identity object and snapshot identity;
- ordered stage definitions;
- dependency edges;
- required/optional policy;
- selected adapter selectors, declared version constraints, and explicitly unresolved runtime capabilities;
- owned workspace allocations expressed without volatile paths in the plan identity;
- declarative invocation templates rather than probe-derived command vectors;
- expected outputs; and
- blocking diagnostics.

Semantically unordered collections are sorted by a defined identity key before hashing.

## 8. Stage result

Reserved schema: `osqar.inspector.stage-result.v1`.

Each result contains:

- stage and adapter identity;
- status: `succeeded`, `failed`, `blocked`, `skipped`, or `degraded`;
- required/optional policy;
- input snapshot ID;
- start/end timestamps and duration as observational data;
- redacted argument vector;
- process exit status or typed internal error;
- stdout/stderr artifact paths;
- output artifact records; and
- diagnostics.

A required stage must be `succeeded` for publication. Zero exit without required outputs is `failed`, not `succeeded`.

## 9. Producer adapter protocol

Every producer adapter implements:

```text
validate_declaration(config) -> Diagnostics + CapabilityRequirements
plan_declaration(config, snapshot) -> DeclarativeStagePlan
probe(config, owned_probe_workspace) -> Capability
validate_capability(config, capability) -> Diagnostics
plan_command(declarative_plan, capability, owned_stage_workspace) -> CommandPlan
execute(command_plan) -> ProcessResult
collect(process_result, workspace) -> ProducerOutput
normalize(producer_output, snapshot) -> ArtifactRecords + MappingRecords
```

The first two operations are pure and are the only adapter operations permitted by public `plan`. `build` performs `probe` through the shared process runner in an owned workspace; a missing or incompatible required capability blocks producer execution and publication. The runner executes argument vectors without a shell, applies timeout policy, captures logs, and records executable version. Adapter-specific accepted non-zero statuses require explicit contract tests.

The adapter owns no publication logic and cannot write to the live project.

## 10. Doxygen mapping design

The Doxygen stage generates HTML plus XML and/or a tag file. Mapping records contain:

- adapter schema and version;
- snapshot ID;
- producer `refid`;
- entity kind and qualified name;
- normalized source path;
- declaration line/column when available;
- HTML artifact ID; and
- HTML anchor.

Duplicate `(snapshot ID, refid)` records, missing artifact targets, or ambiguous normalized source/anchor targets fail mapping ingestion. No mapping is inferred from HTML filename conventions.

## 11. Coverage ingestion design

Coverage ingestion reads a configured pre-generated report and never executes a
coverage producer. `coverage.report` identifies the report entry point relative
to the ingestion input root; its immediate parent is the closed report-tree
root. The tree permits directories and regular files only. Every regular-file
byte is read unchanged and recorded by normalized report-relative path, byte
count, and SHA-256 digest. The entry point must name one inventoried regular
file. A descriptor-based no-follow read and complete pre/post file-set and
metadata comparison reject report-tree replacement, mutation, addition, or
removal during ingestion.

The report-tree digest is SHA-256 over RFC 8785 canonical JSON with exactly
`entries`, `kind`, and `schema`; `kind` is `coverage-report-tree` and `schema`
is `osqar.inspector.coverage-report-tree.v1`. `entries` contains exactly `path`,
`sha256`, and canonical decimal-string `size` for every report file, sorted by
unsigned UTF-8 path bytes. The entry point is bound separately by each sidecar
and therefore does not alter the tree-byte digest. Sidecars are independent
inputs and must reside outside the report-tree root.

Coverage uses two independent optional, strict UTF-8 JSON sidecars. Their
objects are closed; unknown or missing fields fail validation. The packaged
JSON Schemas are `coverage-map-v1.schema.json` and
`coverage-attestation-v1.schema.json`. Each configured sidecar is retained as
an evidence artifact with its exact input bytes, normalized input-root-relative
path, byte count, SHA-256 digest, sidecar kind, and deterministic artifact ID;
parsing and validation do not replace those original bytes.

The schemas express closed object shapes, path segment/control-character
constraints, safe-integer bounds, and digest/identity syntax. Inspector also
enforces Unicode NFC at runtime because JSON Schema 2020-12 has no Unicode
normalization keyword; schema validation alone is therefore not the complete
path-profile validation operation.

### Mapping sidecar

Reserved schema: `osqar.inspector.coverage-map.v1`.

It contains exactly `schema`, `report`, and `relations`. `report` contains the
exact report-relative `entry_point` and `tree_sha256`. Each relation contains an
exact `report_path`, exact selected-snapshot `source_path`, and nullable
`fragment`, positive-integer `line`, and `symbol`. Duplicate relations, absent
report targets, absent source targets, ambiguous source basenames, and escaping
paths fail. No source or report path is inferred from a basename or report
presentation. Without a configured valid mapping, the report remains navigable
only at report level.

### Attestation sidecar

Reserved schema: `osqar.inspector.coverage-attestation.v1`.

It contains exactly `schema`, `report`, `snapshot_id`,
`configuration_identity_sha256`, `producer`, `test_selection_identity`,
`test_result_identity`, `instrumentation_identity`, and
`coverage_data_identity`. `configuration_identity_sha256` covers the canonical
complete configuration identity from Section 3. `producer` contains
exactly `name` and `version`; `report` has the mapping-sidecar binding shape.
An attestation upgrades provenance only when its report tree, source snapshot,
and complete configuration-identity digest all match the current ingestion inputs.
Structural and digest validation establishes internal binding consistency of
the declaration, not declarant authenticity or independent reproduction of
tests.

### Provenance states

- `verified-current-snapshot` — produced in this run against the materialized snapshot and validated by the adapter;
- `externally-attested` — an external declaration passes schema and digest checks but was not reproduced by this run;
- `unknown-origin` — presentation input whose source/test/configuration identity is not established.

Pre-generated ingestion emits `externally-attested` only for a matching
attestation and otherwise emits `unknown-origin`. Absence of an attestation can
never produce `externally-attested`. `verified-current-snapshot` is reserved for
a future stage that executes and validates a coverage producer in the current
run; ingestion alone never emits it. Mapping validity and provenance are
independent.

## 12. Artifact graph

Reserved schema: `osqar.inspector.artifact-graph.v1`.

Initial node kinds:

- snapshot;
- source file;
- symbol;
- API page;
- coverage report/page/summary;
- producer log;
- stage result; and
- rendered navigation artifact.

Initial edge kinds:

- `describes-snapshot`;
- `generated-by-stage`;
- `documents-source`;
- `documents-symbol`;
- `covers-source`;
- `covers-symbol`;
- `has-log`; and
- `links-to`.

Edges are created only from validated identities. Missing symbol identity may degrade to a valid file relation. Ambiguous basenames never create a relation.

The graph is a closed canonical record. Nodes are sorted by `node_id`; edges are
sorted by `edge_id`; duplicate records, missing endpoints, unknown kinds, and
noncanonical order are rejected. Each node commits canonical JSON of exactly
`{"identity": <kind-specific identity>, "kind": <node kind>}`. Its identifier is
the node-kind prefix followed by `:sha256:` and the SHA-256 digest of those
bytes (for example, `source-file:sha256:<digest>`). Each edge
commits its kind, endpoints, and the complete locator profile (`relation_id`,
`fragment`, `line`, and `symbol`); its identifier is derived in the same manner.
The graph identifier commits the schema, snapshot identifier, and complete
canonical node and edge records. Validation reconstructs all three identity
levels rather than accepting retained digests.

Node semantic fields are closed by kind. Snapshot nodes use only `label`;
source nodes use `label`, `path`, and `sha256`; symbols use `label`, `path`, and
`fragment`; API and coverage payloads additionally use only their declared
`provenance`; stage results use only `label`, `sha256`, and `stage_status`;
producer logs and rendered navigation use only `label`, `path`, and `sha256`.
Every unlisted optional field is null. Labels equal their canonical path except
for snapshot and stage-result labels. Doxygen symbol identities retain the
adapter, entity kind, refid, qualified name, source path, optional positive
line and column, API artifact ID, and HTML fragment; construction validates
these primitive profiles before projection and rejects duplicate semantic
targets even when their native refids differ. Kind-specific identities
additionally commit their adapter-native identifiers and schemas where
applicable. Producer
logs commit stage and byte size; navigation commits base graph and byte size.
Every `links-to` target is rendered with its exact node identifier on the source
navigation page. Producer digest and fragment checks run before rendering, after
page publication, and at a terminal checkpoint after graph augmentation. This
is point-in-time validation of path-addressed inputs, not a filesystem lock:
owned-workspace mutation exclusion and closed-bundle revalidation remain
necessary through publication.

Coverage identities commit the adapter schema, native artifact ID, payload
path and digest, provenance, snapshot, report-tree digest, the report entry
point, and whether that artifact is the entry point. Construction requires the
reported entry-point path to identify exactly one artifact and requires that
artifact alone to carry the entry-point flag. Validation derives the flag and
`coverage-report` kind from the committed entry-point path, requires one report
node and one report-tree digest, classifies other HTML payloads as
`coverage-page` and other payloads as `coverage-summary`, and rejects all
inconsistencies. Coverage relation edges alone carry relation metadata. Their
native relation identifier is reconstructed from report artifact and path,
snapshot, source path, symbol, line, and fragment; structural edges require all
relation metadata to be null.

Before graph construction, the supplied `GitSnapshot` is treated as caller-constructible input. Validation requires the closed `git-clean` source profile, matching SHA-1 or SHA-256 commit and tree grammar, closed and canonically ordered include/exclude paths, closed and canonically ordered file records, canonical file kinds/modes/sizes, lowercase SHA-256 content digests, exact path-to-byte content bindings, policy membership, and internal relative symlinks that resolve directly to selected regular files. It then reconstructs and matches the native snapshot manifest bytes and snapshot ID; a caller-provided snapshot label or internally self-consistent rehash is not a trust boundary. The graph then requires exactly one
snapshot node. Each represented coverage report
requires exactly one coverage-report node. Relations and structural edges are
unique by their complete canonical records. A producer payload may be supplied
without a stage-result node when it was independently normalized by its
adapter; if the corresponding stage result is present, payload attribution is
accepted only for `succeeded`. Producer logs may represent any executed stage
status and are linked by `has-log` to their matching stage result. Adapter and
stage identities are reconstructed in every case. These checks establish
deterministic structural and byte-integrity consistency; they do not
authenticate a graph or establish the adequacy of the represented evidence.

## 13. Run report

Reserved schema: `osqar.inspector.run.v1` and process-format identifier `osqar-inspector-run-v1`.

The run-report entry point is RFC 8785 canonical UTF-8 JSON without a byte-order mark or trailing newline. It has exactly this v1 structure:

```json
{
  "artifact_counts": [{"count": "1", "kind": "api-page"}],
  "claim_boundary": {
    "does_not_establish": [
      "certification",
      "evidence-adequacy",
      "evidence-approval",
      "fitness-for-use",
      "functional-safety",
      "security",
      "software-qualification",
      "standards-compliance",
      "tool-qualification"
    ],
    "scope": "mechanical-structural-and-integrity-inspection"
  },
  "configuration_identity": {
    "controlled_input": {"path": "inspector.json", "sha256": "<digest>", "size": "1"},
    "defaults": {"id": "builtin-v1", "sha256": "<digest>"},
    "overrides": [],
    "resolved": {"sha256": "<digest>"},
    "schema": {"id": "osqar.inspector.config.v1", "sha256": "<digest>"}
  },
  "diagnostics": [{"code": "stage.warning", "message": "<non-empty message>", "path": null, "severity": "warning"}],
  "inspector": {"version": "0.1.0"},
  "optional_stages": {"degraded": [], "skipped": []},
  "plan_sha256": "<digest>",
  "required_stage_decision": "satisfied",
  "schema": "osqar.inspector.run.v1",
  "snapshot_id": "snapshot:sha256:<digest>",
  "stage_result_digests": ["<digest>"]
}
```

Angle-bracketed strings are substituted values. Every enclosing object is closed. `configuration_identity` is the complete object defined in Section 3, including canonical, sorted, non-overlapping override pointers and v1-safe typed JSON override values. Digests use 64 lowercase hexadecimal characters. The Inspector version is a non-empty ASCII token formed from alphanumeric components separated by `.`, `_`, `+`, or `-`.

`artifact_counts` contains zero or more records with exactly `count` and `kind`. Kinds use lowercase alphanumeric hyphen-separated tokens, occur once, and are sorted by unsigned lexicographic comparison of kind UTF-8 bytes. Counts are positive canonical decimal strings; omitted kinds have count zero. `stage_result_digests` contains the final result digest for each planned stage in plan order and rejects duplicates. Stage identifiers in `optional_stages` use lowercase alphanumeric components separated by `.`, `_`, or `-`; each list is independently sorted by unsigned UTF-8 byte order, contains no duplicates, and the two lists are disjoint. `required_stage_decision` is exactly `satisfied` or `blocked`.

Each diagnostic object has exactly `code`, `message`, `path`, and `severity`. Codes use lowercase alphanumeric components separated by `.`, `_`, or `-`; messages are non-empty strings without control characters; paths are either `null` or satisfy Section 4; and severity is `info`, `warning`, or `error`. Diagnostic array order is significant and records deterministic production order.

The report repeats the exact claim-boundary object shown above. It does not contain the final bundle ID because the report is itself a bundle payload. Secrets, host credentials, and unredacted protected environment values are forbidden. Schema validation establishes only structural conformance; it does not claim semantic secret detection or redaction adequacy.

## 14. Closed bundle

Reserved schema: `osqar.inspector.bundle-manifest.v1`.

A release contains directories and regular files only. Its exact inventory is:

```text
manifest payload paths
+ manifest.json
+ checksums.sha256
```

`manifest.json` is an RFC 8785 canonical JSON object with exactly this v1 structure:

```json
{
  "entries": [
    {
      "path": "<normalized payload path>",
      "sha256": "<64 lowercase hexadecimal SHA-256 of exact payload bytes>",
      "size": "0"
    }
  ],
  "entry_points": {
    "index": "<normalized path naming one entries member>",
    "run_report": "<normalized path naming one entries member>"
  },
  "schema": "osqar.inspector.bundle-manifest.v1"
}
```

Angle-bracketed strings denote substituted values. `size` is the payload byte count encoded as a canonical decimal string matching `0|[1-9][0-9]*`; signs, whitespace, and leading zeroes are forbidden. The `entries` array contains every payload file exactly once, sorted by unsigned lexicographic comparison of normalized path UTF-8 bytes. Each entry object and each enclosing object has exactly the members shown; unknown, duplicate, missing, or checksum-derived fields are forbidden. `manifest.json` must not list itself or `checksums.sha256`, and it must not contain the bundle ID, manifest digest, or checksum-file digest. Both entry-point paths must resolve to regular payload files in `entries`. Serialize the substituted object as RFC 8785 UTF-8 JSON without a byte-order mark or trailing newline. Bundle directories are only the implicit parents of listed files; empty or additional directories are forbidden.

`checksums.sha256` uses this exact byte grammar:

- UTF-8 without a byte-order mark;
- exactly one record for each member of the set comprising every payload path plus `manifest.json`;
- each record is `<64 lowercase hexadecimal SHA-256 bytes><two ASCII spaces><normalized relative path UTF-8 bytes><LF>`;
- paths satisfy the path profile in Section 4, so no escaping is permitted or required;
- records are sorted by unsigned lexicographic comparison of the normalized path UTF-8 bytes;
- each path occurs exactly once; duplicate, missing, extra, empty, malformed, or non-canonical records fail validation;
- no blank lines or carriage returns are permitted; and
- the final record has exactly one terminal LF.

The checksum file excludes itself. After `manifest.json` and `checksums.sha256` are final, construct a JSON object with exactly these members:

```json
{
  "identity": {
    "checksums_sha256": "<64 lowercase hexadecimal SHA-256 of exact checksums.sha256 bytes>",
    "manifest_sha256": "<64 lowercase hexadecimal SHA-256 of exact manifest.json bytes>"
  },
  "kind": "bundle"
}
```

The angle-bracketed strings above denote substituted digest values, not literal bytes. Canonicalize the substituted object using RFC 8785 UTF-8 JSON with no byte-order mark or trailing newline, then compute its SHA-256. The bundle ID is `bundle:sha256:<digest>`, where `<digest>` is that 64-character lowercase hexadecimal result. Independent verification recomputes payload digests, canonical manifest bytes, exact checksum-file bytes, the exact identity-object bytes, and the bundle ID; extras, omissions, duplicates, and mismatches fail.

### Internal-link contract

After inventory, payload, manifest, and checksum validation succeeds, independent verification parses every listed payload whose path ends exactly in `.html` as UTF-8 HTML. The v1 link surface comprises `href` and `src` attributes on any element, `data` on `object`, and `poster` on `video`. Attribute and element names are ASCII case-insensitive. A `base` element carrying `href` and any `srcset` attribute fail as unsupported v1 link semantics rather than being ignored.

A reference with a URI scheme or authority is external and is not fetched. Every other reference is internal. Its percent escapes must be well formed and decode as UTF-8. Query components do not affect target resolution. A root-relative path resolves from the bundle root; another non-empty path resolves from the referring HTML payload's parent; and an empty path resolves to the referring payload. Dot segments in a reference are resolved, but the result must remain inside the bundle and satisfy the Section 4 path profile. A reference ending in `/` resolves to `index.html` beneath that path. The resolved target must name a manifest payload.

A non-empty fragment is percent-decoded as UTF-8 and must match exactly one `id` attribute or legacy `name` attribute on an `a` element in an HTML target. Duplicate anchor identities in one target are ambiguous and fail. Empty fragments resolve to the document itself. HTML payloads with invalid UTF-8, malformed percent escapes, unsupported link semantics, escaping paths, absent targets, non-HTML fragment targets, or missing or ambiguous anchors fail verification with typed diagnostics. External URLs are never evidence that a network resource exists or is trustworthy.

Producer artifacts remain byte-identical. Inspector-owned navigation and reports are separate payloads.

## 15. Publication protocol

The Linux publisher uses one filesystem and immutable releases:

1. exclusively create an owned candidate directory `releases/.candidate-<run-unique>` beneath the publication root;
2. write and close every payload file;
3. generate, write, and close canonical `manifest.json` from the closed payloads;
4. generate, write, and close canonical `checksums.sha256` from the payloads and exact manifest bytes;
5. validate complete closure and compute the bundle ID;
6. flush every candidate regular file, then candidate directories from leaves to root;
7. rename the candidate to `releases/<bundle-id>/`, or, if that path exists, independently verify exact identity before discarding the candidate;
8. flush the `releases/` directory after creation or verified reuse;
9. exclusively create a temporary symlink `.current-<run-unique>` in the publication root whose target bytes are exactly `releases/<bundle-id>`;
10. atomically replace the publication-root `current` entry with that temporary symlink; and
11. flush the publication-root directory before reporting durable success.

Temporary names are invocation-unique, must not exist before exclusive creation, and do not contribute to bundle identity.

Pointer replacement is the observable commit point. Failures after pointer replacement but before final directory sync are `commit-indeterminate`, not ordinary failure or success. Startup recovery verifies the exact old or new pointed release before another publication.

### Publication result and state machine

Reserved schema: `osqar.inspector.publication-result.v1`. This result is an external process result, never a bundle payload and never a member of `manifest.json` or `checksums.sha256`. Its canonical JSON contains the schema, run identifier, closed publication state, bundle ID when computed, normalized release path when assigned, run-report path and SHA-256, prior and intended `current` targets when known, and typed diagnostics. It therefore binds the enclosing bundle ID to the immutable in-bundle run report without creating an identity cycle.

The publication state is exactly one of:

- `not-attempted` — stage or candidate validation prevented publication;
- `definite-pre-commit-failure` — the operation failed before pointer replacement and the previous `current` target is unchanged;
- `commit-indeterminate` — pointer replacement occurred or may be visible, but publication-root durability was not established;
- `durable-success` — pointer replacement and the final publication-root flush completed;
- `recovered-durable-success` — recovery verified the intended exact release as `current` and durably synchronized the root;
- `recovered-no-commit` — recovery verified the previous exact release as `current`; the candidate or unpointed release is not treated as published; or
- `recovery-blocked` — recovery could not establish one exact valid old or intended target.

Before pointer replacement, the publisher durably records an invocation-unique recovery record outside every release containing the old target, intended target, bundle ID, and run-report digest. It removes that record only after durable success and a synchronized removal. Recovery validates the pointer and exact pointed bundle against this record; it never infers success from an unpointed release directory.

The build exit mapping is exact: `0` for `durable-success` or `recovered-durable-success`, `10` for `not-attempted`, `11` for `definite-pre-commit-failure`, `12` for `commit-indeterminate`, `13` for `recovered-no-commit`, and `14` for `recovery-blocked`. No new publication starts while an indeterminate recovery record remains unresolved. Fault-injection tests cover each file flush, directory flush, release rename, recovery-record write/removal, pointer replacement, and final root flush boundary.

## 16. OSQAr handoff contract

OSQAr consumes only a closed bundle plus run report under supported versions. It validates:

- bundle closure and internal consistency;
- Inspector protocol and schema versions;
- Inspector tool identity/version policy;
- snapshot Git commit/tree against the trusted OSQAr source revision;
- every component of configuration identity against the OSQAr-controlled input bytes/path, schema/default-set identifiers, and explicit overrides;
- publication state, accepting only independently reverified durable outcomes;
- required stage result policy; and
- provenance classifications.

OSQAr may derive candidate evidence and implementation records, but must not infer `approved`. See [OSQAr integration](osqar-integration.md).

## 17. Evolution rules

- Patch releases may clarify diagnostics without changing accepted data.
- Additive optional fields require either an explicitly open extension object or a new schema version; unknown ordinary fields remain errors.
- Removing, renaming, changing meaning, or widening accepted values requires a new schema identifier.
- OSQAr and Inspector negotiate exact supported protocol/schema sets; they do not silently accept newer unknown contracts.
- A migration tool may be added later, but runtime validation remains fail-closed.
