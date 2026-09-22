# Cross-representation metamorphic testing

V2-09 measures whether one local canonical telemetry event retains its fields,
meaning and context through selected fixture/profile representations. It executes
the existing encoders, parsers and profile mappings, then compares actual outputs.
The source stays separate from the generated representations and their raw evidence.

Use `MetamorphicInput` from `dvi_sentinel.metamorphic_models` and
`analyze_representations` or `metamorphic_artifacts` from `dvi_sentinel.metamorphic`.
The producer pins the complete request digest before consumption:

```python
request = MetamorphicInput(source=event)
input_digest = request.stable_digest()
report = analyze_representations(request, expected_digest=input_digest)
```

`representations` selects one to eight fixed names; the default selects all eight.
`supplied` optionally provides actual representation content for selected names.
Names and supplied rows canonicalize before hashing, so declaration order does
not change the report. No runtime mappings, expressions or callbacks are accepted.

## Executed representations

| Name | Actual consumer |
| --- | --- |
| `canonical_jsonl` | V1 DVI JSONL encoder and parser. |
| `csv` | V1 CSV fixture encoder and parser. |
| `suricata_eve` | V1 EVE-style fixture encoder and parser. |
| `zeek_like` | V2-03 local Zeek-like projection and normalization. |
| `ecs_like` | V2-03 local ECS-like projection and normalization. |
| `ocsf_like` | V2-03 local OCSF-like projection and normalization. |
| `otel_like` | V2-03 local OpenTelemetry-like projection and normalization. |
| `sigma_metadata` | V2-03 Sigma metadata projection; cannot reconstruct an observed event. |

The existing [profile contract](schema_profiles.md) defines the exact subsets and
extensions. These names do not claim full standard compliance. Supplied profile
content is one JSON object; supplied fixture content must normalize to exactly
one event. Missing/extra logical event IDs are differences, never silently aligned.

Existing V1 constraints remain observable. Unsupported encoder fields produce
unknowns. A generated CSV with an empty optional vendor cell is rejected by the
current parser; omitting that optional column is supported. Partial parses and
multiple events cannot establish equivalence. Sigma metadata always remains
unknown as event evidence, even when its metadata fields can be mapped.

## What agreement means

Each result retains the actual bytes, projection when generated, normalization,
field differences, ontology equivalence and any parser failure. Field comparison
uses the existing V1 semantic projection, which includes normalized context such
as sensor, vendor, tags and correlation. Ontology equivalence independently checks
the V2 declared meaning and required evidence.

A row agrees only when those comparisons resolve without field differences or
mapping loss. A known difference produces `disagree`. Missing/ambiguous evidence,
unsupported features or incomplete parsing produces `unknown`, with measured
differences still visible when available. Unknown rows override overall agreement.
Missing input pins block measurement as unknown; integrity or structural policy
rejections block it as `unsafe_rejected` and omit input content.

The complete matrix compares every selected row with every selected row in sorted
order, including the diagonal. Unknown rows have unknown comparisons, even with
themselves. Pairwise agreement is **not source fidelity**: two profiles can share
the same metadata loss while agreeing with each other. Baseline differences remain
in the report so that this shared loss cannot disappear.

## Field-linked findings

| Class | Evidence |
| --- | --- |
| `semantic_loss` | Changed semantic fields/identity or different complete ontology projections. |
| `timestamp_precision_loss` | Mapping precision diagnostic or a measured timestamp matching truncation to fewer fractional digits. |
| `timezone_drift` | Different actual instants with retained equal wall-clock spellings and different explicit offsets. |
| `severity_mapping_drift` | Changed canonical severity or an actual profile severity mapping diagnostic. |
| `field_alias_mismatch` | Actual conflicting aliases from the parser or profile normalizer. |
| `correlation_key_loss` | Changed or missing correlation value. |
| `adapter_disagreement` | Each independently normalized field difference; expected/observed values remain linked. |
| `unsupported_profile_feature` | Unsupported fields, incomplete parsing/encoding, metadata-only scope or unresolved ontology evidence. |
| `metadata_context_loss` | Changed/lost metadata or a mapping issue naming discarded context, including warnings. |

Equivalent timezone spellings that identify the same instant do not produce a
drift finding. Arbitrary time shifts do not establish a timezone cause. The
timestamp precision class records a measured truncation pattern, not a universal
causal attribution. Adapter disagreement can reflect intentionally different input
bytes or profile limits; it does not by itself prove an adapter defect.

Each finding carries the complete input digest, representation, logical field path
and a JSON pointer into `metamorphic_report.json`. Concrete parser diagnostics and
profile field traces retain original alias/path details. A field can have multiple
diagnostic traces and classes; counts are not independent failures or confidence.

## Artifacts, safety and limits

Four files are recomputed from the request:

- `metamorphic_report.json`: request, bytes, actual measurements, findings and matrix.
- `representation_diff.json`: findings and input digest.
- `adapter_disagreement.jsonl`: field disagreement rows with input digests and evidence pointers.
- `cross_profile_matrix.json`: complete ordered matrix and input digest.

Models validate content links, input digests, row/matrix identity and verdict
consistency. Parsing a report does not rerun its analyzers or authenticate its
producer. Use the input-based API to reproduce measurements; hashes establish
content linkage against a separately retained pin, not authenticity.

The models and analyzer perform no filesystem, network, subprocess or detector
service I/O. Input is one event and up to eight named representations, at most
64 KiB per supplied representation and 256 KiB for the complete request. Existing
parsers/mappings limit generated content to 2 MiB. The matrix has at most 64 cells,
findings at most 4096 rows, and combined artifact output at most 32 MiB. Unsafe
input never reaches comparison and is not re-exported. No V1 contract or dependency
changes are required. Multi-event sequence and detector outcomes belong to other
analyses; these artifacts do not replace the V1 verified run bundle or certify a release.

Run the [example](../examples/cross_representation.py) under a new local directory:

```powershell
.venv\Scripts\python.exe examples/cross_representation.py --out runs/v2/representation-proof
```

It executes all eight paths and 64 matrix cells for a synthetic flow with context
and microsecond precision. It exposes actual timestamp/context loss and keeps Sigma
event equivalence unknown. The [behavioral tests](../tests/test_v2_cross_representation.py)
also exercise a supported common subset that agrees across all seven event
representations, supplied differences, alias conflicts, safety, integrity and bounds.
