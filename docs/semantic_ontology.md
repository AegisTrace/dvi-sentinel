# Semantic event ontology

The V2 development library projects a V1 `TelemetryEvent` into an explicit semantic
signal, evidence bindings and loss findings. It analyzes local synthetic/documentation
fixtures. A known signal means its declared evidence contract is satisfied; it does
not mean a detector fired or that a production detection is effective. The combined
V2 CLI, standards profiles and oracle consensus are later cards.

## Run the example

From an installed development checkout:

```sh
python examples/semantic_ontology.py --out runs/v2/ontology-proof
python -m pytest tests/test_v2_ontology.py
```

Choose a new output directory on repetition. The example normalizes two inert flow/DNS
records using documentation identifiers, then removes the DNS question from a copy
to demonstrate a model-valid event with incomplete semantic evidence. It prints
`known=2 unknown=1` and writes three actual analysis files:

| Artifact | Evidence |
| --- | --- |
| `semantic_ontology.json` | Versioned profile, input anchor, complete signal extractions, assumptions, findings and recommendations. |
| `ontology_bindings.json` | Each selector, all alias candidates, resolved value/state, event digest and raw-source digest. |
| `semantic_loss.json` | Classified findings and recommendations referring to those findings and evidence fields. |

These standalone files use schema version `1`. They are not V1 run bundles and do not
claim manifest or provenance-DAG verification. They contain deterministic source/input
anchors, not signatures or proof of authorship. Re-extract from trusted source events
to verify assertions about source content; a matching hash alone cannot establish them.

## Identity and evidence

`SemanticSignal` includes category, action, outcome, entities, source/destination
relation, protocol, resource observables, time role, required timestamp precision,
evidence requirements, confidence/correlation requirements and identity-bound values.
Its `semantic_digest` hashes that meaning using the existing DVI canonical JSON
serializer; `signal_id` is `signal:` followed by the full digest. Loading a signal
checks that both match its meaning. This is version-local DVI JSON, not RFC 8785.

Event IDs, source hashes, adapter/vendor/sensor metadata, labels, tags and absolute
timestamps do not affect the default signal identity. They stay available in source
evidence. Explicitly binding one with `affects_identity=True` makes it meaningful.
For example, binding `raw.payload.sensor_label` detects changes to that declared
label; binding `timestamp` as an additional identity field makes exact instants matter.
Detector/signature/title metadata on `DetectionEvent` can likewise be explicitly bound.

Core canonical meaning always participates, even with a custom profile. Entity
references are treated as a sorted set; source and destination remain distinct roles.
Required evidence names are sorted. Exported events are sorted by unique event ID.
Profile labels and alias ordering do not alter signal meaning, but profile/source
digests preserve the exact submitted contract and representation.

`FieldBinding` declares a semantic field name, up to eight inert paths, applicable
categories, whether evidence is required, whether its value affects identity and
an optional endpoint role. `OntologyProfile` holds at most 64 bindings. Selectors
access explicitly supported canonical fields or dictionary keys below `raw.payload`;
they cannot execute expressions, traverse arrays, invoke attributes or perform I/O.
Unsupported selectors produce `unknown_mapping`. Recognized but absent selectors
produce missing evidence. Equal populated aliases agree; differing populated aliases
are ambiguous before normalization. No first-alias priority is guessed.

`Observable` stores an immutable canonical JSON value or an explicit missing,
ambiguous or unknown state. Empty values cannot claim known evidence. `EvidenceBinding`
retains every candidate and checks that its resolved value agrees with them.
The default profile requires category/action/event time, DNS question names for DNS,
HTTP method/path for HTTP and known severity for alerts. Endpoint/protocol/correlation
absence remains explicit and optional unless the profile adds a requirement.
Source confidence, observation time and retained source time text are also bound as
optional evidence without affecting semantic identity, so their measured values
remain inspectable when a profile requirement produces a finding.

`semantic_equivalence(left, right)` returns `equivalent`, `different` or `unknown`.
Two incomplete extractions remain unknown even when their digests match. Every
comparison emits a `SemanticInvariant` describing the protected meaning fields and
an inert `SemanticTransform` recording source/destination event digests and changed
fields. It does not apply a transformation. `DetectionAssumption` records binding
requirements; each `SemanticFinding` has a cause-linked `SemanticRecommendation`.

## Losses and uncertainty

| Class | Observed trigger |
| --- | --- |
| `missing_required_evidence` | A required binding has no nonempty value, or required observation time is absent. |
| `ambiguous_field_binding` | Declared aliases contain conflicting populated values. |
| `lossy_normalization` | Explicit casefold changes a text value, discarding source distinctions. |
| `unsupported_semantic_category` | A valid canonical category is outside the selected profile. |
| `inconsistent_entity_role` | A binding declares source while selecting a canonical destination, or the reverse. |
| `timestamp_precision_loss` | Valid retained source time has fewer fractional digits than required. |
| `correlation_key_loss` | Required correlation evidence is absent. |
| `severity_semantic_loss` | A required canonical severity is explicitly unknown. |
| `unknown_mapping` | Unsupported selector/type/warning interpretation or unavailable/invalid source precision evidence. |
| `insufficient_confidence` | Source confidence is absent or below the profile's explicit threshold. |

All current loss findings block equivalence. A byte-valid projection with a lossy
normalization remains unknown until independently justified; casefold is not
automatically a safe semantic relation. Loss-free optional absence is recorded and
can compare equally. No equivalence claim fills in a missing required value.

Timestamp precision means the number of fractional digits in valid retained source
time text, not clock accuracy or effective sensor resolution. V1 has no retained
source-precision record for observation time, so a precision requirement on that
clock is unknown. Source confidence is a declared event value, not a calibrated
statistical estimate. The statistical confidence card will have a separate contract.

## Library and safety boundaries

Use `extract_signal(event, profile)`, `semantic_equivalence(left, right)`,
`export_ontology(events, profile)` and `ontology_artifacts(export)`. The first two
modules are pure data/validation and pure analysis. They reuse V1 event validation,
raw digests, serialization and fixture-policy checks; direct callers cannot bypass
those checks with unchecked model copies. There are no new runtime dependencies.

Exports accept 1–1,000 unique events with at most 2 MiB combined canonical input,
bindings have at most eight path segments, and individual value snapshots are
limited to 65,536 characters. Existing serialization caps each artifact at 32 MiB.
The example writer rejects network/symlink destinations and existing output, writes
only the three fixed filenames and never executes content or sends traffic.

The large-input tests exposed quadratic URL-regex work in the existing V1 policy
checker. Its scan now locates URL delimiters first; property and negative tests
preserve the previous candidate/rejection behavior, including prefixed and nested
URL text. This is a bounded-analysis fix with the same defensive rules.

Proof lives in [ontology tests](../tests/test_v2_ontology.py),
[policy regressions](../tests/test_policy.py) and the
[executable example](../examples/semantic_ontology.py). See the
[V2 architecture](v2_architecture.md) for the fixed local-only boundary and future cards.
