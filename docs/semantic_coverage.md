# Semantic discovery coverage

V2-08 tracks distinct, measured observations from local cases. It retains a case
when that case adds resolved semantic or diagnostic coverage, records growth,
and explains skips. Case counts, event identifiers and content hashes do not
become evidence of discovery by themselves.

Use `analyze_coverage(inputs, seed=...)`, `measure_case(input)` and
`coverage_artifacts(inputs, seed=...)` from `dvi_sentinel.semantic_coverage`.
`CoverageCaseInput` contains actual V2-06 oracle evidence, a reference event set,
pinned input/reference digests and up to three existing schema profiles.
The producer pins digests before consumption. No caller-supplied branch name,
coverage score, fragility flag or oracle verdict is accepted as a measurement.

## Twelve measured dimensions

| Dimension | Observation source |
| --- | --- |
| `semantic_signal` | Existing ontology semantic identity from complete event evidence. |
| `invariant_state` | Recomputed semantic equivalence against the reference event with the same ID; all source/reference IDs must be accounted for. |
| `matcher_branch` | Actual matcher result reason and comparison field/outcome/reason combinations. |
| `adapter_path` | Successful parsing of supplied representation bytes through the existing adapter. |
| `schema_profile_path` | Executed profile roundtrip, decision and semantic disposition. |
| `temporal_relation_state` | V2-06 temporal oracle decision and reason codes from actual observations. |
| `oracle_disagreement_class` | Recomputed consensus and the diagnostic decisions that disagree. |
| `fragility_class` | Observed confirmed/probable timing or correlation gaps, explicit unclassified gaps, or existing schema-difference classes. |
| `field_mapping_path` | Actual projection field/path/state traces from requested profiles. |
| `normalization_loss_path` | Recorded profile issue paths and parsed adapter differences; no-loss is emitted only when the required analyses resolve. |
| `correlation_path` | Actual matcher key-comparison outcomes, with absent requests distinguished from missing requested evidence. |
| `evidence_quality_state` | Recomputed safety, provenance, schema, semantic and required-evidence gates. |

Every dimension has a state, sorted unique values, evidence paths and an
explanation. Measurements retain ontology extractions, equivalence checks,
normalized representations, mapping roundtrips, matcher comparisons, oracle
decisions and consensus. Paths resolve within the containing case record.
Missing representations, profiles, observations or reference evidence remain
explicitly unknown.

Existing adapter limits remain visible. For example, the V1 normalizer rejects
an empty CSV vendor field; that representation contributes unknown adapter
coverage. A successful alternative representation does not hide the failure.

Coverage values describe states and paths. They exclude case IDs, event IDs,
raw hashes and provenance hashes. The existing ontology semantic digest is the
intentional exception: it represents declared meaning rather than physical record
identity. A changed case ID or unbound raw metadata does not add discovery coverage.
Expected/observed literal values remain in measurement evidence instead of
creating a token for every incidental value.

## Retention and growth

Cases sort by a seed-derived digest of their complete canonical input. Input-list
order does not change the report. The profile list also canonicalizes before
measurement. A fixed seed/input yields identical cases, tokens and decisions.

Only values from known dimensions enter the coverage union. A case with any new
known value is retained, including a partially unresolved case that supplies
some new resolved evidence. Fully duplicate known cases are skipped as
`duplicate_coverage`. Cases without new known values are explained as
`unknown_coverage` or `unsafe_rejected` where applicable.

Growth is the exact cumulative union of `(dimension, value)` tokens. Repeating
an observation cannot inflate it. Each retained case records the precise tokens
it added. Models validate the union, growth arithmetic, row alignment, retention
and gate disposition when parsing the report.

A resolved mismatch or loss can be a known observation. For example, a measured
timestamp precision loss adds its path and retains the lossy mapping decision.
An unresolved profile is distinct from a measured loss. Unknown values stay in
the evidence but do not increase coverage.

## Evidence gate and scope

`coverage_evidence_gate(inputs)` recomputes measurements from inputs. It passes
only when all twelve dimensions resolve for every supplied case. It checks
skipped cases too: discarding an unknown case from the discovery queue cannot
make the evidence gate pass. Empty input yields an unknown gate result. Safety
or integrity rejection overrides the result.

This is an **evidence-resolution gate**, not a release certification. A known
negative result, semantic difference or lossy mapping is still an observation;
passing this gate does not say that every detector matched or every mapping was
lossless. Coverage does not imply security completeness, production effectiveness,
independent samples or coverage of unobserved behavior. There is no invented
percentage of all possible security behavior.

Fragility tokens describe bounded associations. Timing/correlation miss reasons
can name their existing classes; other detection gaps remain unclassified.
Disagreement alone does not establish a confirmed cause. Existing schema classes
come from actual adapter differences. Causal ranking belongs to later cards.

## Artifacts and bounds

The example emits exactly four files:

- `semantic_coverage.json`: inputs, measured evidence, twelve dimensions, the
  token union, retention, growth and evidence gate.
- `coverage_growth.json`: ordered additions, cumulative counts and final count.
- `discovery_queue.jsonl`: one retained/skipped decision per input in seeded order.
- `coverage_retention.json`: decisions and the evidence gate, including unknowns.

Inputs are limited to 16 cases, eight source/reference events per case, three
profiles and 256 KiB per complete case. Existing oracle limits also bound
observations, repetitions and representations. Each dimension has at most 1024
distinct values, and combined artifact output is limited to 32 MiB.

Safety and digest checks precede coverage consumers. Unsafe or integrity-rejected
inputs contribute no tokens and are not re-exported. Missing pins contribute
unknown coverage. Hashes establish content linkage, not external authenticity.
Models and analyzers perform no filesystem, network, subprocess or detector-service
I/O. The example runs local declarative controls, then writes fixed filenames to
a new validated local directory. No new dependency or V1 command change is needed.

Run the [example](../examples/semantic_coverage.py):

```powershell
.venv\Scripts\python.exe examples/semantic_coverage.py --out runs/v2/coverage-proof
```

It evaluates a timely alert, a late alert and a duplicate timely observation.
Two cases are retained, the duplicate adds zero coverage, and the measured union
has 34 tokens across the twelve dimensions. The
[behavioral tests](../tests/test_v2_coverage.py) verify new signals/branches,
adapter/profile paths, losses, disagreement, unknowns, tampering, duplicate
rejection, growth arithmetic and deterministic serialization.
