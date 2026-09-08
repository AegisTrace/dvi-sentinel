# Assumption probes

`run_probes(events, policy, harness)` performs sixteen fixed counterfactuals,
sorted by name. There is no feedback-directed search, external detector, clock,
random state, or network access. Each output declares its hypothesis,
transformation, expected invariant, observed result, finding class, rationale,
and JSON Pointer evidence paths within its JSONL record.

The baseline is evaluated once. A valid candidate is **fragile** only when a
baseline `(detector, signature)` identity disappears from complete candidate
observations. **Robust** means those identities survived this one test.
Additional candidate identities do not cancel missing baseline identities.
Missing fixture cases, empty baseline observations, ambiguous repeated detection
identities, and exhausted budgets are **unknown**, never measured misses.
Failed invariants are **invalid** and are not evaluated. Undeclared, unsupported,
unchanged, or already-tested equivalent candidates are **not_applicable**.

This observation comparison does not yet implement the expected-detection
matcher (Phase 8). It cannot detect changed title, severity, evidence, or latency
when detector/signature identities survive. It makes no statistical confidence
claim and does not establish universal resilience or causality.

## Transformations and permissions

| Probe | Permission | Protected meaning |
| --- | --- | --- |
| Fractional precision / timezone | timing | exact instant, all normalized fields |
| Schema alias / severity spelling | metadata | all normalized fields |
| Reversed order | ordering + order_independent | every original event and field |
| Optional sensor/vendor/confidence | dropout + named optional field | undeclared fields, raw payload, event semantics |
| Correlation, labels, tags removal | dropout + named optional field | same, under the scenario's optional-field declaration |
| Sensor/vendor alias | metadata + named optional field | same, with a fixed benign metadata alias |
| One duplicate | volume, maximum >= 1 | original coverage, exact duplicate lineage |
| Bounded volume | volume, maximum >= 2 | declared maximum number of duplicate additions |
| Benign background | noise, maximum >= 1 | original coverage; one labeled non-alerting UDP background record |

Source transformations take fresh raw-payload copies, encode one record using
its original supported adapter, and normalize independently. Precision changes
only redundant trailing zeros; six significant decimal places are not rounded.
Timezone changes retain fractional precision and the exact instant. Source alias
probing changes one supported field per record, not every possible alias. EVE
severity probes cover alert severity; canonical nested JSONL supports time
spellings but its strict numeric severity and field schema have no alternate
spellings. Unavailable transformations remain explicit.

Raw payloads and hashes are retained separately for original and candidate.
Because implicit IDs depend on raw bytes, one-record-to-one-record parsing
explicitly aligns the candidate's logical ID to its original. Counts must match;
all normalized fields, including labels, correlation, and sensor/vendor, must
compare equal. Representation checks intentionally exclude raw source and
normalization warnings, which describe the changed representation. They do not
permit semantic drift. Canonical optional-field probes use the independent
Phase 5 invariant checker and leave historical raw payloads intact.

## Bounds, evidence, and verification

Inputs require 1–10,000 unique event IDs and pass safety before the harness.
Every candidate is checked again. The run has sixteen candidate attempts and a
50,000 total event-occurrence budget including baseline; callers may reduce it.
`VariationPolicy.max_variants` limits the variation planner, not this fixed probe
catalog. A candidate ID collision is invalid, never silently renamed. Duplicate
candidate content is evaluated once. Separate transformations can legitimately
expose the same finding class. Stable IDs bind the spec, input, policy, resource
budget, and tool version. Observations and lineage are embedded for inspection.

`probes_jsonl` and `probes_markdown` are pure serializers. To write the concrete
proof artifacts, run `uv run python examples/probe_assumptions.py`. It writes
`runs/assumption-proof/assumption_probes.jsonl` and `assumption_probes.md`.
The general run artifact system is reserved for Phase 12.

`examples/probes/events.jsonl` and `rules.json` contain thirteen known fragile
local rules and a normalized-meaning negative control. `tests/test_probes.py`
checks each dependency individually, proves the volume threshold survives one
duplicate before failing at the declared maximum, checks all supported source
representations, and verifies robust controls, ambiguity, budget, safety,
invariant rejection, deterministic ordering, serialization, and source integrity.
