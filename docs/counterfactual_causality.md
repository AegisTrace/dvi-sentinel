# Local counterfactual failure mining

V2-10 finds safe changes associated with a missed detection in a local declarative
rule fixture. It starts with an actual detected baseline, tests individual changes,
selects combinations through the existing covering-array engine, and verifies
subset controls before making a minimality claim. No external detector is called.

Use `CounterfactualInput`, `CounterfactualDimension` and `CounterfactualBudget` from
`dvi_sentinel.counterfactual_models`, and `mine_counterfactuals` or
`counterfactual_artifacts` from `dvi_sentinel.counterfactuals`. The producer retains
a complete input digest before consumption:

```python
input_digest = request.stable_digest()
report = mine_counterfactuals(request, expected_digest=input_digest)
```

The request contains one to eight canonical events, one to six named binary
dimensions, a V1 variation policy and detection expectation, a local rule harness
configuration, seed, interaction strength and execution budget. Each dimension
selects one existing non-identity probe operation, such as dropping an explicitly
optional sensor field. An inactive dimension uses identity. Names and operations
must be unique. A dimension is a declared probe operation, not necessarily one
physical field across the entire event set.

Dimension declarations, rule declarations and policy sets canonicalize before
hashing. Event order remains meaningful and is preserved. Fixed input and seed
produce identical observations, rankings and artifact bytes. Strength is capped
at the number of dimensions; a single dimension needs no combination array.

## Measured search and eligibility

The analyzer reuses [constraint exploration](constraint_exploration.md)'s safe
materialization and covering selection. Policy permissions, independently checked
V1 invariants and final V2 ontology equivalence determine eligibility. Safety and
pinned-input checks precede consumers. An unresolved baseline meaning blocks
detector evaluation. A missing, unknown or missed baseline stops the search and
cannot support a new-failure claim.

After a detected baseline, every bounded subset receives an eligibility result.
The execution order is:

1. Each single active dimension in name order.
2. Seeded covering-array rows over eligible combinations.
3. Every proper subset of each observed missed combination, in increasing size/name order.

Before execution, a candidate must reproduce its eligibility digest. Unexpected
engine errors propagate; changed replay content is rejected. Each subset executes
at most once. Baseline, singles, combinations and subset controls share the same
case/event budget. An unaffordable row does not prevent later affordable rows.
Unknown observations consume the budget but never count as misses.

The report accounts for every subset after the baseline is proven. Cases retain
active dimensions, execution stage/index, candidate hash, events, transformation
checks, actual harness observations and matcher evidence. Rejected cases retain
reasons without unsafe candidate content. Unselected or budget-skipped cases remain
explicitly unobserved. The covering plan and actual executed interaction count are
separate; interaction coverage says which combinations ran, not whether they passed.

Any rejected, unknown or budget-unresolved requested case leaves the study
`incomplete`. Verified findings can still be retained with their own controls.
An eligible subset omitted because its interactions were already covered is
`not_selected`; this does not mean every possible subset was tested. A robust
control can therefore yield `no_failure_observed` only within the measured cases.

## Minimal sufficient sets

A measured miss is sufficient for this configured local expectation to fail.
It is **inclusion-minimal** only when every proper subset is measured and detected.
The empty subset is the original detected baseline. Restoring any dimension in a
verified minimal set therefore restores detection under these tested conditions.

Checking only immediate single-deletion neighbors is insufficient: a rule can
lose detection, regain it after another change, and lose it again. The miner
checks every proper subset and makes no monotonicity assumption. A known smaller
miss marks the larger set `nonminimal`. Missing, invalid or unknown subset controls
make it `unresolved`; the sufficient miss remains visible without a minimality claim.

All observed misses appear in `FailureSet` records. Only verified minimal sets
become `CounterfactualFinding` records. Several distinct minimal sets may exist.
The search does not guarantee a globally smallest undiscovered set or discovery
of all minimal sets. This card reduces sets of transformations; event/field delta
debugging is available through the [V2-11 oracle-aware shrinker](failure_shrinking.md).
That stricter mode requires confirmed multi-oracle evidence. A missing-alert case
with unknown timing stays unresolved instead of acquiring a stronger claim.

## Effects, rankings and confidence

For each dimension, compare every measured pair differing only in that dimension.
The paired delta is +1 for detected-to-missed, -1 for missed-to-detected, and zero
when the outcome is unchanged. The mean is:

```text
(loss pairs - recovery pairs) / measured pairs whose actual input changed
```

Identical-input pairs are counted separately and excluded from that denominator.
If no changed pair is measurable, the mean is unknown. Every possible pair remains
accounted for: untested, invalid and unknown observations increase unavailable
pairs rather than disappearing. Pair records link the actual case IDs and direction.

Rankings prioritize membership in verified minimal sets, then descending mean
paired effect, loss-pair count and dimension name. They are deterministic local
rankings, not estimates of population causality. Confidence labels describe evidence:

- `verified_local_subset_controls`: all proper subsets of a linked minimal set were detected.
- `partial_local_pairs`: changed local paired observations exist without verified necessity.
- `insufficient_evidence`: no changed paired effect can be measured.

Findings say the changes are **associated with this local fixture**, **necessary
under this tested scenario** within the verified minimal set, and a **likely
contributor** to the observed local miss. Necessity is conditional on that set and
fixture; it does not extend to every context. Counts and mean deltas are descriptive.
They are not independent samples, causal probabilities, statistical confidence
intervals or production-effectiveness measurements. The later statistical card
has its own sampling and uncertainty contract.

## Artifacts, safety and reproduction

Each analysis recomputes four files from the pinned request:

- `counterfactuals.jsonl`: every case with actual observations or explicit nonexecution.
- `minimal_failure_set.json`: every observed failure set and verified conditional findings.
- `causal_rankings.json`: measured paired effects, rankings, confidence labels and limitations.
- `counterfactual_summary.json`: input, all evidence, covering plan, budgets, findings and rankings.

Models validate input/content linkage, observation identity, transformation chains,
evaluation budgets, subset accounting, minimality controls, effect denominators and
executed coverage. Loading JSON does not rerun the detector or authenticate the
producer; reproduce observations through the input-based API. Hashes establish
content linkage against a separately retained pin, not external authenticity.

The new models and analyzer are pure local components. The harness is the existing
bounded declarative `RuleLogicHarness`; requests cannot provide arbitrary callbacks,
fixture lookup paths, subprocesses, executable rules or external services. Limits
are 256 KiB per complete input, eight original events, six binary dimensions,
eight local rules, 64 subsets, 128 events/2 MiB per transformed candidate, at most
64 detector evaluations and 4096 evaluated events, and 32 MiB combined artifacts.
Source safety/integrity failures block consumption and omit input content.

Run the [example](../examples/counterfactuals.py) under a new local directory:

```powershell
.venv\Scripts\python.exe examples/counterfactuals.py --out runs/v2/counterfactual-proof
```

It writes the four files for each of three actual controls: a sensor-dependent
rule, independent sensor/vendor rules that fail only when both fields change, and
a robust category-based rule. The first two produce one- and two-dimension minimal
sets; the robust control produces no failure claim. Tags are irrelevant to those
local rules. See [the behavioral tests](../tests/test_v2_counterfactuals.py) for
non-monotonic outcomes, unknown controls, budgets, safety, replay and artifact proof.
These files do not replace a verified V1 run bundle or certify a V2 release.
