# Baseline regression comparison

`dvi compare previous.json current.json` compares declared local
`ComparisonSnapshot` files. `--json` prints the complete machine-readable
`ComparisonResult`; the default view includes global metrics, family deltas,
case transitions, class transitions, and threshold decisions. Nothing modifies
the input files or starts a detector. Snapshot files are limited to 32 MiB each
and use strict duplicate-key-rejecting JSON parsing and local path checks.

`snapshot_from_plan` binds assessments to actual planned case content digests.
Snapshots retain comparison metadata, assessments, optional probe evidence, and
optional schema results. Frontier metrics are recomputed, not accepted as
authoritative self-reported scores. The integrated CLI also accepts verified run
directories and reads their captured `comparison.json`; see [CLI usage](cli.md)
and the [executed regression example](reproduction.md#verify-an-actual-regression).

## Compatibility before arithmetic

Both snapshots must use comparison schema 1 and the same tool version, scenario
ID, scenario digest, input digest, variation configuration digest, and seed.
Case sets, each case's input digest, family, and distance must agree. Probe and
representation coverage must also agree. Missing cases are incompatible, never
silently omitted from a rate. Incompatible results contain reasons and no metric
deltas. A new tool version requires an explicit migration policy, not an assumed
cross-version comparison.

`detector_digest` may differ: comparing a detector change is the purpose of the
operation. The caller's `scenario_digest` must cover static scenario meaning,
expected detection contract, and fixture declarations, excluding the changing
detector/harness implementation. The planner supplies input/config/case digests.
The run orchestrator computes these from the strict scenario. A standalone
declared snapshot is not an authenticated claim; directory inputs use the
[bundle integrity contract](run_artifacts.md).

## Deltas, transitions, and gates

Every metric delta is `current - previous`, globally and by family. Unavailable
metrics have null deltas. The report retains both full frontiers and the adapter
disagreement delta. There is no summary weighted score.

Case identities determine transitions, including the baseline if present:

- Newly missed: previously anything except a measured miss, now measured missed.
- Recovered: previously missed, now detected.
- Unchanged miss: measured missed on both sides.

Invalid and unparsed cases use the scoring engine's guarded unknown/invalid
outcome, even if their supplied match says detected. A previously unknown case
that is now measured missed is newly missed, not falsely claimed as a recovery.
New/removed fragility classes compare the evidence-linked taxonomy sets.

Default gates permit zero detection-rate drop, unknown-rate increase,
semantic-preservation drop, adapter-disagreement increase, and newly missed
cases. Each gate is independently configurable with:

```text
--max-detection-drop
--max-unknown-increase
--max-semantic-drop
--max-adapter-increase
--max-new-misses
```

Equality at the limit passes. Decimal subtraction of serialized metric values
avoids binary-float artifacts at simple decimal boundaries. The gate is inclusive
and does not use an undisclosed tolerance. Optional differential analysis absent
on both sides is excluded from that gate. A requested metric unavailable on
either side is unknown. A proven failed gate takes precedence over other unknown
gates, and every gate remains visible.

Exit 0 means all applicable thresholds passed; exit 1 means a proven regression;
exit 2 means incompatible, invalid input, or an unknown decision. Passing a
comparison means no disallowed deterioration; unchanged existing misses may
still pass. It is not an absolute release-quality gate. Empty/baseline-only
measurements cannot yield a successful detection-rate comparison.

`tests/test_comparison.py` runs real rules over identical planned duplicate
variations to prove regression, recovery, no change, new/removed classes, and
per-family deltas. It also checks every compatibility dimension, missing cases,
changed candidate contents, exact thresholds, deterministic order, empty unknown
results, strict parsing, and actual JSON/human CLI output and exit statuses.

## V2 drift and regression memory

The opt-in history library adds pinned local records, explicit named baselines,
ordered trends and a confidence-aware gate above the V1 comparison contract.
It reuses [V2 statistical confidence](statistical_confidence.md), including its
conditional sampling assumptions and unchanged V1 regression decisions.

```sh
python examples/regression_memory.py --out runs/v2/regression-memory-proof
```

The [example](../examples/regression_memory.py) executes four local measurement
batches: robust, fragile, unchanged fragile and recovered. Each batch has three
seeds and 32 declared metadata cases plus a baseline control. The 32 cases contain
16 sensor changes and 16 unchanged controls. Its named `release` baseline stays
bound to the first record after later appends and a verified local reload.

The adjacent classifications are `newly_fragile`, `still_fragile` and `recovered`.
The last run is also `stable_strong` against the named baseline. The example
explicitly selects a finite-fixture gate with a `low_confidence` minimum and a
0.15 maximum plausible detection-rate drop. The old regression remains a failed
historical edge; the final recovery and baseline comparison pass that declared
local policy. This does not certify population performance or release readiness.

### Records and explicit baseline registration

`DriftRecord` contains a unique ID, an explicit increasing sequence, a detector
revision, schema-profile stamps and a current-only `ConfidenceInput` seed batch.
The sequence is a caller-supplied ordinal; filenames and timestamps never infer
chronology. Each `PinnedRecord` retains its producer digest. Every case keeps the
V2-12 proof pin, actual events/observations and recomputable matcher evidence.

`DriftMemory` is immutable. `append_record` creates a new value and requires the
old memory's pin plus the new record's separately retained pin. Repeating the exact
same append is idempotent. Reusing an ID for other content or appending an earlier
sequence is rejected. Nothing silently drops or overwrites old records.

`register_baseline` binds an exact, case-sensitive name to a present record ID
and digest. Repeating the same binding is idempotent; replacing the target of an
existing name is rejected. Multiple explicit names may identify a record. Adding
a record never promotes it to baseline. Names are identifiers, never file paths.

```python
from dvi_sentinel.regression_memory import (
    append_record,
    register_baseline,
    regression_memory_artifacts,
)
from dvi_sentinel.regression_memory_io import load_regression_memory
from dvi_sentinel.regression_memory_models import DriftInput

memory = load_regression_memory(
    root, "regression_memory.json", expected_digest=trusted_memory_digest
)
updated = append_record(
    memory,
    measured_record,
    expected_digest=trusted_memory_digest,
    expected_record_digest=producer_record_digest,
)
registered = register_baseline(
    updated,
    "reviewed-baseline",
    measured_record.id,
    expected_digest=updated.stable_digest(),
)
request = DriftInput(
    memory=registered,
    current_id=current_record_id,
    named_baseline="reviewed-baseline",
)
# Retain this request pin when preparing the request, before later consumption.
artifacts = regression_memory_artifacts(request, expected_digest=producer_request_digest)
```

A request selects its current record explicitly. Its predecessor is the immediately
preceding record in sequence, including an incompatible or uncertain one; the
analyzer never skips inconvenient history. A selected historical record produces
only its prefix of trend points. A named baseline must be strictly earlier than
that selected current record. Missing current/predecessor/baseline references stay
unknown. Self or future baselines are incompatible. All retained history still
passes integrity checks, including records beyond a selected prefix.

### Compatibility and declared detector versions

Detector identity, comparison-contract ID and definition digest must link to the
captured snapshots and detector expectations. Version labels are opaque; there is
no inferred semantic-version compatibility. Different detector versions can be
compared under the same logical identity and declared comparison contract. A
single detector/version label mapping to multiple definition digests anywhere in
the supplied history makes affected comparisons incompatible, including
nonadjacent reuse. These labels are producer declarations, not authentication or
replayed detector execution.

Profile stamps contain the profile ID, revision and definition SHA-256 from the
existing built-in catalog. Paired records must use the same stamp set, and each
stamp must match the local supported definition. Unknown revisions, altered
mappings or changed profile sets are incompatible; no profile is downloaded or
silently migrated. Profile usage is declared context for canonical observations,
not proof that a historical projection was executed.

Statistical settings, seed sets and case expectations must match. V1's tool,
scenario, input, variation configuration, case-content, family/distance and schema
checks also apply. Metadata incompatibility is checked before paired arithmetic.
Any incompatible seed prevents a whole-record comparison; its reasons remain
visible and no partial seed effects are presented as a comparable cohort.

### Descriptive classifications

All classifications describe supplied local observations. Precision and a passing
gate are separate decisions. Baseline controls must be detected and variants must
have resolved outcomes for an ordinary transition classification.

| Class | Meaning |
| --- | --- |
| `stable_strong` | Both comparable runs detect every eligible variant. |
| `still_fragile` | Misses remain without newly lost detections; any partial recovery remains visible in the paired counts. |
| `newly_fragile` | At least one formerly detected case is now missed. |
| `recovered` | Previous misses have disappeared and the current variants all detect. |
| `unstable` | Losses and recoveries coexist, seed transition classes differ, or V2-12 reports unstable seed outcomes. |
| `incompatible` | Required identity, version, profile or comparison contracts differ. |
| `unknown` | Required references, baseline controls or case outcomes are absent, invalid or unresolved. |

Incompatibility is resolved before interpreting transitions. Within comparable
records, unresolved controls/cases take precedence over an ordinary class, and
instability takes precedence over improvement/decline labels. Across requested
predecessor/baseline comparisons, missing references give an unknown summary;
otherwise incompatible, unknown and unstable results take precedence. The full
pair-specific classifications and observations remain available.

### Confidence-aware regression gate

The gate has `pass`/0, `fail`/1 and `unknown`/2 outcomes. It applies to the selected
current versus its predecessor, plus the named baseline if requested. Older trend
failures remain recorded but do not permanently veto later recovery.

A retained V1 regression always fails the gate, even with tiny samples or an effect
interval including zero. Otherwise a pass requires all of the following:

- Compatible required comparisons and passing applicable V1 default thresholds.
- Detected baseline controls, nonempty variant denominators and no unknown/invalid cases.
- Complete measured seed agreement without V2-12 instability or conflicting transition classes.
- Every run/family estimate on both sides meets the configured confidence floor.
- Every run/family paired effect is available and its lower endpoint is at least
  `-max_plausible_detection_drop`.

The default minimum is `moderate_confidence` and the plausible-drop limit is 0.05.
A deliberate `low_confidence` floor is available for conditional finite-fixture
checks. Both policy values are covered by the request pin. A tighter interval
limit does not change V1 thresholds; a wider limit never excuses a V1 failure.
Equality at the configured boundary passes. Finding-specific singleton intervals
remain diagnostic; they cannot borrow a family's sample count to satisfy a gate.

One seed cannot establish cross-seed stability. Small samples, partial agreement,
weak precision, unresolved paired bounds or missing references prevent a pass.
Finite fixtures default to no IID assumption, so a default gate ordinarily stays
unknown unless its required sampling evidence is explicitly declared and sufficient.
V2-12's assumptions remain unverified and every calibration warning stays attached.
A `stable_strong` observational class can therefore have an unknown gate. An
unchanged, known fragile cohort can pass a no-regression policy and still be
`still_fragile`; this gate is not an absolute detector-quality threshold.

### Artifacts, local reload and integrity

| Artifact | Contents |
| --- | --- |
| `trend_report.json` | Full request, pinned history, per-record confidence, adjacent comparisons, named-baseline comparison and selected gate |
| `regression_memory.json` | Reloadable memory envelope with record pins, immutable baseline bindings and canonical memory digest |
| `baseline_registry.json` | Named bindings linked to the same memory/request digests |
| `comparison_with_uncertainty.json` | Paired V1 comparisons, effect intervals, descriptive classes and gates |

`load_regression_memory` reads a caller-selected local file using an external
canonical memory pin. It does not trust the envelope's own hash as an anchor.
Strict JSON parsing rejects duplicate keys/nonfinite values; network roots,
encoded/absolute/traversing/device paths, symlink/junction roots or children and
oversized files are rejected. A blocked envelope cannot supply history. A safe
memory from a report with missing comparison references can still be reloaded;
that does not convert its earlier gate into a pass.

Before any history matching/statistics, every retained record pin and registry
reference is checked, followed by the existing safety/provenance gates. Actual
case input digests and matcher results are then verified. Any authoritative failure
omits raw history and all estimates from exported reports. Malformed or inconsistent
observations raise validation errors. Full report validation verifies point/input
links and rederives transitions, compatibility and gates; nested confidence reports
reproduce their numerical evidence. Export slices are linked views, not independent
proofs. Pins establish content integrity, not authorship, real chronology or signed
attestation. The analyzer does not replay transformations or detectors.

Limits are eight history records, 16 baseline names, 512 total case proofs and
4 MiB for memory/the complete request. V2-12's per-run/event/bootstrap bounds still
apply. Reloads read at most 8 MiB including the envelope; combined outputs are at
most 32 MiB. Exhausting a bound raises an error without evicting history. The
example writes fixed filenames into a new plain local directory and refuses
replacement. Caller-owned files need a trusted local root; this is not a
concurrent transactional database or a hostile-filesystem race defense.

Models are category D, the history engine category A, the bounded reader category
R and example output category W. No runtime network, subprocess, plugin, callback
or dependency was added. Existing V1 CLI comparison and bundle contracts remain
supported; integrated V2 commands/reports arrive in their later cards. Behavioral
and negative coverage lives in [history tests](../tests/test_v2_regression_memory.py).
