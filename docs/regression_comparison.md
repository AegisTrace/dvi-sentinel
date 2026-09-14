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
