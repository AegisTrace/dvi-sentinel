# Expert fixture benchmarks

The released **V1 suite** contains ten declared fragility families, each paired with a negative
control. All inputs are synthetic local files. Twenty independent scenario YAML
files share a two-event JSONL fixture; adapter checks also use equivalent and
deliberately changed CSV fixtures. `benchmarks/suite.json` declares each oracle:
target probe/representation, outcome, exact finding classes, matcher reason,
minimal counterexample characteristics and numeric metric bounds.

The runner evaluates actual parsers, declarative local detectors, variations,
probes, matching, scoring and shrinking. Oracles check the results after execution;
they never provide observations to the detector. Tests deliberately change an
oracle and prove that the measured evidence stays unchanged while acceptance
fails. All ten controls require zero findings, including findings outside the
selected probe.

## Run and inspect

From an installed checkout:

```sh
python examples/run_benchmarks.py --out runs/benchmarks/benchmark_report.json
pytest tests/test_benchmarks.py
```

The script prints one PASS/FAIL per case and exits 0 only when every declared
check passes. Failure output names the mismatched expected and observed values.
It refuses to overwrite an existing output; choose a fresh `--out` path to repeat.
The default destination is the one shown above. JSON records all per-case checks,
scenario/fixture SHA-256 digests, the suite digest, version, seed, complete plans,
assessments, frontier metrics, probe/differential evidence and available minima.
Pass/fail is derived from the recorded checks; it is not a weighted score.

The report contains no timestamps, absolute workspace paths or environment-dependent
metadata. Repeating the same inputs and version produces identical bytes. The
report is reproducible benchmark evidence, separate from the manifest-backed
`dvi run` bundle contract. CI runs the tests and records an additional report using
the installed wheel, then retains it alongside the normal fixture artifacts.

After building the image, with the host `runs/` mount prepared as described in
[Docker reproduction](docker.md):

```sh
docker compose run --rm dvi python examples/run_benchmarks.py --out /runs/benchmarks-docker/benchmark_report.json
```

The container includes the benchmark fixtures so this command is also offline.
Native and container reports can be compared directly by SHA-256.

## Declared findings

Every baseline detects both original events. Fragile probe examples lose that
detection with `DVI-MATCH-NO-CANDIDATE`; controls retain it with
`DVI-MATCH-DETECTED`. The local rules require two matching original observations.
The table describes the fragile case; its paired control uses normalized action
and severity, with no dependency on the changed optional representation.

| Family | Deliberate dependency / finding | Minimal safe counterexample | Variant detection rate |
| --- | --- | --- | --- |
| Schema alias | Raw `src_ip` spelling; `schema` | One original uses an equivalent alias | 1 |
| Timestamp precision | Literal `.000000` timestamp text; `timestamp_timezone` | One original omits redundant fractional zeros | 1 |
| Timezone | Literal `Z` spelling; `timestamp_timezone` | One original expresses the same instant with an offset | 1 |
| Ordering | Input must arrive in timestamp order; `ordering` | Two originals with one inversion | 0 |
| Optional field | Optional sensor field must exist; `optional_field_dependency` | One original loses its optional sensor | 0 |
| Severity mapping | Raw integer `4` required; `severity_normalization` | One original uses equivalent textual severity | 1 |
| Correlation key | Optional correlation ID required; `correlation_key_dependency` | One original loses its optional correlation ID | 0 |
| Benign noise | Total input count may not exceed two; `noise_sensitivity` | Two originals plus one unrelated safe noise event | 0 |
| Volume | Matching input count may not exceed two; `volume_sensitivity` | Two originals plus one semantic duplicate | 0 |
| Adapter disagreement | CSV changes one action; `adapter_disagreement` | Not applicable: protected meaning changed | Not measured |

The representation-sensitive cases can have a variant detection rate of 1 while
their targeted source-representation probe fails. Planner variants and assumption
probes are separate measurements; their denominators are never blended. Controls
have variant detection rate 1, except the adapter-only cases, which have no planner
variants and explicitly require a null rate. Correlation dropout also receives
the planner's coarser `optional_field_dependency` class; both classes are declared
and asserted rather than hiding the extra association.

The adapter example supplies a deliberately inconsistent CSV action, compared
against the original JSONL semantics. Its disagreement rate is exactly 1; the
equivalent CSV control is exactly 0. This proves that the comparison catches a
known semantic mapping difference. It does not imply an actual bug in an external
adapter, or a safe detector-failure reproducer. The report shows the changed field
and suppresses a misleading minimum claim for that case.

## What this evidence supports

The fixed suite uses seed 42, at most eight planned cases per scenario, a
256-event planning/probe budget, and the existing bounded shrinker. Its nine safe
fragility examples reach their declared minima with original-event coverage and
semantic invariants intact. The minima are local to supported reductions and
these fixtures. Tests verify every expected count, changed original, added event,
ordering inversion, final reason, finding class and invariant result.

These are intentionally small diagnostic examples, not a prevalence study,
performance benchmark, live product evaluation or evidence of universal discovery.
The rules are transparent fixtures. The suite establishes that implemented V1
mechanisms identify the specified weaknesses and protect these robust controls
from invented findings. It does not claim full schema compliance, real-world
detector robustness, or coverage of all possible hidden dependencies.

## V2 expert suite

The development suite adds **32 cases across all 16 V2 categories**, with one
diagnostic and one control per category. Its independent declarations live in
[`benchmarks/v2/suite.json`](../benchmarks/v2/suite.json). The V1 manifest and
report format remain unchanged. Eight pairs reuse real V1 measurements; the
other eight call the implemented temporal, mapping, intent, oracle, statistical
and provenance engines. This is a fixture benchmark, not a V2 release.

```sh
python examples/run_v2_benchmarks.py --out runs/benchmarks/v2
python examples/run_v2_benchmarks.py --case sequence_window_fragility-diagnostic --out runs/benchmarks/sequence
pytest tests/test_v2_benchmarks.py
```

Use a new output directory. Exit **0** means all selected expectations matched;
**1** means a measured regression, with evidence still written; **2** means invalid
input or an output error. `--root` selects another local benchmark root containing
`v2/suite.json` and its declared sources. A selected case is explicitly marked
`selected_case`; it cannot claim complete suite coverage. Commands in the manifest
are inert proof instructions and are never executed by the runner. The combined
`dvi` CLI integration remains V2-18.

| Category | Diagnostic fixture and independent control | Measured score |
| --- | --- | --- |
| `schema_alias_fragility` | Raw alias dependency / normalized-field rule | V1 planned-variant detection rate |
| `timestamp_precision_fragility` | Literal fractional spelling / normalized rule | V1 planned-variant detection rate |
| `timezone_fragility` | Literal UTC suffix / normalized rule | V1 planned-variant detection rate |
| `sequence_window_fragility` | Two events at a 10 ms limit, then a 1 ms shift / 20 ms rule window | Target counterfactual detection rate |
| `correlation_key_fragility` | Optional correlation key required / key-independent rule | V1 planned-variant detection rate |
| `severity_mapping_fragility` | Raw integer severity / normalized severity | V1 planned-variant detection rate |
| `optional_field_dependency` | Optional sensor required / sensor-independent rule | V1 planned-variant detection rate |
| `benign_noise_sensitivity` | Total-count cap / uncapped local rule | V1 planned-variant detection rate |
| `adapter_disagreement` | Changed CSV action / equivalent CSV | Adapter disagreement rate |
| `normalization_loss` | Supplied representation changes protected action / canonical round trip | Known representation agreement rate |
| `rule_intent_mismatch` | Flow evidence against DNS intent / flow intent | Known single-event intent support rate |
| `sensor_source_drift` | Sensor B against declared sensor A / sensor A | Known single-event intent support rate |
| `cross_profile_semantic_loss` | DNS name lost through Zeek-like connection subset / retained by ECS-like subset | Known representation agreement rate |
| `oracle_disagreement` | Timely alert with wrong signature / correct signature | Primary detector contract rate |
| `statistical_small_sample_warning` | Four fixture trials / 32 fixture trials, each excluding baseline | Known local trial detection rate |
| `provenance_tamper_detection` | Append one byte to a captured source after hashing / intact bundle | Fraction of DAG artifacts without integrity failures |

The window case calls the detector and temporal predicate independently, checks
semantic preservation, and uses the real shrinker. The 1 ms shift reduces to
**1 microsecond** beyond the 10 ms boundary, the smallest supported datetime unit;
both original events remain. Other detector minima retain event counts, changed
originals, added events, inversions and maximum time shift. These are minima under
the implemented finite reductions, not global proofs. Analysis-only cases declare
why detector minimization is not applicable.
Missing baseline, unresolved timing/invariant evidence or a missing reduction for
a measured failure instead produce an unavailable minimum. A detector can emit
an alert while the temporal predicate remains unknown; the detection rate retains
that observation, but the benchmark state stays unknown and fails a resolved-control
expectation. Rate and evidence resolution are separate checks.

The normalization fixture models a supplied changed representation; it does not
claim the canonical normalizer has a defect. Sensor drift is checked against a
declared source contract, not a longitudinal sensor population. The profile case
retains **unknown** when required DNS evidence disappears: the score has a zero
known denominator, null value and one unknown. Passing this expected-unknown
diagnostic does not certify the input or satisfy any deployment gate.

The oracle pair retains all nine decisions, the primary observation and three
actual local replays. A wrong signature fails detection/statistical checks while
the timely alert passes the temporal check, so consensus is `ambiguous`. The
correct signature yields `suppressed_false_positive` for the proposed gap.
Other categories explicitly declare oracle aggregation not applicable, rather
than inventing votes about a non-detection diagnostic.

Statistical inputs are finite genuine fixture observations, without an IID claim.
Four known trials produce `insufficient_sample`; 32 remove the small-sample warning
but remain `low_confidence`. Both retain dependent-fixture, conditional latency
and unmeasured seed-stability warnings. Other categories do not borrow confidence
from an unrelated cohort. Replays, trial counts and variant counts are distinct.

The provenance pair builds an actual local run and its artifact DAG. The diagnostic
changes only an in-memory source copy; source files are never edited. Nine of ten
DAG artifacts become invalid, including unchanged descendants, leaving an integrity
rate of 1/10. The intact control remains 10/10. The bundle verifier also detects the
stale materialized integrity view. Hashes prove consistency, not authorship.

### V2 output and boundaries

- `benchmark_report.json`: strict suite declarations, selected scope, byte hashes
  and sizes for every consumed source, native engine evidence, derived summaries
  and each expected/observed comparison. Pass/fail is derived from checks.
- `benchmark_report.md`: escaped human-readable matrix and regression details.
- `benchmark_matrix.json`: full report byte hash, per-case evidence hashes and
  JSON pointers linking summaries to native evidence, checks and source pins.

Every case declares its ID, scenario, complete fixture inventory, expected findings,
minimum, score range, consensus, confidence class and reproducible proof command.
Expected values and control labels do not drive measurements. Tests alter each
expectation independently, change actual detector inputs, and verify failure exits.
The legacy engine's original declarations/checks are retained as supporting evidence;
V2 acceptance is computed separately from its measured outputs. Report export
revalidates typed evidence, checks, coverage and summaries; it does not authenticate
the author or independently replay a replaced report. Keep external source/report
hash pins when comparing separate executions.

The suite validates all selected scenarios and source inventories before execution.
Operations are a fixed typed set, with no callbacks, network, external detector,
subprocess or executable input. Paths must be portable, confined local files;
network roots and symlink/junction ancestors are rejected before access. Limits:
32 cases, 128 KiB suite/scenario files, 2 MiB per fixture, 16 MiB total selected
unique inputs, 8 original events for reused V1 cases or 64 for new cases, at most
8 planned variants/noise events/duplicates per scenario, and 32 MiB combined output.
The declared event budget bounds planning/probes; native diagnostic operations
have their own finite event and replay bounds. Existing engine safety checks apply.

Outputs use fixed filenames in a new local directory and refuse overwrite. An
unexpected filesystem write failure can leave a partial new directory; exit 2
does not certify that directory. The supported filesystem is local and has one
trusted writer; this does not defend against hostile concurrent path replacement.
CI executes both suites through the built wheel on Python 3.12 and 3.13 and retains
the reports. Identical inputs and package version produce identical bytes.
