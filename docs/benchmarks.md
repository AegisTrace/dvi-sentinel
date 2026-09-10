# Expert fixture benchmarks

The suite contains ten declared fragility families, each paired with a negative
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
