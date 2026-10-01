# Local CLI workflow

The installed `dvi` entrypoint and `python -m dvi_sentinel.cli.main` expose the same
Typer application. Commands perform local fixture work only. Run from a checkout
after `python -m pip install -e ".[dev]"`, or prefix commands with `uv run`.

```sh
dvi doctor --json
dvi validate examples/artifact_scenario.yaml --json
dvi run examples/artifact_scenario.yaml --out runs/cli-proof --seed 42 --json
dvi ci-check runs/cli-proof --threshold 1 --json
dvi report runs/cli-proof --overwrite --json
dvi compare runs/cli-proof runs/cli-proof --json
python -m dvi_sentinel.cli.main --version
```

The count-threshold example intentionally records nine misses among eleven
variants, so `ci-check --threshold 1` exits **1**. Completion of `run` exits **0**
because it successfully measured and saved the experiment. Repeating `run` against
the same destination requires `--overwrite`; only a verified DVI bundle can be
replaced. Run directories are ignored by Git.

| Command | Behavior |
| --- | --- |
| `doctor [--json]` | Read-only Python/package version checks and packaged report-template availability. No network or external detector probes. |
| `validate <scenario> [--json]` | Apply scenario policy, read and normalize every telemetry fixture, enforce unique IDs across files, validate detector-result fixture safety, and print allow/warn decisions. |
| `run <scenario> --out <dir> [--seed 42] [--json]` | Plan, evaluate, match, probe, compare schemas, shrink one eligible failure, generate reports, and publish a verified complete bundle. |
| `report <run-or-dir> [--baseline <run>] [--overwrite] [--json]` | Regenerate reports from verified evidence, optionally including compatible baseline regression. |
| `compare <baseline> <current> [--json]` | Compare verified run bundles or explicitly supplied standalone comparison snapshot JSON. See regression comparison documentation for limits. |
| `ci-check <run-or-dir> [--threshold <ratio>] [--max-unknown <ratio>] [--json]` | Check the declared baseline and variant acceptance policy described below. |

Run defaults include assumption probes, differential testing and shrinking. Use
`--no-probes`, `--no-differential`, or `--no-shrink` to omit an analysis explicitly.
`--event-budget` is bounded to 1..50000 event occurrences per planner/probe engine;
it must cover the original input. Shrinking retains the existing bounded attempt
and ablation limits. It selects the first eligible variation by family, then by
distance within that family and ID. If none misses, it selects the first fragile
probe by catalog name. Only one counterexample is shrunk per CLI run; schema-only
disagreements are retained in the differential report. A detected baseline is
required before shrinking. No global distance ordering is implied.

Fixture paths resolve beside the scenario. Malformed, unsafe, missing or partially
parsed inputs fail before publication. Completed observations can be unknown;
missing detector-result cases never imply a measured miss. Temporary staging is
owned by the process, and the destination is published only after report generation
and artifact verification succeed. A read-only ordinary-checkout HEAD lookup
records the git commit when available; unsupported worktree metadata or missing
git data yields `null`, with no subprocess fallback.

Run commands are stored as explicit argument arrays with effective seed, budget
and analysis switches. Output and report paths are printed as absolute paths.
`run-or-dir` accepts a run directory or its `run.json`, `manifest.json`, or
`report.json`. Consumer commands verify the entire bundle before using it.
Standalone comparison snapshots remain supported explicitly, but have no manifest
integrity guarantee; supplying a directory selects the verified-bundle path.

## CI acceptance policy

`--threshold` is a ratio in **[0,1]**, the inclusive minimum detection rate among
semantically valid variants. It defaults to `scoring.min_detection_rate`.
`--max-unknown` is the inclusive unknown-rate ceiling, defaulting to
`scoring.max_unknown_rate`. Both reject NaN/infinity. Baseline counts are excluded
from these rates. Additionally, the baseline must detect, no variant may violate
semantic invariants, at least one variant must have a measured decision, and the
planner must not exhaust its event budget.

This gate assesses the declared baseline/variant thresholds. Probe and differential
findings remain separate report evidence; they are not folded into a weighted
score or silently used as extra threshold criteria. A passing gate is limited to
these checks, and does not certify all counterfactual or schema behavior. For
regression use `dvi compare`, which retains compatibility checks, new misses,
unknown-rate changes, adapter deltas and the configured comparison thresholds.

Exit codes are stable:

- **0**: command completed; for comparison/CI commands, configured checks passed.
- **1**: a measured comparison regression or CI gate failure, including exceeding
  the allowed unknown rate. A known failed check takes precedence over an unknown.
- **2**: invalid input, unsafe path/content, failed integrity, unavailable runtime,
  incompatible comparison, or insufficient evidence without a known failed check.

Expected input errors produce concise messages without stack traces. `--json`
returns canonical schema-versioned JSON for command results and execution errors;
argument-parser usage errors still use Typer's normal stderr output and exit 2.


### Advanced V2 report format

`dvi report <run> --advanced [--overwrite] [--baseline <prior>] [--json]` renders
all eighteen V2 sections and a local stylesheet/portable ZIP from a verified
schema-2 bundle. Native analyses are optional but, when present, must match the
run's evidence. This is report consumption, not execution of new analysis stages.
An existing schema-3 report keeps its format on regeneration without the flag.
See [V2 report contracts, limits and example](report_v2.md).

## V2 analysis commands

The ten V2 commands run the existing local engines as explicit analysis stages.
They accept typed JSON inputs, except `analyze-rule`, which accepts a local rule
declaration plus a typed events file, and `benchmark`, which accepts a suite root.
`--json` returns a schema-1 command envelope containing the complete native
`result`, a measured human summary, input byte hashes and native artifact hashes.
Without that flag the command prints a concise summary. `--out <new-directory>`
also writes the native artifacts and the same envelope as `command_result.json`.
Omitting `--out` performs no artifact writes.

| Command | Input and measured output |
| --- | --- |
| `ontology <events.json>` | `EventInput`; default ontology extraction, known/unknown signals, bindings and semantic losses. |
| `map-schema <events.json>` | `EventInput`; all seven local profile roundtrips, explicit field losses and alias paths. These are declared subsets, not full standard compliance. |
| `analyze-rule <rule> --events <events.json> [--format dvi]` | Native intent YAML/JSON by default; `sigma_metadata` selects the bounded metadata subset and `v1_rule` selects one local rule. Reports evidence support and unsupported conditions. |
| `temporal <temporal.json>` | `TemporalInput`; time-window, sequence and correlation evidence, with source precision and missing keys retained. |
| `oracles <oracles.json>` | Native `OracleEvidence`; recomputes nine checks and consensus. Missing evidence stays unresolved. |
| `explore <explore.json> [--seed N]` | `ExplorationInput`; feasible covering cases, constraints, rejected combinations and budget omissions. Plans cases; does not execute detector observations. |
| `explain <explain.json> [--seed N]` | Native `CounterfactualInput`; executes its bounded local declarative harness and measures minimal transformation sets and conditional effects. |
| `confidence <confidence.json> [--seed N]` | Native `ConfidenceInput`; observation-linked rates, bootstrap intervals, seed agreement and comparison uncertainty. The seed overrides only the bootstrap seed. |
| `graph <counterfactual_summary.json>` | Native `CounterfactualSummary`, such as the artifact from `explain`; validates retained evidence and builds graph/weak-edge/recommendation views. Recommendations remain untested. |
| `benchmark <root> [--case ID]` | Root containing `v2/suite.json`; defaults to all 32 expert cases. Compares actual measurements with independent expectations and writes report/matrix artifacts. |

Every row supports `--json`, `--out`, `--help` and `--input-sha256 <hex>`.
The optional pin checks the exact primary input bytes before analysis; for
`benchmark` it pins `v2/suite.json`. `analyze-rule` additionally supports
`--events-sha256`. These pins establish content consistency, not authorship.
Each result records source digests even when no external pin is supplied. Captured
inputs are checked again before publication; benchmark fixture capture/rechecking
uses the existing expert runner. Each native input retains its own integrity rules.

`EventInput` is `{"schema_version":"1","events":[...]}`, where every entry is a
complete canonical `TelemetryEvent` or `DetectionEvent`, including raw provenance.
Detection subtypes are preserved. `TemporalInput` adds `window_ms` (default 1000),
`pattern` (default empty) and `precision_digits` (default 0).
`ExplorationInput` adds the existing `space`, `policy`, optional `budget`, and
`seed` (default 42). The other inputs use the native models documented in
[oracles](oracle_consensus.md), [counterfactuals](counterfactual_causality.md),
[confidence](statistical_confidence.md) and [graphs](knowledge_graph.md).
Unknown fields are rejected. Input files are standalone requests, not unverified
run directories; the existing bundle consumer commands still verify their manifests.

The runnable [CLI example](../examples/v2_cli.py) creates these requests from real
synthetic fixture execution, invokes every command and links `explain` to `graph`:

```sh
python examples/v2_cli.py --out runs/v2/cli-example
dvi ontology runs/v2/cli-example/inputs/events.json --json
dvi map-schema runs/v2/cli-example/inputs/events.json --json
dvi analyze-rule runs/v2/cli-example/inputs/rule.json --format v1_rule --events runs/v2/cli-example/inputs/events.json --json
dvi temporal runs/v2/cli-example/inputs/temporal.json --json
dvi oracles runs/v2/cli-example/inputs/oracles.json --json
dvi explore runs/v2/cli-example/inputs/explore.json --seed 42 --json
dvi explain runs/v2/cli-example/inputs/explain.json --seed 42 --out runs/v2/explanation --json
dvi confidence runs/v2/cli-example/inputs/confidence.json --seed 42 --json
dvi graph runs/v2/explanation/counterfactual_summary.json --json
dvi benchmark benchmarks --out runs/v2/benchmark-cli --json
```

Exit **0** means an analysis completed, including measured losses, local misses or
diagnostic unknowns. It does not mean a detection is robust or a release is accepted.
`benchmark` exits **1** when a completed measurement fails a declared expectation;
its output retains the failed checks and actual evidence. Malformed or unsafe
inputs, changed hashes, blocked authoritative evidence and invalid destinations
exit **2** with a concise error. The existing `ci-check`/`compare` release-blocking
unknown behavior is unchanged. Native diagnostic uncertainty is never converted
to a passing release verdict.

All request reads reject network roots, links/junctions and device/traversal paths.
The CLI read ceiling is 4 MiB, with a 128-KiB rule/suite ceiling; lower native limits
still apply (including 32 mapping/exploration events and eight counterfactual events).
Combined output, including the envelope, is capped at 32 MiB. Output directories
must be new; there is no overwrite option. A filesystem failure may leave a partial
new directory and returns exit 2. Local paths assume one trusted writer; hostile
concurrent filesystem replacement is outside this contract.

Identical inputs and effective seeds produce identical native artifacts and command
JSON; output paths and wall-clock timestamps are excluded from these results.
The benchmark seed belongs to its declared suite. CLI seed overrides are retained
in the native effective input or plan, alongside the original input byte pin.
These commands do not silently choose a detector, invent missing evidence, append
unlinked analyses to a run bundle, or replace the existing `run` workflow.
