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
