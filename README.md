# DVI Sentinel

AegisTrace's detection resilience engineering project, under development.
The intended V1 scope is local, synthetic, fixture-based defensive telemetry.

The current package provides a validated
[canonical event model](docs/event_model.md), and strict
[scenario validation](docs/scenario_dsl.md) with a [safety policy](docs/safety_model.md).
Two [local detector harnesses](docs/detector_harness.md) evaluate explicit result
fixtures or small declarative rules. [Adapters](docs/adapters.md) normalize local
JSONL, CSV, and synthetic Suricata EVE fixtures. The
[variation planner](docs/variation_engine.md) generates
bounded deterministic cases with independently checked invariants and lineage.
[Assumption probes](docs/assumption_probes.md), [schema comparisons](docs/differential_testing.md),
[explainable matching](docs/matching.md), and [frontier metrics](docs/resilience_frontier.md)
operate on those local observations. `dvi compare` evaluates declared run snapshots
with [compatibility checks and regression thresholds](docs/regression_comparison.md).
[Failure shrinking](docs/failure_shrinking.md) retains minimal local evidence.
[Run bundles](docs/run_artifacts.md) capture fixtures, derived analysis, and verified
SHA-256 manifests for reproducible inspection.
[JSON, Markdown and local HTML reports](docs/reports.md) explain these results
with direct references to the underlying evidence.
The [local CLI workflow](docs/cli.md) connects these engines through `doctor`,
`validate`, `run`, `report`, `compare`, and `ci-check`.

## Development

Python 3.12 or 3.13:

```sh
python -m pip install -e ".[dev]"
dvi --help
dvi --version
ruff check .
ruff format --check .
mypy src/dvi_sentinel
pytest
python -m build
```

Alternatively, use `uv sync --extra dev` and prefix commands with `uv run`.
See [foundation notes](docs/foundation.md) for the implemented boundary.

## Safety

V1 is limited to local fixtures and synthetic telemetry. Live scanning,
exploitation, payload generation, credentials, stealth, persistence, command
execution from scenarios, and live detector integrations are out of scope.

MIT licensed. This development version is not a V1 release.
