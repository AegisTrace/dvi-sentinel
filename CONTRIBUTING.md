# Contributing

Start with a concrete bug, missing proof or documentation correction. Keep V1
local, synthetic and fixture-based. Changes that introduce live targets, attack
traffic, credentials, executable scenario hooks or bypass recipes are outside
scope. Research directions belong on the [roadmap](docs/roadmap.md).

## Development

Use Python 3.12 or 3.13 and a virtual environment. From the repository root:

```sh
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src/dvi_sentinel
python -m coverage run -m pytest
python -m coverage report --fail-under=90
python -m build
python examples/run_benchmarks.py --out runs/contribution-benchmarks/benchmark_report.json
```

Use the executables inside your environment or activate it first. `uv sync
--locked --extra dev` is an alternative; prefix commands with `uv run` when using
that workflow. The [testing guide](docs/testing.md) explains generated cases,
failure replay and the Windows symlink-permission skip.

## Changes and review

- Inspect the existing contracts and relevant decision record before changing
  behavior. Keep parsing, experiments, matching, analysis and presentation separate.
- Add meaningful regression/edge tests for behavior changes. Use real local
  parsers and detectors; do not mock the outcome being proved or permit network
  access to make a test pass. Preserve a failing generated input when practical.
- Keep synthetic fixtures small, use documentation identifiers and record source
  provenance honestly. Never commit credentials, private telemetry, environments,
  run outputs or local agent instructions. `AGENTS.md` is intentionally untracked.
- Update the affected docs and changelog. State what changed, why, the exact
  validation performed, and any changed compatibility or limitations in the PR.
- Confirm the relevant benchmark controls still pass. Broaden testing when the
  affected contracts justify it; do not add a dependency or abstraction without
  a concrete implemented use case.

For a documentation-only change, check links and claims against the implementation.
CI still runs the full suite. Keep commits coherent and do not rewrite history to
manufacture a development narrative. Follow the [code of conduct](CODE_OF_CONDUCT.md);
report vulnerabilities through [SECURITY.md](SECURITY.md).
