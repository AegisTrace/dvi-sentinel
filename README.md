# DVI Sentinel

AegisTrace's detection resilience engineering project, under development.
The intended V1 scope is local, synthetic, fixture-based defensive telemetry.

The current foundation provides an installable Python package and CLI
help/version. Detection experiments are not implemented yet.

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
