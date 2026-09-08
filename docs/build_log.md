# Build proof record

## Phase 0 — Repository foundation

Acceptance came from the Phase 0 card on the authoritative Trello board:
https://trello.com/c/VAqoeXaO/6-phase-0-repository-foundation

Implemented only packaging, CLI help/version, behavioral smoke tests, tooling,
foundation documentation, CI, and minimal Docker/Compose execution. The parent
workspace had an empty Git repository; a separate `dvi-sentinel` repository was
created without altering it. Git identity uses the authenticated AegisTrace
account and its GitHub noreply address, configured only in this repository.

Local proof on 2026-09-08:

- `uv sync --python 3.13 --extra dev`: passed (Python 3.13.15).
- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed.
- `uv run mypy src/dvi_sentinel`: passed, 3 source files.
- `uv run python -m coverage run -m pytest`: 4 passed; coverage 85%.
- `uv run python -m build`: wheel and sdist built successfully.
- `uv run python -m dvi_sentinel.cli.main --help`: passed.
- `uv run dvi --version`: `dvi-sentinel 0.1.0.dev0`.
- `.venv312/Scripts/python.exe -m pip install -e ".[dev]"`: passed.
- `.venv312/Scripts/python.exe -m pytest`: 4 passed (Python 3.12.14).
- `.venv312/Scripts/python.exe -m dvi_sentinel.cli.main --version`: passed.
- `docker build -t dvi-sentinel:foundation .`: passed.
- `docker run --rm --network none dvi-sentinel:foundation dvi --version`: passed.
- `docker compose run --rm dvi`: passed, help displayed.

Source review: the only runtime behavior is help/version presentation, with no
scenario ingestion, network operations, subprocess calls, or telemetry changes.
These checks establish the foundation only; they do not establish V1 readiness.
Remote CI status and phase completion are recorded on Trello after verification.
