# Engineering contract

The Trello MASTER card and numbered phases govern implementation:
https://trello.com/c/NuidKDC1/70-master-codex-autopilot-v1-build

Read the current phase before coding. Implement phases sequentially; do not
scaffold future functionality. Complete tests, documentation, diff review,
safety review, commit, push, and available CI verification before advancing.

Only local synthetic/fixture telemetry is allowed. Runtime code must never
launch commands, access live targets, generate attacks, or consume credentials.
No scenario-sourced execution, network integrations, or bypass instructions.

Use typed boundaries, deterministic serialization, explicit failure reasons,
cohesive modules, and real behavioral tests. Preserve unrelated user changes.
Run `ruff check .`, `ruff format --check .`, `mypy src/dvi_sentinel`,
`pytest`, and `python -m build` in the development environment.

Never mark a phase complete while required remote verification is unavailable.
Do not tag a release until every V1 release gate passes.
