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

## Phase 1 — Canonical security event model

Acceptance: typed telemetry/detection/entity/endpoint/semantics boundaries,
explicit optional metadata, UTC normalization, immutable raw snapshots, stable
digests, meaningful unit/property tests, and field/tradeoff documentation.

`uv run pytest tests/test_models.py`: 35 passed. Full `uv run python -m coverage
run -m pytest` and `.venv312/Scripts/python.exe -m pytest`: 39 passed on each
version. Ruff check, format check, strict mypy (5 source files), and package
build passed. Combined branch coverage: 97%. `examples/canonical_event.json`
was produced through the real validated model and canonical serializer.

Review found no networking or executable scenario behavior. Raw-payload copies
cannot mutate stored evidence; hash verification rejects tampered snapshots.
The model does not claim policy safety or standards compliance. Detection
evaluation remains outside this phase. Phase 0 remote CI was green on both
versions at commit `a8aa584` before this phase began.

## Phase 2 — Scenario DSL and safety policy

Acceptance: strict bounded YAML, explicit local/synthetic/no-execution
declarations, safe relative fixture paths, stable allow/reject/warn decisions,
documented rule IDs, and negative tests for each prohibited capability class.

`uv run pytest` and `.venv312/Scripts/python.exe -m pytest`: 112 passed and one
documented Windows symlink privilege skip on each version. The actual symlink
test is required to pass in Linux CI before phase completion. Ruff check,
format check, strict mypy (9 source files), and wheel/sdist build passed.
The exact scenario proof command in `docs/scenario_dsl.md` printed
`example-flow` and `['DVI-POL-000']`.

Review separated file access, parsing, and pure policy decisions into cohesive
modules. Content remains inert; there is no scenario-sourced execution or network
client. The documentation distinguishes declared fixture provenance from a
sandbox guarantee. An LF formatter setting was necessary to make formatting
consistent across Windows edits and Linux CI; it changes no runtime behavior.

## Phase 3 — Local detector harness

Acceptance: FixtureHarness and RuleLogicHarness behind a justified Protocol,
typed requests/results, deterministic observations, explicit unknown/unsupported
states, no external execution, and real fixture/rule tests.

`uv run pytest tests/test_harness.py`: 37 targeted cases in the final suite.
`uv run pytest` and `.venv312/Scripts/python.exe -m pytest`: 149 passed and the
one documented Windows symlink privilege skip. Ruff/format/mypy passed (11 source
files). Wheel/sdist builds passed. Tests verify an actual declared scenario rule
produces the expected signature, rather than mocking a detector response.

Review added strict JSON parsing for detector-result fixtures, rejecting duplicate
keys and non-finite constants. Reused policy preflight on fixture outputs so
rejections cannot silently become empty observations. Output timestamp overflow
and unsafe output are tested unknowns. The scenario now requires a concrete
harness declaration because detector selection is an implemented behavior.
Phase 2 Linux CI passed all 113 tests before harness implementation began.

## Phase 4 — Defensive telemetry adapters

Acceptance: real JSONL, CSV, synthetic EVE mappings with raw evidence/digests,
structured errors/warnings, deterministic output, malformed-data rejection,
equivalent fixture tests, and documented supported fields/limitations.

`uv run pytest tests/test_adapters.py`: 37 cases in the final suite. Full
`uv run pytest` and `.venv312/Scripts/python.exe -m pytest`: 186 passed and the
documented Windows symlink privilege skip on each version. Ruff, format, strict
mypy (13 source files), and package build passed. Committed examples cover four
event categories through every actual adapter.

The fixture regression caught blank optional CSV DNS cells being treated as
network identifiers; empty content is now absent, while required normalized
fields remain validated. Relative HTTP resource paths are allowed because EVE
uses them; protocol-relative external URLs remain rejected. Existing canonical
raw snapshots are policy-checked before wrapping new source evidence. All changes
stay within inert local fixture parsing. Phase 3 CI was green at `11daf36`.

## Phase 5 — Deterministic variation planner and invariants

Acceptance: typed strategies/parameters/constraints/cases, explicit lineage,
all six safe families, independent semantic checks, post-transform policy,
stable seed/config/input identities, bounded planning, and meaningful properties.

`uv run pytest tests/test_variations.py`: 18 tests (including deterministic
Hypothesis cases). Full Python 3.12 and 3.13 suites: 204 passed with the documented
Windows symlink privilege skip. Ruff, format check, strict mypy (16 source files),
and `uv run python -m build --installer uv` passed. Combined coverage was 97%.

`uv run python examples/plan_variations.py` and
`.venv312/Scripts/python.exe examples/plan_variations.py` produced the same
16 valid cases, all six families, no omissions, and plan digest
`447ddbaac2707566b14abac98a5e454478a44fe3c1cc77fed63ed9a52a8c5b1a`.

Review verified immutable source payloads, local RNG isolation, unique lineage,
independently rejected protected-field edits, and explicit overflow/event-budget
omissions. Distances and limitations are documented; no universal equivalence,
adaptive search, or live detector behavior is claimed. Valid planned cases execute
through real local rules. Phase 4 CI passed before implementation began.

## Phase 6 — Assumption probe engine

Acceptance: every requested assumption family has an explicit bounded probe,
independent invariants, local observations, class/rationale/evidence, deterministic
JSONL and report section, fragile fixtures, and a robust negative control.

`uv run pytest`: 236 passed, one documented Windows symlink privilege skip.
`uv run pytest tests/test_probes.py` and
`.venv312/Scripts/python.exe -m pytest tests/test_probes.py`: 32 passed each.
Ruff check, format check, strict mypy (20 source files), and wheel/sdist build
passed. Both Python versions ran `examples/probe_assumptions.py` and produced
the same sixteen probe IDs: thirteen fragile observations, two robust, one
not applicable for absent confidence. Individual-rule tests isolate each
dependency; the robust control loses no detection identity in any valid probe.

Proof outputs: `runs/assumption-proof/assumption_probes.jsonl` and
`assumption_probes.md`. Source spelling probes use real independent adapter
parsing, preserve exact timestamps and all normalized meaning, and retain fresh
raw evidence. Review checked ambiguity, missing fixtures, resource exhaustion,
identity collisions, unsafe baselines, and normalized metadata loss: none become
fragility claims. The current comparison deliberately measures detector/signature
identity survival; expected-detection matching remains Phase 8. Phase 5 remote
CI passed at `9db251f` before this phase began.
