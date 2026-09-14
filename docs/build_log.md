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

## Phase 7 — Cross-schema differential testing

Acceptance: encode from a canonical sequence, independently normalize canonical
JSONL/CSV/synthetic EVE, compare meaningful fields and observed detector outcomes,
report typed disagreement with per-case evidence, and suppress formatting noise.

Full suite: 250 passed with the documented Windows symlink privilege skip.
`uv run pytest tests/test_differential.py` and the Python 3.12 equivalent:
14 passed, including a deterministic Hypothesis matrix of exact timestamps and
supported EVE alert severities. Ruff, format, strict mypy (23 source files),
and wheel/sdist build passed. `examples/compare_schemas.py` produced agreement
in all three representations for the robust control and schema-fragility
disagreements in canonical JSONL/EVE for the raw-field-dependent local rule.

Proof outputs are the robust and fragile `differential_schema_report.json` files
under `runs/differential-proof/`. Review checked loss-aware encoders, unknown
unsupported fields, actual per-field disagreement, explicit ID/order alignment,
partial-parse rejection, safety, and raw provenance. Schema fragility is claimed
only after normalized semantics agree. Full expected-detection matching is the
next phase. Phase 6 remote CI passed at `4379cb4` before implementation began.

## Phase 8 — Explainable detection matching

Acceptance: detected/missed/unknown with candidate-level comparisons, required
field/identity/signature/title/severity/metadata/event/correlation/time checks,
matching IDs, exact delay, missing/contradictory evidence, and finite reason codes.

Full suite: 268 passed and the documented Windows symlink privilege skip.
`tests/test_matching.py`: 18 tests on both Python 3.12 and 3.13, including
Hypothesis window boundaries. Ruff check/format, strict mypy (25 source files),
and isolated wheel/sdist builds passed. Integration tests expose title failure
in probes and severity failure in differential output while identities survive.

The scenario adds explicit literal signature containment and observation-source
adapter constraints. Exact signature and containment together are an unknown
ambiguous expectation. Distinct failed candidates cannot hide a true match;
duplicate IDs cannot fabricate one. Independent invariant/normalization/harness
guards precede all matching. Completeness measures evidence availability only;
fully evidenced failures can score 1.0 completeness. Rules and limitations are
documented in `docs/matching.md`. Phase 7 CI was green at `237a39a` before work.

## Phase 9 — Resilience frontier and fragility taxonomy

Acceptance: explicit counts and ratios, independent validity/parser guards,
evidence availability, measured latency percentiles, per-family observed
boundaries, adapter disagreement, and evidence-linked fragility classes.

Full suite: 278 passed with the documented Windows symlink privilege skip.
`tests/test_scoring.py`: 10 passing tests on Python 3.12 and 3.13, including
Hypothesis outcome partitions. Ruff, format, strict mypy (28 source files),
and wheel/sdist build passed. Formula fixtures prove 1/4 detected, 1/4 missed,
2/4 unknown, 9/10 invariant checks, and explicit unavailable empty ratios.

Actual planned duplicate variations give miss rate 1.0 and minimum miss distance
one for the fragile exact-count rule; the robust control gives detection rate
1.0 with no findings. Real probe/schema results prove taxonomy deduplication and
one-third adapter disagreement. Review verified baseline exclusion, invalid-case
guards, denominator/sample disclosure, deterministic ties, and no cross-family
distance ranking or weighted headline score. `docs/resilience_frontier.md`
documents all formulas and interpretation limits. Phase 8 remote CI passed at
`5c2c253` before implementation began.

## Phase 10 — Baseline regression comparison

Acceptance: declared snapshot comparison with stable case/content pairing,
incompatibility reasons, previous/current frontiers and family deltas, case/class
transitions, adapter deltas, configurable inclusive thresholds, and real
`dvi compare` JSON/human output with exit 0/1/2.

Full suite: 295 passed with the documented Windows symlink privilege skip.
`tests/test_comparison.py`: 17 passing tests on Python 3.12 and 3.13. Ruff,
format, strict mypy (31 source files), and wheel/sdist build passed. Tests run
real robust/fragile local rules against identical planned variations and invoke
the CLI against actual snapshot files. Regression, recovery, unchanged misses,
class changes, schema disagreement, parser/invariant deterioration, compatibility
dimensions, missing cases, changed content, empty unknowns, strict JSON, and
threshold equality are verified.

Review checked explicit detector-change allowance without relaxing static
scenario/input/configuration identity, recomputed metrics, finite bounded local
reads, stable ordering, and unknown decisions that cannot become false passes.
`docs/regression_comparison.md` documents the snapshot contract and gates.
The compare command is implemented here as the phase explicitly requires; full
run orchestration remains Phase 14. Phase 9 remote CI passed at `df9b724`.

## Phase 11 — Failure shrinking and root-cause explanation

Acceptance: bounded FailureShrinker, replayable MinimalCounterexample, independent
reduction validation, preserved finding class/matcher reason, conditional causal
ablation and RootCauseRanker, and all four requested artifacts.

Full suite: 307 passed with the documented Windows symlink privilege skip.
`tests/test_shrinking.py`: 12 tests pass on Python 3.12 and 3.13. Ruff,
format, strict mypy (34 source files), and wheel/sdist builds passed. The actual
`examples/shrink_failure.py` run reduces eight events to four in six attempts,
retaining two protected originals and two threshold-crossing duplicates.
It writes `minimal_case.json`, `minimal_case.md`, `shrinking_trace.jsonl`, and
`root_cause.json` under `runs/shrinking-proof/`.

Other real fixture tests reach one noise event, one affected metadata/source
record, one ordering inversion, and a 10.001 ms shift against a 10 ms window.
Review checked restoring nonessential metadata, rejecting lost intent/unsafe
inputs, unknown reductions, explicit budget exhaustion, no zero-change
counterexamples, and robust controls without root-cause claims. Minimum claims
are local to the supported reductions; causal language is conditional on the
tested fixture. See `docs/failure_shrinking.md`. Phase 10 remote CI passed at
`cb8c9b3` before implementation began.

## Phase 12 — Run artifact and manifest system

Acceptance: complete typed run evidence, original fixture capture, deterministic
identity and serialization, portable SHA-256 manifest, bounded cross-file
verification, staged publication and explicit verified overwrite.

Full suite: 331 passed with the documented Windows symlink privilege skip.
`tests/test_artifacts.py`: 24 tests pass on Python 3.12 and 3.13. Ruff check/format,
strict mypy (38 source files), and isolated wheel/sdist builds passed. The real
`examples/write_run_artifacts.py` run writes and verifies fourteen artifacts plus
the manifest under `runs/artifact-proof/`, including volume misses and a minimized
counterexample. Both Python versions produce run ID `run:920e4a597d62bd0afce351c4`.

Tests cover raw hash tampering, missing/extra files and empty directories,
validly typed but inconsistent rehashed scores, independent manifest anchors,
captured result fixtures, deterministic reruns, invalid paths, incomplete input,
and rollback after injected rename failure. Review confirmed bounded local I/O,
no execution/network capability, preservation of unowned output, and honest
limits on hashes, detector claim verification, overwrite crash recovery and
filesystem concurrency. See `docs/run_artifacts.md`. Phase 11 remote CI passed
at `9fd00af` before implementation began.

## Phase 13 — Explainable reports and provenance

Implemented: reports from verified bundles, JSON/Markdown/HTML and provenance,
all requested human sections with explicit absent-analysis states, actual
regression comparison with captured baseline/thresholds, escaped local rendering,
and direct finding-to-file/record/field hashes.

Full suite: 341 passed with the documented Windows symlink privilege skip.
`tests/test_reports.py`: 10 tests pass on Python 3.12 and 3.13. Ruff check/format,
strict mypy (42 source files), and isolated wheel/sdist builds passed. The wheel
contains the HTML template. `examples/render_report.py` adds four verified report
files to `runs/artifact-proof/`; repeated generation is byte-identical. Tests
prove 2/11 detected and 9/11 missed, unknown-only result fixtures, escaping of
HTML/Markdown/template-looking text, no external resource elements, valid anchor
targets, optional-section messages, regression persistence, and resolution of
variation/probe/schema finding references.

Review checked preservation of input artifacts, source inventory hashing without
report recursion, local links, explicit invocation arguments, no execution or
network capability, and accessible document structure. The artifact integration
fixture was shared with report tests without changing engine behavior. See
`docs/reports.md`. Phase 12 remote CI passed at `189e767` before implementation.

Outstanding release proof: automated browser navigation to the local HTML URL
was rejected by the browser URL policy, which also prohibited alternate browser
workarounds. A native Codex file-preview request was accepted as queued, but the
tools did not confirm rendered display. No visual inspection is claimed. This
check remains pending while implementation continues at the user's instruction;
it must be resolved before the release gate can pass.

## Phase 14 — CLI integration

Acceptance: installed/module entrypoints for doctor, run, compare, report and
ci-check, shared local validation, bounded full engine orchestration, explicit
overwrite, JSON/human summaries, stable exits and expected errors without traces.

Full suite: 360 passed with the documented Windows symlink privilege skip.
`tests/test_cli_workflow.py`: 19 tests pass on Python 3.12 and 3.13. Ruff
check/format, strict mypy (48 source files), and isolated wheel/sdist builds
passed. Installed `dvi doctor`, `validate`, `run`, `ci-check`, `report`, and
`compare` commands ran against real fixtures; the Python module entrypoint also
passed. `runs/cli-proof/` contains a complete verified report bundle with nine
misses among eleven variants, and its threshold-1 gate exits 1 as expected.

Integration tests cover robust controls, real regression between run bundles,
probe-only shrinking, baseline misses, exhausted budgets, unknown coverage,
optional analysis switches, overwrite refusal/replacement, malformed/unsafe YAML,
missing/partial/duplicate fixture input, unsafe unused detector observations,
non-finite thresholds and tampered consumer inputs. Review confirmed reports are
generated before destination publication, command arrays are data only, git
metadata reads launch no process, and no network/live detector surface was added.
The CI gate's scope and 0/1/2 exits are explicit in `docs/cli.md`. Phase 13 code CI
passed at `e23ceb9`; its separate browser-render release proof remains pending.

## Phase 15 — GitHub Actions CI gate

Acceptance: secure Python 3.12/3.13 matrix with full quality checks, coverage,
wheel/sdist build, fresh installed-package checks, doctor, a bounded real fixture
run, CI acceptance and useful artifact retention.

Fresh local reproduction used Python 3.12.14 in `.venv-ci` with a new pip editable
development install. Ruff check/format, strict mypy, coverage-wrapped pytest and
the 90% coverage gate passed: 360 tests passed, one documented Windows symlink
privilege skip, and 95% combined coverage. Coverage XML and wheel/sdist builds
were produced. A separate `.venv-package` installed the wheel with its runtime
dependencies; `pip check`, doctor and module-version checks passed outside the
checkout, and the imported module path was confirmed inside its site-packages.

The installed wheel ran `examples/foundation_scenario.yaml` with seed 42 and a
256-event planner/probe budget: 31 detected variants, no misses/unknowns/findings,
and threshold 1 passed. Artifacts are under `runs/ci/`, run ID
`run:23edb6b6d7b011729fa4caa8`. All workflow commands match `docs/ci.md`.

Actionlint 1.7.12, downloaded from its official release with the archive SHA-256
checked against published checksums, accepted the workflow. Official action
release commits are pinned with version comments. Review checked read-only token
permissions, disabled credential persistence, no required secrets, job timeout,
concurrency cancellation, scoped seven-day evidence uploads, and session-wide
test guards against Python DNS/socket I/O. The guard does not claim an OS sandbox.
Phase 14 remote CI passed at `c05f576` before implementation began.

## Phase 16 — Docker reproducibility

Acceptance: pinned slim Python, non-root offline CLI, bounded temporary storage,
documented host artifact mounts, no ports/services/privileges, and a real mounted
fixture run after the native quality gate passed.

Docker Desktop's Linux amd64 engine 29.5.2 built the image successfully from the
official Python 3.13.15 slim Bookworm index pinned by digest. Pip installed the
hash-verified runtime export of `uv.lock` and checked the installed package.
Both direct `docker run` and Compose created complete host bundles under
`runs/docker-direct/` and `runs/docker-proof/`. Doctor passed; the bounded example
detected all 31 variants, with no misses, unknowns, invalids or findings, and its
threshold-1 gate passed. Run ID: `run:23edb6b6d7b011729fa4caa8`.

Native/container `dvi compare` passed with zero metric changes. Eight core
analysis artifacts, including variations, matches, probes and schema comparison,
matched the native run byte for byte. Both complete manifests verified. The
Compose bundle manifest digest is
`f4f09936cc339b8df79aa3f7f1bb28ea43cc891a1ceeb6a30fb85703128de98b`.
Container checks confirmed UID/GID 10001, zero effective capabilities,
no-new-privileges, loopback-only interfaces, a read-only root and writable tmpfs.
README PowerShell commands and `docker compose config --quiet` passed.

Full native suite: 360 passed, one documented Windows symlink privilege skip;
Ruff check/format, strict mypy and wheel/sdist builds passed. Self-review covered
the restricted build context, runtime/build network distinction, mount ownership,
explicit overwrite, absent checkout metadata and honest image reproducibility
limits. No runtime engine change or prohibited capability was introduced.
Phase 15 CI passed at `3c77fb5`; the user's deletion of `AGENTS.md` at `9560d07`
was fast-forwarded and preserved. Its CI also passed. The separate Phase 13
rendered-HTML visual proof remains pending before release.

## Phase 17 — Property, metamorphic and interaction hardening

Acceptance: strengthen complete-engine behavioral evidence across model/policy
boundaries, parsers, variation interactions, probes, schema equivalence, matching,
frontier arithmetic, regression, shrinking, artifact tampering and CLI behavior.

Added 31 test cases plus generated inputs: bounded arbitrary fixture bytes,
partial-line locations, Unicode/offset model round-trips, inert scenario text,
numeric safety rejection, normalized prohibited-key spellings, eight-row pairwise
coverage of seven planner parameters, full matcher/schema endpoint equivalence,
candidate permutation invariance, honest mixed-outcome denominators, regression
and recovery across seeds, robust/missing-evidence probes, threshold-based
shrinker minimality, byte mutation/restoration and complete Unicode CLI runs.

The Unicode JSONL regressions initially failed for U+0085, U+2028 and U+2029.
Corrected the parser to split physical LF boundaries instead of general Unicode
text lines; CRLF and the terminal-newline/10,000-record limit remain explicit.
This is the only production change in this phase and does not add capabilities.

Full Python 3.13 coverage suite: 391 passed, one documented Windows symlink
privilege skip, 95% combined coverage. Focused Python 3.12 model, metamorphic,
matching, scoring and CLI suite: 77 passed using seed 20260910. The artifact and
matching hardening subset also passed on Python 3.13. Ruff check/format, strict
mypy and isolated wheel/sdist builds passed. Property generation now defaults to
deterministic cases with reproduction blobs, with explicit smaller budgets on
costlier properties. Reproduction commands, coverage map and limits are recorded
in `docs/testing.md`.

Self-review checked that assertions exercise real detectors and independent
invariants, minimum claims stay local, temporary mutation cases do not share
state, and no skips/health-check suppression or unstable clocks were added.
Phase 16 remote CI passed at `354c678` before hardening. The separate Phase 13
visual browser-render release gate remains unresolved.

## Phase 18 — Expert benchmark suite

Acceptance: ten required fragility families with paired robust controls, declared
scenario/fixtures, finding classes, reason codes, minima, metric ranges and
automated oracles; deterministic JSON evidence and clean-checkout execution.

Twenty scenarios and three shared synthetic source fixtures drive 275 explicit
checks. All twenty cases pass; ten controls have zero findings and nine safe
fragility cases reach their declared minima. The adapter-disagreement case
detects a deliberately changed action and correctly has no safe failure minimum.
The JSON evidence includes plans, assessments, source/suite digests, probes,
frontier values and reduction traces. Changed oracles fail without changing
measured detector evidence. See `docs/benchmarks.md` for the exact expectations
and the distinction between planner rates, probes and semantic mapping loss.

Full suite: 418 passed, one documented Windows symlink privilege skip, 95%
combined coverage. Benchmark-specific Python 3.12 suite: 27 passed. Ruff
check/format, strict mypy (50 source files), actionlint and wheel/sdist build
passed. Docker built and ran all twenty benchmarks with networking disabled.
Native and container final reports match byte for byte, SHA-256
`5bd60bd5d90e2685cb91dfc4aa46669e4a24d8bb48902bf8bb29f3108f220618`, under
`runs/benchmarks-final/` and `runs/benchmarks-docker-final/`.

Review aligned CSV fixture bytes with the repository LF checkout policy, kept
expectations separate from detector execution, checked bounded local paths and
resource limits, and retained explicit unavailable minimum/rate values. The
Docker context/image now includes the new benchmark fixtures, and CI records the
report through its installed wheel; these are necessary integrations of this
phase rather than new runtime services. No prohibited capability was introduced.
Phase 17 remote CI passed at `3a3917a` before implementation. Phase 13 visual
browser-render proof remains an unresolved release gate.

## Phase 19 — Research sources and engineering notes

Acceptance: primary-source attribution for the declared V1 influences, explicit
implementation/nonclaim boundaries, and concise explanations of engineering
choices, failure modes and rejected alternatives.

Added `docs/research_sources.md` and `docs/engineering_notes.md`, linked from the
README. Checked primary OCSF, ECS, OpenTelemetry, Suricata, Sigma/pySigma, MITRE,
Hypothesis, metamorphic-testing and NIST sources on 2026-09-14. ATT&CK's data-source
deprecation is explicit. Roadmap technologies remain future research, with no
new dependency or runtime capability. Reviewed claims against actual models,
harnesses, metrics, shrinking, artifact verification and tests. Also corrected
the frontier page's stale reference to future report provenance.

Validation: all 33 local links in the changed documentation resolve; Ruff check,
format (101 discovered Python files), strict mypy (50 source files) and diff
whitespace checks pass. This phase changes documentation only. Phase 18 CI passed
at `dfebc0d` on Python 3.12/3.13; its separate clean Python 3.12 clone passed 27
benchmark tests and produced the same report bytes as native and Docker runs.
The Phase 13 rendered HTML check remains open and is stated in the notes.

## Phase 20 — End-to-end fresh-checkout verification

Acceptance: fresh environment, doctor, robust/fragile runs, verified artifacts,
compatible comparison, report regeneration, correct CI exits, full quality/build
checks and available Docker reproduction, with exact commands documented.

Cloned GitHub main at `e7469d0` into `runs/phase20-checkout/`, created a clean
Python 3.12.14 environment and installed through standard pip. Doctor and fixture
validation passed. The robust benchmark had two detected variants/no findings;
the fragile example had two detections/nine misses and ten findings. Gates
returned 0 and 1 respectively; a repeated robust run compared successfully.
A generated pair differing only in detector count limit produced nine new misses
and regression exit 1. No tracked fixture needed editing.

Verified manifest anchors, typed reports/provenance and all finding/event
references. Report/provenance/manifest regeneration was byte-identical. Ruff
0.16.7, formatting, mypy, isolated wheel/sdist build and pip check passed. Full
suite: 418 passed, one Windows symlink privilege skip, 95% coverage. A wheel-only
environment passed doctor/version outside the checkout root and a complete
robust run/gate. The fresh checkout remained clean.

Docker Desktop's service command started its stopped Linux engine. Built from
the fresh checkout and executed with networking disabled and root read-only.
Robust/fragile outcomes and exits match native Python; eight analysis files per
run and the complete 20-case/275-check benchmark report match byte for byte.
Commands, versions, artifact paths and hashes are in `docs/reproduction.md`.
Phase 19 CI passed before verification. Phase 13 visual readability remains an
open release gate; structural/report-integrity proof does not replace it.
