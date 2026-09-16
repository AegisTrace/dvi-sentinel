# V2 card evidence record

V2 is in development. Cards execute in the order defined in
[V2 architecture](v2_architecture.md), following the
[development standard](development_standard.md). Entries describe actual work;
planned features do not count as implemented behavior.

## V2-00 - Scope Freeze and V2 Architecture Lock

Purpose: define the V2 semantic-engine scope and verification protocol while
preserving released V1 behavior and the fixed local fixture boundary.

Acceptance criteria were recorded before implementation: clearly separate planned
V2 and released V1 claims; document all 22 ordered cards, allowed module categories,
extension boundaries, compatibility, uncertainty and release requirements; include
the one-card loop and done definition; create no runtime placeholders; verify
documentation, full V1 quality gates, package build and CI before V2-01.

Files changed: README.md, CHANGELOG.md, docs/roadmap.md, docs/v2_architecture.md,
docs/development_standard.md and this record.

Behavior implemented: none; this is the blueprint's documentation-only scope card.
The V1 package remains `1.0.0`. The published `v1.0.0` release and its main/tag CI
were verified before V2 development began.

Design decisions: extend existing V1 contracts; keep event identity, semantic identity
and provenance distinct; do not infer equivalence from equally missing evidence;
do not prebuild later confidence/DAG engines for earlier oracle cards; use real
library/example paths until the CLI integration card; distinguish fixture statistics
from inference and standards-like projections from full compliance.

Tests added: none, as required for this documentation-only card. Docs/examples:
the architecture and development standard are complete; no artificial example or
runtime artifact was created. Safety review: documentation-only, with every future
card explicitly constrained to the five allowed local categories. No executable
capability, dependency, scenario permission, release tag or V1 artifact schema changed.

Known limitations: V2 behavior remains planned. The new source blueprint supersedes
earlier roadmap groupings without turning those ideas into implemented features.
Verification: Ruff and formatting passed; strict mypy passed for 50 source files;
pytest reported 418 passed and one Windows symlink-privilege skip (89.70 seconds).
The wheel and source distribution built successfully. All 115 local documentation
links/anchors across 42 Markdown files resolved; all 22 architecture cards match
the source blueprint's order. UTF-8 and `git diff --check` passed. Runtime, test and
dependency files are unchanged. Commit and exact-commit CI references are recorded
in the next entry after the remote checks complete.

Completed and pushed: `9957c75811a43965cad0ce14b9219588e4548cdd`.
[CI succeeded on Python 3.12 and 3.13](https://github.com/AegisTrace/dvi-sentinel/actions/runs/34901551823)
before V2-01 implementation began.

## V2-01 - Semantic Event Ontology

Purpose: reason about explicit detection meaning and incomplete evidence above the
unchanged V1 canonical event contract.

Acceptance criteria were written before implementation: exercise all ten required
typed models, deterministic canonical-field binding and semantic identity, all nine
required loss classes, explicit unknown/ambiguous states, no false equivalence from
missing evidence, raw metadata excluded unless bound, real exports and an executable
example. Preserve V1 behavior and pass full quality/build/CI gates before V2-02.

Files changed: ontology.py, ontology_models.py, test_v2_ontology.py,
examples/semantic_ontology.py, docs/semantic_ontology.md, policy.py, test_policy.py,
README.md, examples/README.md, CHANGELOG.md, docs/roadmap.md, docs/v2_architecture.md,
this record and the package version in pyproject.toml, __init__.py and uv.lock.

Behavior implemented: safe canonical event extraction, semantic signal identity,
evidence candidates and alias resolution, required/optional evidence, confidence
and correlation requirements, source time precision checks, classified losses,
cause-linked recommendations, equivalence and inert change/invariant records.
Three versioned deterministic exports retain input/profile/source anchors.

Tests added: ontology behavioral/property/negative tests, equivalent JSON/CSV
representations, semantic action/resource/direction changes, source/metadata
separation, all required loss classes, strict/tampered inputs, bounds and a real
example subprocess. A large-value test exposed excessive regex backtracking in the
V1 policy URL scan; the prerequisite fix preserves its candidate/rejection semantics
with property, prefixed/nested URL and large-value regression cases.

Docs/examples updated: the ontology contract and runnable fixture example, roadmap
status and development version `2.0.0.dev0`. Released V1 remains tagged and unchanged.
Artifacts generated: actual semantic_ontology.json, ontology_bindings.json and
semantic_loss.json under ignored runs/v2/V2-01-proof, using two known events and
one intentionally incomplete DNS projection.

Safety review: ontology_models.py is immutable data/validation; ontology.py is pure
bounded analysis/serialization. They reuse canonical events, raw hashes and fixture
policy checks. The example is a bounded local writer, rejecting existing/network/
symlink destinations. The URL scanner retains defensive rejection rules while
avoiding quadratic work on long ordinary strings. No new dependency, runtime
network/subprocess capability, scenario execution or artifact-schema change.

Known limitations: declared profile semantics only; source confidence is not a
statistical estimate and source fractional digits are not clock accuracy. Standalone
ontology exports are not V1 run bundles or V2 provenance DAGs. Consumers need trusted
source evidence to verify content assertions. Combined CLI integration and later
engines remain planned. Verification results are recorded below as checks complete.

Verification: Ruff/format and strict mypy passed (52 source files); the full suite
reported 484 passed and one Windows symlink skip in 314.24 seconds, with 96% combined
statement/branch coverage. After retaining optional source confidence/time values
in the final bindings, all 53 ontology tests passed again in 11.14 seconds; both new
modules have 100% statement/branch coverage. All 126 local links across 43 Markdown
files resolve. The offline lock check passed with only the package version changed.

Both wheel and source distribution built. A clean Python 3.12 wheel installation
passed dependency checks and `dvi doctor --json` from outside the checkout; the
ontology import resolved inside its site-packages. Its three generated files match
the Python 3.13 source example byte-for-byte (two known signals, one missing DNS
question). Archive contents include the models/example/docs/tests and exclude
private configuration. `git diff --check` passed.

Completed and pushed: `18714fbfd3fd3b8b8108ac55f682c0ff55e3baeb`.
[CI succeeded on Python 3.12 and 3.13](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35027961953).
The repository now uses `main` for all updates, preserving the existing README
correction and published release tag. The consolidation commit
`2434a8a5b0ae55e33b85d93f1ceeb3d0234ad8c3` passed
[both CI jobs](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35028733681)
before V2-02 began. `main` is the only local and remote branch.

## V2-02 - Semantic Detection Algebra

Purpose: evaluate bounded semantic relations over actual ontology evidence, retaining
field checks and unresolved support in every result.

Acceptance criteria were recorded before implementation: execute all seven relations;
reuse full ontology context and validate actual invariant/transform references; keep
missing evidence unknown; distinguish known contradictions from absence; record
required-evidence support with explicit numerators/denominators; produce replayable
plans and decision records; exercise real example behavior, tampering, bounds and
determinism; preserve V1 gates and publish directly on main before V2-03.

Files changed: semantic_algebra_models.py and semantic_algebra.py, their behavioral
tests, examples/semantic_algebra.py and docs/semantic_algebra.md; README, changelog,
examples index, roadmap, architecture status and this record.

Behavior implemented: evidence-bound invariant/transform identities; three-valued
preservation, requirements, contradiction, contract implication and equivalence;
observed weakening fractions; association of actual findings with source bindings.
Known contradictions suppress the compared signal assertion. Unknown contexts cannot
prove preservation/equivalence; missing required fields remain in support denominators.
Artifact serialization re-evaluates the entire plan, rejecting changed decision traces.

Tests added: 25 behavioral/property/negative cases, including actual protected changes,
unknown and robust controls, directional constraints, absent/lossy bindings, support
fractions, full-support unknown contexts, known contradiction alongside missing data,
forged identities/decisions, context bounds, fixture policy and the executable example.
Docs/examples updated: relation semantics, metric interpretation, selectors, trust
boundary, replay and the actual missing-DNS proof.

Safety review: models are immutable data; the analyzer is pure bounded analysis with
no I/O. It revalidates evidence and reapplies existing fixture policy to exposed values.
The example is a local writer with fixed filenames beneath a new directory, rejecting
network/symlink/junction/existing destinations. No dependencies, scenario capabilities,
runtime network/subprocess calls, V1 artifact contracts or release tags changed.

Known limitations: implication compares declared projection contracts; explanation
verifies finding association rather than independently proving every upstream loss.
Support fractions are descriptive, not statistical confidence or detector accuracy.
Replay checks consistency with recorded evidence and cannot authenticate original
source assertions. Independent oracles, temporal logic, profiles and CLI integration
remain planned.

Commands/results: Ruff check and format passed (128 files); strict mypy passed for
54 source files. Targeted coverage ran all 25 algebra tests in 7.50 seconds, with
100% statement/branch coverage in both new modules. The full coverage run reported
509 passed and one Windows symlink-privilege skip in 160.25 seconds, with 96% combined
coverage. The Linux CI suite exercises that symlink case. All 136 local links across
44 Markdown files resolve, and the publication-content audit passed for 174 files.

Artifacts generated: the real source example wrote semantic_plan.json (49,711 bytes,
SHA-256 `038dc52231dce562a44b69829aa6dfdb7f3cb5fe9de3f96d30ea756de0ab964f`)
and algebra_decisions.jsonl (17,312 bytes, SHA-256
`00012b163c6f53da6824ce4607fcd21a6dc2699cf596a54e751012e5c86b140e`)
under ignored runs/v2/V2-02-proof. It measured five unknown relations, true weakening
from 4/4 to 3/4 support, and one true explanation for the actual missing DNS question.

`python -m build` produced wheel and source distribution. A clean Python 3.12 wheel
installation passed dependency checks and `dvi doctor --json` outside the checkout;
the analyzer import resolved inside that environment's site-packages. The installed
example reproduced both Python 3.13 source artifacts byte-for-byte. Package archives
contain the intended code and exclude private configuration. `git diff --check`
passed. Commit/push and exact-commit CI evidence are recorded after publication;
V2-03 may begin only when both supported Python jobs succeed.

Completed and pushed on main: `3fa7ee71a567fa601e60fc3ed4f4e144dedae40f`.
[CI succeeded on Python 3.12 and 3.13](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35045304945)
before V2-03 began.

## V2-03 - Standards Mapping Profiles

Purpose: project canonical fixtures through explicit local subsets and measure what
survives normalization, without implying complete standards conformance.

Acceptance criteria were recorded before implementation: all seven profiles;
canonical projection and evidence-aware normalization; mapped/unmapped/lossy fields,
alias ambiguity, timestamp precision and severity drift; deterministic profile,
mapping/loss, alias-graph and roundtrip artifacts; primary references, runnable example,
negative/property tests, full gates and main-only publication before V2-04.

Files changed: mapping_models.py, mapping_codecs.py, schema_profiles.py and
schema_mapping.py; tests/test_v2_mapping.py, examples/schema_profiles.py and
docs/schema_profiles.md; README, changelog, examples index, roadmap, architecture
status and this record.

Behavior implemented: seven revisioned mappings with literal key paths and explicit
extensions; exact integer epoch conversions; strict alias comparison before selection;
canonical subtype preservation; measured field changes and provenance separation.
EVE reuses the V1 encoder/adapter. Sigma metadata reports missing event evidence
instead of inventing an event. OpenTelemetry retains security severity in a local
attribute, separate from native log severity. Artifact export reevaluates source
events and retains actual values, issues and digests.

Tests added: 45 behavioral/property/negative cases across all profiles, DNS/HTTP
resources, lossless and lossy controls, severity collapse, timestamp precision/range,
metadata-only unknowns, subtype serialization, alias conflict, unsupported fields,
strict types, bounded inputs, fixture policy, tampering and the executable example.
An alias-conflict test exposed an inspection gap for an unselected endpoint spelling;
every mapped candidate now receives canonical-field policy checks before selection.
Normalization traces also retain the actual values after V1 adapter normalization.

Docs/examples updated: exact supported subsets, primary versioned definitions,
extension and metadata boundaries, independent roundtrip/semantic decisions,
source-provenance limits, and a real seven-profile synthetic flow proof.

Safety review: immutable data models plus pure bounded codec/profile/analyzer modules;
existing canonical, raw and fixture-policy validation applies before consumption.
The example is a bounded local writer with fixed names and new-directory validation.
No network, subprocess or executable mapping/condition behavior in the runtime;
no dependency, V1 schema/command or release tag changed.

Known limitations: explicit subsets only. Sigma metadata cannot reconstruct events;
Zeek time uses local decimal text; EVE uses the declared legacy DNS projection.
Timestamp value preservation does not prove source clock accuracy or measurement
resolution. Replay/digests do not authenticate external source assertions. Original
raw provenance stays in the report, while normalized raw evidence describes the
profile payload. Independent oracles, intent and integrated CLI remain later cards.

Commands/results: Ruff check and format passed for 135 files; strict mypy passed for
58 source files. Targeted coverage reported 45 passed in 11.53 seconds and 98% combined
coverage across the four new modules. The full coverage run reported 554 passed and
one Windows symlink-privilege skip in 169.20 seconds, with 96% combined coverage.
The Linux CI suite exercises that symlink case. All 146 local links across 45 Markdown
files resolve; the publication-content audit passed for 181 files.

Artifacts generated: eleven files under ignored runs/v2/V2-03-final-proof. The actual
flow example records four lossless profiles, two lossy profiles and one unknown
metadata projection. mapping_report.json is 48,288 bytes, SHA-256
`321570940b48156be03b0f4504fe47855bc44704c02596f8c1217d911ab7ad9f`;
roundtrip_report.json is 2,745 bytes, SHA-256
`801d0f3be15d1634f14d31c8edc7594a0c39e8a306ae6b6e6a610970e6f6c76f`.

Both packages built with `python -m build`. The clean Python 3.12 wheel installation
passed dependency checks and `dvi doctor --json` outside the checkout. Its import
resolved in site-packages and its example reproduced all eleven Python 3.13 source
artifacts byte-for-byte. A final package rebuild includes the source formatting
correction identified by archive comparison. Exact-commit CI must pass for both
supported Python versions before V2-04 begins.

## V2-04 — Detection Intent Parser

Card: V2-04 Detection Intent Parser

Purpose: Parse bounded local detection declarations and explain whether supplied
fixture evidence supports their explicit requirements.

Acceptance criteria: Strict immutable intent models, native DVI parsing, a small
Sigma-style metadata/selection subset, validated V1 rule metadata, ontology-backed
field binding, explicit unsupported/loss classes, source and output severity scope,
finite time/correlation expectations, deterministic artifacts, safety boundaries,
tests, docs, example, package proof and green Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/intent_models.py`,
`src/dvi_sentinel/intent_parsing.py`, `src/dvi_sentinel/detection_intent.py`,
and the shared YAML boundary in `src/dvi_sentinel/scenario_io.py`;
`tests/test_v2_intent.py`; `docs/detection_intent.md`;
`examples/detection_intent.py`; README, roadmap, architecture, changelog and
examples index updates.

Behavior implemented: Native intent records use canonical JSON values and inert
finite selectors/operators. Sigma support requires explicit `taxonomy: dvi`, one
flat scalar selection and a selection-naming condition; unsupported shapes and
metadata remain unknown diagnostics. V1 rule count/order/window/delay requirements
remain assumptions. Actual events are revalidated through ontology bindings and
produce expected/observed checks for missing, optional, unsupported, mismatched,
ambiguous, lossy, correlation, time, metadata and technique evidence. Overall
support is existential across candidates only when global requirements are known.

Tests added: 14 focused parser/analyzer tests cover native support, literal
operators, unsupported shape/operator, missing versus optional evidence, source
mismatch, alias ambiguity, normalization loss, correlation keys, timestamp
precision, Sigma metadata/technique scope, detection severity, V1 metadata,
canonical artifacts, duplicate/anchor YAML and nested capability-field rejection.
The full suite passed 568 tests with one expected Windows symlink-permission skip;
local coverage was 95% with the required 90% floor.

Docs/examples updated: `docs/detection_intent.md` defines the local subset,
unknown semantics, artifacts, bounds and limitations. `examples/detection_intent.py`
writes the four artifacts from one matching and one incomplete synthetic DNS event;
the README, roadmap, architecture, changelog and examples index link to it.

Artifacts generated: source and installed-wheel examples matched byte-for-byte in
`runs/v2/V2-04-intent-proof-release` and `runs/v2/V2-04-wheel-proof-release`.
`detection_intent.json` is 818 bytes (SHA-256
`e6e0a93d181f0254630677ba3f5a7e2af3025856f170d06326019db75848ef14`);
`semantic_loss_report.json` is 4,274 bytes (SHA-256
`0768d9e8784f6befa06d4b169790bf6caa6081d77a090db664c497c95601ec8b`);
`unsupported_conditions.json` is 118 bytes (SHA-256
`3d7359123a68ea8ca0d4960fea38b131eb471a0038abe637cc4f709daa62bf5c`);
`intent_assumptions.json` is 73 bytes (SHA-256
`ce51f67a5b31edf401ec4101fed57c0c4e68c38e3edf489790cc646b1515c4f6`).
The final wheel is 136,423 bytes (SHA-256
`8a246458668cb63bf0ccd959bfaedf838fcb993a082a0cf2658174759ab12065`);
the sdist is 318,506 bytes (SHA-256
`faeb190dccf1de471b6e27fd5a431469b4bfd6b83c75fc6e996bfac7eaa678f8`).

Commands run: Ruff format/check, strict mypy, focused tests, full coverage test
and report, `python -m build`, source and installed-wheel examples, artifact hash
comparison, wheel member inspection, and `dvi doctor --json` outside the checkout.

Results: Ruff and mypy passed; focused tests passed 14/14; full local coverage
passed 568/568 with one platform skip and 95% coverage; the wheel imported from
site-packages, doctor reported `ready`, and both example output directories were
identical. No runtime dependency or V1 command changed.

Safety review: Pure typed models/parsers/analyzers plus a bounded local artifact
writer. The existing YAML syntax, duplicate/anchor/depth, canonical-value,
fixture-policy and documentation-network checks remain enforced. No filesystem,
network, subprocess, query, plugin, compiler or executable condition behavior is
available to the parser or analyzer.

Known limitations: The Sigma adapter is an explicit local subset, not a full
Sigma compiler. Source metadata may be absent or unmapped. Detection/output
severity cannot be inferred from ordinary input events. Time checks cover retained
representation and precision only; cross-event windows, order and same-value
correlation belong to V2-05. Evidence references associate paths but do not
authenticate source claims; unresolved assumptions stay unknown.

Commit: `1cf9402e50a1433d6aece451f6469af2347a421c` — `feat(intent): analyze local detection intent`.

CI status: GitHub Actions run
`35153650158` passed both `core (3.12)` and `core (3.13)` jobs for the exact
commit: https://github.com/AegisTrace/dvi-sentinel/actions/runs/35153650158.

Next card: V2-05 bounded temporal and correlation engine.

## V2-05 — Temporal and Correlation Engine

Card: V2-05 Temporal and Correlation Engine

Purpose: Evaluate bounded temporal, sequence and correlation assumptions over
validated local telemetry while preserving missing evidence and representation
uncertainty.

Acceptance criteria: Ten required predicates, deterministic UTC/event-ID order,
finite windows, explicit unknown outcomes for missing evidence, timezone
normalization proof, timestamp precision-loss findings, correlation-key
survival, four canonical artifacts, tests, docs, example, package proof and
green Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/temporal_models.py` and
`src/dvi_sentinel/temporal.py`; `tests/test_v2_temporal.py`;
`docs/temporal_correlation.md`; `examples/temporal_correlation.py`; README,
roadmap, architecture, changelog and examples index updates.

Behavior implemented: Bounded `before`, `after`, `within`, `same_entity`,
`same_flow`, `same_correlation_key`, `at_least_k_of_n`,
`no_contradictory_context`, `alert_within_window` and `sequence_order`
predicates operate on revalidated canonical events. Timestamps normalize to
UTC and ties sort by event ID. Missing entity, flow, correlation, alert or
finite-set evidence is unknown; benign/control markers produce an explicit
contradicted context check. Windows are integer milliseconds from 0 through
24 hours, sequence tokens match IDs/categories/actions, and declared source
precision loss remains unknown. Correlation IDs are retained as evidence and
never synthesized.

Tests added: Eight focused tests cover before/after and finite windows,
timezone shifts, out-of-order and duplicate-time ordering, entity/flow/key
evidence, incomplete finite counts, precision loss, alert windows, benign
suppression, sequence matching and deterministic canonical artifacts. The
full local suite passed 576 tests with one expected Windows symlink-permission
skip; coverage was 95% with the required 90% floor.

Docs/examples updated: `docs/temporal_correlation.md` defines predicate
semantics, unknowns, precision evidence, limits, artifacts and safety. The
example writes all four artifacts for a shuffled flow-to-alert fixture; the
README, roadmap, architecture, changelog and examples index link to the
contract and proof.

Artifacts generated: source and installed-wheel examples matched byte-for-byte
in `runs/v2/V2-05-temporal-proof-release` and
`runs/v2/V2-05-wheel-proof-release`. `correlation_evidence.json` is 339 bytes
(SHA-256 `8e8177f60f19bf7ce771ec5f23c3b818a07577e548497bf92a998e03922e8b50`);
`sequence_findings.json` is 2,908 bytes (SHA-256
`f27c6e7b677702916e69ac58800976dcaa8c47435a3a7018042a8f13a540c8fa`);
`temporal_summary.json` is 8,328 bytes (SHA-256
`8b9e88ea05e893723a9ff0ed702aa50d85ccc573487359f90f4c4b5771dcaacf`);
`temporal_trace.jsonl` is 5,092 bytes (SHA-256
`018e2437e311131afd02e91e38d2345d3bfde82b2c31af93e98ae2cc58505005`).
The wheel is 142,456 bytes (SHA-256
`c46230e36a6e80eb6a5f4d1c87959b106e2c2ce075c4413b0c2efa5f01f706e8`);
the sdist is 328,756 bytes (SHA-256
`53f96e3bd42e3f0a91da24d4113f7722f810fea523246fb0051788bef458d3a7`).

Commands run: Ruff format/check, strict mypy, focused tests, full coverage
test/report, `python -m build`, source and installed-wheel examples, artifact
hash comparison, wheel installation into the clean Python 3.12 proof runtime,
wheel member/import inspection, `dvi doctor --json` outside the checkout and
publication branding scan.

Results: Local quality gates passed; focused tests passed 8/8; full local
coverage passed 576/576 with one platform skip and 95% coverage. GitHub Actions
run `35155532882` passed both `core (3.12)` and `core (3.13)` jobs for the exact
implementation commit. The installed import resolved from site-packages,
doctor reported `ready`, and both example output directories were identical.

Safety review: Pure immutable models and bounded analyzers plus a local writer
with fixed artifact names and new-directory validation. Existing event policy
validation runs before every predicate. Limits are 128 events, 2 MiB combined
canonical input, 24-hour windows, 128 sequence tokens and 32 MiB artifact
output. No network, filesystem reads, subprocess, query, expression execution,
live target or detector-service behavior was introduced.

Known limitations: Temporal comparisons describe retained timestamp
representation and do not establish clock accuracy or sensor resolution.
Same-flow requires all three endpoint/protocol fields. Sequence matching is an
ordered subsequence over supplied events, and correlation compares only an
explicit retained string. This card does not add integrated CLI or independent
oracle consensus.

Commit: `bed50b699eba5e0ae0ba7bd18765965aedc1fc3b` — `feat(temporal): evaluate bounded detection sequences`.

CI status: GitHub Actions run
`35155532882` passed both supported Python jobs for the exact commit:
https://github.com/AegisTrace/dvi-sentinel/actions/runs/35155532882.

Next card: V2-06 Multi-Oracle Consensus and Uncertainty Classification.
