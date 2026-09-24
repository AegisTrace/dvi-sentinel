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

## V2-06 — Multi-Oracle Consensus and Uncertainty Classification

Card: V2-06 Multi-Oracle Consensus and Uncertainty Classification

Purpose: Evaluate a proposed local detection gap through nine bounded evidence
checks while preserving disagreement, missing evidence and integrity failures.

Acceptance criteria: All nine required oracle classes; typed decisions with
confidence, severity, evidence references, reasons, explanation, uncertainty,
blocking and content digest; seven consensus states; multiple diagnostic checks
for confirmation; authoritative safety/provenance rejection; stable oracle-ID
ordering; four canonical artifacts; behavioral tests, docs, runnable controls,
installed-package proof and green Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/oracle_models.py`,
`src/dvi_sentinel/oracle.py`, `src/dvi_sentinel/oracle_consensus.py`,
`tests/test_v2_oracles.py`, `examples/oracle_consensus.py`,
`docs/oracle_consensus.md`, README, changelog, roadmap, architecture and
examples index.

Behavior implemented: Safety, schema, semantic, temporal, differential,
detection, statistical, evidence and provenance checks recompute their results
from actual canonical events, expectations, local harness observations and
optional repetitions/representations. Eligibility checks remain separate from
diagnostic support for the detection-gap claim. Safety/provenance rejection
prevents downstream analysis; missing required evidence prevents confirmation;
opposing diagnostics remain ambiguous. Confidence describes resolution of finite
checks and never claims a probability. Each result links to the same complete
input digest and hashes its own canonical content. Safe artifact output retains
the input evidence; blocked inputs are omitted.

Tests added: 41 focused cases cover real delayed/timely harness observations,
diagnostic disagreement, safety gates across every input group, provenance
tampering and missing digests, required evidence, missing timestamps/keys,
retained precision, window boundaries, ontology and representation loss,
small/mixed/unknown repetitions, duplicate identities, copied-model validation,
bounds, benign controls, low-confidence gates, ordering permutations and artifact
content/digests. The full suite passed 617 tests with one expected Windows
symlink-permission skip and 95% combined statement/branch coverage.

Docs/examples updated: The [oracle contract](oracle_consensus.md) documents
check roles, decisions, combination rules, evidence paths, confidence scope,
limits and safety. The [example](../examples/oracle_consensus.py) evaluates an
actual rule-harness alert at 2 seconds against a 1-second expectation, plus a
timely 0.5-second control. README and planning indexes link to this implemented
behavior.

Artifacts generated: Source Python 3.13 and installed-wheel Python 3.12 examples
produced byte-identical outputs under `runs/v2/V2-06-source-proof` and
`runs/v2/V2-06-wheel-proof`. The delayed case was `confirmed`; the timely
control was `suppressed_false_positive`.

| Case / artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| delayed/oracle_consensus.json | 12843 | `388e874d9c2df38d91e7b52af08817c06cb4a9c50b272be811e678663ef34fcd` |
| delayed/oracle_decisions.jsonl | 5853 | `20cdcfc12c5c0c22689209a10c07d68bff71c0ba8d3281f5f77503b2e4665c0e` |
| delayed/oracle_matrix.json | 1592 | `5dd68964c4d2e52c5e3686af7325649be3eb918e955747868399eca57727afd2` |
| delayed/uncertainty_report.json | 309 | `06f34b9621e675b489a4f6f03875b2ce744d514c8adf6093f3add93ac8c917b2` |
| timely/oracle_consensus.json | 12867 | `042416197fdddc743345a532e2e56a232797b8ce9bd95f1cc989ba7d142a3a90` |
| timely/oracle_decisions.jsonl | 5827 | `32423a397bd06bafe266c5cffbdb6202a7a76a05fb822c164a4245a9e5b33bcc` |
| timely/oracle_matrix.json | 1591 | `1a421cba3ad0f820e81c984545da2caa063e0f88ed7b92e5d9de0e29376bff69` |
| timely/uncertainty_report.json | 333 | `c4575c8140b015b5bb516480e410adc490ea8d20d99d0f9da1ef34631d840862` |

The proof wheel is 152275 bytes (SHA-256
`b3af949f37e4a755ac42aa1f042568dd64e69d6c9ce1cf78ec658269e81814db`);
the sdist is 345443 bytes (SHA-256
`3dac9fafeb0f239486b490d546e5dbd506ec986726a0a3460a53730f5ad6bd7d`).
All three oracle module files in the installed wheel match the committed source.

Commands run: `ruff check .`, `ruff format --check .`,
`mypy src/dvi_sentinel`, focused pytest, full
`python -m coverage run -m pytest -q --junitxml=...`,
`python -m coverage report --fail-under=90`, `python -m build`, source and
installed-wheel example runs, wheel installation and dependency check,
`dvi doctor --json` outside the checkout, artifact/member hash comparisons,
documentation link validation, publication-content scan and `git diff --check`.

Results: Focused tests passed 41/41; full local tests passed 617 with one
platform skip in 222.32 seconds; coverage was 95%. Ruff and strict mypy passed.
The package import resolved from the isolated runtime's site-packages,
17 installed packages had compatible dependencies and doctor reported `ready`.
All eight example artifacts matched byte-for-byte. Local proof logs, JUnit
results, coverage data and the hash manifest remain under ignored `runs/v2/`.

Safety review: Pure immutable data models and pure analyzers; the example is
a bounded local artifact writer using fixed filenames and a new local directory.
Inputs are revalidated before analysis, including copied model values; all
primary/repeated detections and representation records pass existing policy
checks. Limits are 128 input events, 128 detections per observation, 128 unique
repetitions, 3 representations, 32 configured evidence paths, 2 MiB canonical
input, 9 results and 32 MiB output. No network, subprocess, external detector,
query, plugin, expression execution or live-target capability was introduced.
Existing V1 models, commands and dependencies remain unchanged.

Known limitations: Checks may share a fixture and matcher; they are not
statistically independent samples. Repeat counts show local repeatability and
confidence is not a population estimate. Hashes prove content linkage, not source
authenticity. Temporal checks evaluate retained time/key evidence and preserve
unknowns for absent alerts or references. Benign/control context applies to the
bounded fixture as a whole and does not establish causal attribution to one alert.
Differential checks corroborate representations without duplicating matcher votes.
Integrated V2 CLI/report wiring and population statistics belong to later cards.

Commit: `6a6ea612385df9ed33c6a1ec2337948f2a61a95c` —
`feat(oracles): add multi-oracle consensus engine`.

CI status: [GitHub Actions run 35551658481](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35551658481)
passed both `core (3.12)` and `core (3.13)` jobs for the exact implementation
commit, including the test/coverage gates, package build, isolated install,
CLI fixture run and benchmarks.

Next card: V2-07 bounded combinatorial exploration and coverage accounting.

## V2-07 — Constraint-Guided Exploration

Card: V2-07 Constraint-Guided Exploration

Purpose: Select local telemetry cases that cover feasible interactions between
existing safe transformations while explaining constraints, invariant failures
and budget omissions.

Acceptance criteria: Pairwise and configurable t-way covering; exact declarative
constraints; semantic and policy filtering; seeded deterministic ordering;
bounded case/event selection; explained rejected and skipped combinations;
four canonical artifacts; real local controls, tests, docs, example, installed
package proof and successful Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/constraint_models.py`, `constraints.py`,
`covering_array.py` and `exploration.py`; `tests/test_v2_constraints.py`;
`examples/constraint_exploration.py`; `docs/constraint_exploration.md`; README,
changelog, roadmap, architecture and examples index.

Behavior implemented: A finite parameter space names existing V1 probe operations
or identity. Exact forbidden conjunctions, V1 permissions, independently checked
transform outputs, structural policy and final V2 ontology equivalence determine
feasibility. The complete bounded Cartesian space is evaluated before greedy
coverage selection. A seeded digest breaks ties; affordable alternatives remain
eligible when larger cases exceed the event budget. Infeasible interactions and
feasible uncovered interactions are separate. Every assignment appears once as
selected, rejected or skipped. Selected cases replay their measured content digest;
the plan retains inputs, configuration, events and transformation hash chains.

Tests added: 37 focused cases cover one-/two-/three-/four-way interactions,
independent coverage denominators, forbidden conjunctions, case/event budgets,
affordable alternatives, seeded declaration-order invariance, safety rejection,
permission checks, semantic unknowns and correlation loss, real duplicate-ID
collisions, finite growth, schema/search bounds, known and unexpected errors,
replay drift, absent optional solvers, artifact hashes/tampering and local controls.

Docs/examples updated: The [exploration contract](constraint_exploration.md)
defines parameter choices, constraints, feasibility, budgets, provenance and
limits. The [example](../examples/constraint_exploration.py) exercises four binary
dimensions and two actual local rules. Five selected cases cover all 23 feasible
pairs out of 24 theoretical pairs; four of 16 full assignments are forbidden.
The robust rule detects all five selected cases, while the sensor-dependent rule
detects three. These are measured local fixture observations.

Artifacts generated: Source Python 3.13 and installed-wheel Python 3.12 outputs
matched byte-for-byte in `runs/v2/V2-07-source-proof` and
`runs/v2/V2-07-wheel-proof`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| constraint_plan.json | 34037 | `c5c1204acbbfc61fe15fea5d1f3227f04483a8fdb5d753c5aeef743385326a7f` |
| covering_array.json | 1140 | `711c2e509d192abd9610a7aa653f6dccda4568fd5f50b090769b3076bdea8aef` |
| exploration_manifest.json | 565 | `55651eaae396837e00df277299f8bc5e6de5f25850252fb95793510c32953161` |
| invalid_combinations.json | 3677 | `5646b61a156ff0914f91fb9eef7fd552790d62be87d0e3aa5a6629de0bfa76aa` |

The proof wheel is 160634 bytes (SHA-256
`633d67349e9d668f8a2cc9d0166815d7ae3ccf33b5af4acc46b19dcf0d2809d8`);
the sdist is 361225 bytes (SHA-256
`69f139f439179ecb730678b0165590b9be3ee31133ee60927201fb556ec09a0d`).
The four exploration module files in the wheel match the committed source.

Commands run: `ruff check .`, `ruff format --check .`, strict mypy, focused pytest,
full `python -m coverage run -m pytest -q --junitxml=...`, coverage report with
the 90% floor, isolated `python -m build --installer uv`, source and installed-wheel
examples, isolated wheel installation/dependency check, `dvi doctor --json`
outside the checkout, artifact/member hash comparison, archive exclusion check,
documentation links, publication-content scan and Git whitespace checks.

Results: Focused tests passed 37/37. Full local regression passed 654 tests with
one expected Windows symlink-permission skip in 226.43 seconds, at 95% combined
statement/branch coverage. Ruff and strict mypy passed. All four example artifacts
matched. Doctor reported `ready`, the import resolved from site-packages and all
17 runtime packages had compatible dependencies. Checked 175 local links across
41 Markdown files. Proof logs, JUnit, coverage and hashes remain under ignored
`runs/v2/`.

Safety review: Pure immutable input models and bounded analyzers reuse existing
V1 probes, canonical validation, policy checks and V2 ontology comparisons. No
scenario callback, expression execution, network, subprocess, external detector
or solver dependency was added. Limits are six dimensions, 512 combinations,
32 constraints, 32 original events, 128 events per candidate, 2 MiB per
input/candidate, 128 selected cases, 4096 selected events and 32 MiB output.
Unsafe inputs block analysis and unsafe candidates never reach selection. The
example writes fixed names under a new validated local directory. V1 contracts,
commands, dependencies and release history remain unchanged.

Known limitations: Options are the existing finite probe catalog, not arbitrary
numeric synthesis. Greedy selection does not promise a minimum covering array.
Budgets limit selected execution cases; full eligibility validation remains
bounded but exhaustive. Parameter coverage is distinct from semantic novelty;
no-op choices can share telemetry. Empty feasible spaces are explicitly
`infeasible`, not complete. Hashes establish content linkage, not authenticity.
These artifacts do not replace the V1 verified run bundle.

Commit: `b66453e660fbdfffb0048ba9a7f8c4838cbed3c6` —
`feat(explore): add constraint-guided exploration`.

CI status: [GitHub Actions run 35553046587](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35553046587)
passed both `core (3.12)` and `core (3.13)` for the exact implementation commit,
including test/coverage, package, isolated-install, CLI fixture and benchmark gates.

Next card: V2-08 Semantic Coverage Engine.

## V2-08 — Semantic Coverage Engine

Card: V2-08.

Purpose: Retain cases that add measured semantic or diagnostic observations,
with exact growth accounting and visible unresolved evidence.

Acceptance criteria: Twelve measured dimensions, deterministic seeded ordering,
novelty retention, duplicate rejection, explained skips, unknown evidence blocking
the coverage evidence gate, four canonical artifacts, behavioral tests, docs,
example, installed-package proof and successful Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/coverage_models.py`, `semantic_coverage.py`,
`tests/test_v2_coverage.py`, `examples/semantic_coverage.py`,
`docs/semantic_coverage.md`, README, changelog, roadmap, architecture and examples index.

Behavior implemented: Pinned, bounded inputs pass policy and integrity checks
before ontology, equivalence, adapter, mapping, matching and oracle analyses.
Twelve dimensions retain their measurements and evidence paths. Only resolved
dimension/value tokens increase coverage. Seeded ordering determines which case
first contributes each token; duplicate cases add nothing. Queue entries retain
the input digest and exact new tokens. Validators recompute union and growth
arithmetic. The evidence gate remeasures inputs and checks every case, including
skipped unknowns and safety rejections.

Tests added: 32 focused cases cover measured branches/signals, duplicate and
incidental-metadata rejection, adapter/profile paths, precision and correlation
loss, missing evidence, policy/integrity rejection before consumers, actual
disagreement, seed/order determinism, bounded inputs, report tampering, evidence
paths, exact union arithmetic and the runnable example.

Docs/examples updated: The [coverage contract](semantic_coverage.md) defines each
dimension, retention, gates, bounds and limitations. The
[example](../examples/semantic_coverage.py) evaluates timely, late and duplicate
observations through the local rule harness. Two of three cases are retained,
with 34 measured tokens and a passing evidence-resolution gate.

Artifacts generated: Source Python 3.13 and installed-wheel Python 3.12 outputs
matched byte-for-byte in `runs/v2/V2-08-source-proof` and
`runs/v2/V2-08-wheel-proof`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| semantic_coverage.json | 149507 | `77f6426536a110c33d50eb06e0f102e2f6c3dcddb5a7bc9374e35e86abb98dee` |
| coverage_growth.json | 210 | `0d87e728ad6305ea2a43a1ce31d133e8e1ff8db26f20b47fccbed4acd58de033` |
| discovery_queue.jsonl | 3264 | `e90908bc8a4e8c1bb432b5cd3269d9cba3ed1d60b4587e95fcc66c45ea8d52fd` |
| coverage_retention.json | 3495 | `2d4b9af823571526e2254c64362006d3d48a4b059f862986421dda1cc9621cc4` |

The proof wheel is 167729 bytes (SHA-256
`3aa80dc54fa04c64631d5a657b44c72fec8b4b4079557fc7bec2a0b824f0c237`);
the sdist is 375029 bytes (SHA-256
`f4ae5fcc6ccc6df628f5a6b7c9964aba2904f325980bdb68503dfb9fe29235bb`).
Both new module files in the wheel match the committed source.

Commands run: Ruff lint/format, strict mypy, focused pytest, full coverage pytest
with JUnit, coverage report with the 90% floor, isolated build with uv, source and
installed-wheel examples, isolated installation/dependency check, doctor/import
checks outside the checkout, artifact/member hash comparisons, archive exclusion
checks, Markdown links, publication-content scan and Git whitespace checks.

Results: Focused tests passed 32/32. Full regression passed 686 tests with one
expected Windows symlink-permission skip in 234.99 seconds, at 94% combined
statement/branch coverage. Lint, format and strict mypy passed. All four artifacts
matched across runtimes. Doctor reported `ready`, imports resolved from
site-packages and all 17 runtime packages had compatible dependencies. Checked
187 local links across 42 Markdown files. Proof logs, JUnit, coverage and hashes
remain under ignored `runs/v2/`.

Safety review: Immutable pure data models and bounded pure analyzers reuse the
existing policy, adapters, ontology, mapping, matching and oracles. No network,
subprocess, callback, external detector or dependency was added. Inputs allow
16 cases, eight source/reference events per case, three profiles and 256 KiB per
case. Dimension values and total output are bounded; artifacts are limited to
32 MiB combined. Rejected unsafe inputs are not re-exported. The example writes
fixed filenames under a new validated local directory. V1 contracts are preserved.

Known limitations: Coverage measures supplied local observations, not security
completeness or independent samples. The gate checks evidence resolution, not
release readiness or detector effectiveness; known negative results remain known.
Partially unresolved cases may contribute resolved tokens but still block the gate.
Fragility tokens describe associations, not causal proof. Existing adapter limits
remain visible, including rejection of an empty CSV vendor field. Hashes establish
content linkage, not authenticity. These files do not replace the V1 run bundle.

Commit: `9d877edf1a71b2f7e0ec0702fe85bfc60c375160` —
`feat(coverage): track semantic discovery coverage`.

CI status: [GitHub Actions run 35663803726](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35663803726)
passed both `core (3.12)` and `core (3.13)` for the exact implementation commit,
including test/coverage, package, isolated-install, CLI fixture and benchmark gates.

Next card: V2-09 Cross-Representation Metamorphic Testing.

## V2-09 — Cross-Representation Metamorphic Testing

Card: V2-09.

Purpose: Measure preservation of meaning, exact fields and context through eight
existing fixture/profile representations, with field-linked differences and unknowns.

Acceptance criteria: Actual generation/normalization of all eight paths, nine
required finding classes, baseline comparisons and a complete deterministic
pairwise matrix, unsupported-evidence unknowns, four artifacts, behavioral tests,
docs, executable example, package proof and green Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/metamorphic_models.py`, `metamorphic.py`,
`tests/test_v2_cross_representation.py`, `examples/cross_representation.py`,
`docs/cross_representation_testing.md`, README, changelog, roadmap, architecture
and examples index.

Behavior implemented: A pinned, bounded canonical event is encoded or compared
with supplied representation bytes. The analyzer reuses V1 JSONL/CSV/EVE adapters,
V2-03 Zeek-like/ECS-like/OCSF-like/OTel-like/Sigma-metadata profiles, V1 field
differences and V2 ontology equivalence. Measurements retain bytes, projections,
normalization, semantic decisions and exact expected/observed fields. Findings
carry the input digest, logical field path and evidence pointer. Matrix rows are
canonical and complete. Shared pairwise losses remain visible against the source;
unknowns never become agreement, including on the diagonal. Safety or integrity
rejections omit input content and block comparison.

Tests added: 37 focused cases cover a common subset agreeing across all seven
event representations, actual precision/context/semantic/severity/correlation
losses, equivalent timezone spellings versus measured drift, arbitrary time shifts,
equal/conflicting aliases, unsupported profile fields, Sigma metadata, parser and
encoder limits, incomplete/multiple events, unresolved ontology, changed identities,
permutation determinism, policy/integrity ordering, unexpected errors, input/output
bounds, artifact tampering, evidence pointers and the runnable example.

Docs/examples updated: The [comparison contract](cross_representation_testing.md)
defines executed paths, finding evidence, matrix semantics, limits and reproduction.
The [example](../examples/cross_representation.py) executes eight representations
and 64 matrix cells for a synthetic flow. JSONL, CSV and EVE agree with the source;
four profile projections expose actual context/precision loss; Sigma remains
unknown as event evidence. The 72 diagnostic rows include related traces and do
not represent 72 independent failures.

Artifacts generated: Source Python 3.13 and installed-wheel Python 3.12 outputs
matched byte-for-byte in `runs/v2/V2-09-source-proof` and
`runs/v2/V2-09-wheel-proof`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| representation_diff.json | 21688 | `c5737eebf58907e61dddf813c12e80616d634928166dbc318eaaa412db26832a` |
| adapter_disagreement.jsonl | 5050 | `db342dd89b4df1042a14dbc050eae0699f165b39ba2b521ef572110b17a0dae5` |
| cross_profile_matrix.json | 68991 | `caa5ce8094ed832af051a9ba3878494c4550f1883ab24021ea68048e4d78c797` |
| metamorphic_report.json | 140107 | `25f8fc0b703d0f934bf8db1224c79e1af6ded00bfb09e5f05baee6104bd5e49e` |

The proof wheel is 174633 bytes (SHA-256
`05f1b22a995794e3f38493ade8bca1e8d3486717ece28578a49e47c9b466a35c`);
the sdist is 388746 bytes (SHA-256
`22396e71e9146c716bba3bd9214c69b524568c7c9b814fad703a39cdddc7f7a8`).
Both new module files in the wheel match the committed source.

Commands run: Ruff lint/format, strict mypy, focused pytest, full coverage pytest
with JUnit and the 90% floor, isolated build with uv, source and installed-wheel
examples, isolated installation/dependency check, doctor/import checks outside
the checkout, artifact/member hash comparisons, archive exclusions, Markdown
links, publication-content scan, import/data-flow review and Git whitespace checks.

Results: Focused tests passed 37/37. Full local regression passed 723 tests with
one expected Windows symlink-permission skip in 279.44 seconds, at 94% combined
statement/branch coverage. Lint, formatting and strict mypy passed. All four
artifacts matched across runtimes. Doctor reported `ready`, imports resolved from
site-packages and all 17 runtime packages had compatible dependencies. Checked
200 local links across 43 Markdown files. Logs, JUnit, coverage and hashes remain
under ignored `runs/v2/`.

Safety review: Pure immutable input/output models and a bounded pure analyzer
reuse existing structural policy, parsers, profile mappings and ontology checks.
No network, subprocess, executable mappings, callback, external detector or new
dependency was added. Bounds are one event, eight representations, 64 KiB per
supplied representation, 256 KiB per complete request, 64 matrix cells, 4096
findings and 32 MiB combined artifacts. Existing parser/profile size bounds apply.
The example writes fixed filenames under a new validated local directory. V1
commands, models, encoders, parsers and release history remain unchanged.

Known limitations: These are explicit local subsets, not standard compliance or
detector-effectiveness tests. One event is analyzed per request. Unknown Sigma
event reconstruction and existing CSV empty-vendor rejection remain visible.
Pairwise agreement can share loss relative to the source. Time classifications
describe measured spellings/truncation patterns, not universal causes. Related
diagnostics are not independent samples. Parsing a report validates structural
links, not analyzer replay or authenticity; reproduce from pinned inputs.

Commit: `3998fd655cf082cf27982e441c9936ef92b45b44` —
`feat(metamorphic): compare equivalent telemetry representations`.

CI status: [GitHub Actions run 35684263532](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35684263532)
passed both `core (3.12)` and `core (3.13)` for the exact implementation commit,
including test/coverage, package, isolated-install, CLI fixture and benchmark gates.

Next card: V2-10 Counterfactual Failure Mining.

## V2-10 — Counterfactual Failure Mining

Card: V2-10.

Purpose: Find inclusion-minimal sets of safe transformations associated with a
missed detection in a measured local rule fixture, with conditional effect rankings.

Acceptance criteria: Detected baseline, single changes, covering-array combinations,
every proper-subset control before minimality, actual harness/matcher observations,
local effect rankings, explicit confidence/limitations, four deterministic artifacts,
behavioral tests, runnable controls, docs, package proof and green Python 3.12/3.13 CI.

Files changed: `src/dvi_sentinel/counterfactual_models.py`, `counterfactuals.py`,
`tests/test_v2_counterfactuals.py`, `examples/counterfactuals.py`,
`docs/counterfactual_causality.md`, README, changelog, roadmap, architecture and
examples index.

Behavior implemented: A pinned, bounded request passes policy and ontology gates
before actual local rule evaluation. Singles run before seeded covering-array
combinations. Subset controls share one case/event budget and evaluation cache.
Every bounded subset is accounted for, including rejected, unselected, unknown and
budget-skipped cases. All proper subsets must detect before an observed miss is
inclusion-minimal; non-monotonic outcomes cannot evade this control. Rankings use
verified local minimal-set membership and descriptive paired miss deltas, retaining
unavailable comparisons and excluding identical-input pairs from the mean. Findings
state conditional local necessity and preserve evidence links and limitations.

Tests added: 42 focused cases cover single/combined/irrelevant changes, robust
controls, seed/declaration-order determinism, missed/ambiguous baselines, one-dimension
studies, case/event budgets, no-op denominators, unsafe/semantically invalid inputs,
pins, replay drift, unknown controls, non-monotonic outcomes, complete proper-subset
verification, budget-unresolved minimality, six-dimension bounds, propagated errors,
artifact tampering, input/output bounds and the executable three-control example.

Docs/examples updated: The [counterfactual contract](counterfactual_causality.md)
defines measured search, inclusion-minimality, descriptive effects, confidence,
budgets and reproduction. The [example](../examples/counterfactuals.py) runs a
sensor-dependent rule, independent sensor/vendor rules and a robust category rule.
Each accounts for eight subsets and evaluates seven. The first two yield verified
one- and two-dimension minimal sets; the robust control yields no observed failure.

Artifacts generated: Source Python 3.13 and installed-wheel Python 3.12 outputs
matched byte-for-byte in `runs/v2/V2-10-source-proof` and
`runs/v2/V2-10-wheel-proof`, with four artifacts for each of three local controls.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| combination/causal_rankings.json | 3503 | `17e45e1f95310b6d13ae323c27a46df03e151a7eda5869902e366e28edafde9d` |
| combination/counterfactual_summary.json | 48628 | `197880a3267a22c0e79c8e077e76385627751f1ace6c95504c38518a41030ba1` |
| combination/counterfactuals.jsonl | 40875 | `c2260014e5d989f89aca08703653d2654ef257e7024463fd44869fa09f6476d3` |
| combination/minimal_failure_set.json | 977 | `2b040a337cc973ab9b799d6d45faf287d0f2439f19e3d1d410c3c7b69eec1093` |
| robust/causal_rankings.json | 3273 | `62b59aed88065cd10e83d5bac9bd2c45c9bd295b75cee1686463e65e5d0a9554` |
| robust/counterfactual_summary.json | 44797 | `02e74ee1e41fb38d349eb9a4e891d3f949861a8a2db9ae36aa9856137a71f375` |
| robust/counterfactuals.jsonl | 38482 | `c0085f6abaf4c1bfcb08ef01b9e8e30fb19e4af2c348df8d4acb91a2190f1dd1` |
| robust/minimal_failure_set.json | 108 | `12cdadecbf9cb5575e3f9638b92a45104bc629383a4330d852ee7e1cf0611fb5` |
| single/causal_rankings.json | 3373 | `347f841bcb2e661e49da8cce66fcc62df44225854c5de32b27c3301d69f9400a` |
| single/counterfactual_summary.json | 40756 | `31d08115238fcd6a6ea7809cb64e8eb3da3514139852112df90deca9d9903ee7` |
| single/counterfactuals.jsonl | 32827 | `4bb8ef8cea5ded81c0f7ae885e37ad75fdbbfc751d03bdafff365128c0700ffc` |
| single/minimal_failure_set.json | 1627 | `dd620fb96da251f30a9f4418d343ce2b1f402984a1a03befda0e96673ebe9f42` |

The proof wheel is 183996 bytes (SHA-256
`d4d136dc2f7f970f793b08e07d7aed573b066f89442ed2039d48f3d9a3b46515`);
the sdist is 406116 bytes (SHA-256
`b42c0074178f9588af2a5e5e10b0636f0dfc5c051632b276d670fd63279139d8`).
Both new module files in the wheel match the implementation source.

Commands run: Ruff lint/format, strict mypy, focused pytest, full coverage pytest
with JUnit and the 90% floor, isolated build with uv, source and installed-wheel
examples, isolated installation/dependency check, doctor/import checks outside
the checkout, artifact/member hash comparisons, archive exclusions, Markdown
links, publication-content scan, import/data-flow review and Git whitespace checks.

Results: Focused tests passed 42/42. Full local regression passed 765 tests with
one expected Windows symlink-permission skip in 261.51 seconds, at 94% combined
statement/branch coverage. Lint, formatting and strict mypy passed. All 12 example
artifacts matched across runtimes. Doctor reported `ready`, imports resolved from
site-packages and all 17 runtime packages had compatible dependencies. Checked
213 local links across 44 Markdown files before this completion record. Logs,
JUnit, coverage and hashes remain under ignored `runs/v2/`.

Safety review: Category D immutable models and a category A pure analyzer reuse
existing local rule evaluation, policy, safe probe materialization, independent
invariants, ontology and covering selection. The category W example writes fixed
filenames under a new validated local directory. No network, subprocess, arbitrary
callback, external detector or dependency was added. Bounds are 256 KiB per input,
eight source events, six binary dimensions, eight local rules, 64 subsets,
128 events/2 MiB per transformed candidate, 64 detector evaluations, 4096 evaluated
events and 32 MiB combined artifacts. Rejected unsafe input content is omitted.
V1 commands, contracts and release history remain unchanged.

Known limitations: Findings describe this local fixture, not universal causes or
production effectiveness. Minimality is inclusion-based within measured controls,
not proof of the globally smallest set or discovery of all sets. Unselected subsets
remain untested. Paired effects are dependent descriptive observations, not causal
probabilities or statistical confidence intervals. Invalid/unknown requested cases
leave the study incomplete even when separately verified findings remain available.
JSON validation checks structure/linkage, not detector replay or authenticity.
These artifacts do not replace a V1 run bundle or certify a V2 release.

Commit: `2feadae24f35792bf6dd2d816a990aefe8e78762` —
`feat(counterfactuals): mine local failure contributors`.

CI status: [GitHub Actions run 35731519035](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35731519035)
passed both `core (3.12)` and `core (3.13)` for the exact implementation commit,
including test/coverage, package, isolated-install, CLI fixture and benchmark gates.

Next card: V2-11 Delta Debugging Shrinker Upgrade.

## V2-11 — Delta Debugging Shrinker Upgrade

Card: V2-11.

Purpose: Minimize local failures while preserving declared semantics, actual finding
class and independently measured nine-oracle consensus.

Acceptance criteria: Event removal, smaller timestamp offsets, restored metadata,
source aliases and optional correlation changes; protected semantics, finding and
consensus; immediate stop on uncertainty; complete deterministic attempts and
budgets; four artifacts, behavioral tests, docs/example, package proof and green CI.

Files changed: `src/dvi_sentinel/consensus_shrinking_models.py`,
`consensus_shrinking.py`, `reductions.py`, `tests/test_shrinking.py`,
`tests/test_v2_counterfactuals.py`, `examples/oracle_shrinking.py`, failure-shrinking
and counterfactual docs, README, changelog, roadmap, architecture and examples index.

Behavior implemented: The opt-in mode reuses V1 proposals and independent
invariants, fixed local rule execution, matching and V2 oracle consensus. Requests
pin complete bounded inputs and explicitly protect original event identities.
Coarse-to-fine event removal must preserve a newly measured surviving baseline;
existing V1 reductions then simplify changes. Actual remaining fields must retain
the declared finding class and matcher reason. Confirmed consensus must preserve
state/confidence and every oracle's decision, confidence and reason codes. A strict
cost decreases on acceptance. Uncertainty/disagreement stops immediately. Shared
budgets and content-cached observations retain exact evaluation/event counts;
all attempted distinct proposals retain parent/content links and decisions.

Tests added: 50 cases cover four real shrinking controls, exact 10.001 ms timing,
chunk rejection followed by smaller removals, protected identities, measured
baseline controls, actual remaining class and matcher reason, oracle disagreement,
changed confidence despite equal state, unsafe/nonsimplifying proposals, complete
trace/cache accounting, all budget types, integrity/safety ordering, unknown meaning
and precision, robust/missed/invalid inputs, deterministic artifacts, tampering,
input/output bounds, propagated errors and the runnable example. A V2-10 integration
case proves a missing-alert finding cannot gain unsupported confirmed consensus.

Docs/examples updated: The [shrinking contract](failure_shrinking.md) describes
explicit event scope, the opt-in API, preservation, uncertainty, trace and budgets.
The [counterfactual contract](counterfactual_causality.md) links the stricter evidence
gate. The [four-control example](../examples/oracle_shrinking.py) reduces six events
to one in each fixture. Alias and correlation use two attempts/four evaluations;
metadata uses four/six and restores the irrelevant vendor change; timing uses
95/81 and reaches the measured 10.001 ms boundary against a 10 ms expectation.

Artifacts generated: All 16 artifacts matched byte-for-byte between source Python
3.13 in `runs/v2/V2-11-source-proof` and installed-wheel Python 3.12 in
`runs/v2/V2-11-wheel-proof`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| alias/oracle_preservation.json | 24362 | `7c3c28d8fe2525c9c40efa4db65dd6f8415d4a11fdbde1e1f41ea88156a49def` |
| alias/shrinking_trace.jsonl | 24309 | `13c29cf58cd74e082ba05fbad40f8eae99bde67c97026ce78232531096fb7520` |
| alias/shrunk_case.json | 84472 | `19249754464e8c38c9155631547170f30a67120ac8a86f2e7db91baa211386ef` |
| alias/shrunk_case.md | 546 | `11417e697ae97509bb3dfaa509412ea921a2ac366e4465ce2bd4dc1751571ae2` |
| correlation/oracle_preservation.json | 24305 | `b70c17eca78805c3796641bff0b9cd31d724ae1c7799009ccf3186e3e33344ae` |
| correlation/shrinking_trace.jsonl | 26134 | `070c026099bf3d5ff8f8b1161af2144a682781257b18ea7d84223e513c450e8e` |
| correlation/shrunk_case.json | 87100 | `3fde5920a6605cdbe00bc0e8a93914a5bb9ac6153fbbaef41299fdfdf58d6534` |
| correlation/shrunk_case.md | 566 | `dcef7b58e738f1a296ad0db010132d1e2e314861228baaa4fd1311d49ce70669` |
| metadata/oracle_preservation.json | 24796 | `e69693dc0506a4c5be048df31b7e145844e42e2f679dec8e1b81829d4e835d43` |
| metadata/shrinking_trace.jsonl | 76191 | `6bf3ff18110d3bc2b3bc0b8db25972dcef43284f4673f1a6280a35c8cbcf3f9e` |
| metadata/shrunk_case.json | 136816 | `1ef9be8424f788ef7aac7edf0bfdb9c919f9aafd340260929abc1e5094c1db05` |
| metadata/shrunk_case.md | 565 | `aef41b1e76dde02a44e71055d470449b670dd9845b07ba31bc38a6c3945511f8` |
| timing/oracle_preservation.json | 44864 | `f5706cd1875d339113e719712ee46d5b87f1dbf6cf373664604195f4b49d2f2d` |
| timing/shrinking_trace.jsonl | 1883468 | `2441e9cc465a96cea6db920181d72f38d5c3c402c39c7299dd71f036233557bc` |
| timing/shrunk_case.json | 1941837 | `a1bad4d6ad1ab3a0321de5ef5e42e4ff4f6f60e53f4c09182342cff5f5712fb4` |
| timing/shrunk_case.md | 560 | `841e8c83d9a1599469c5b67749414f95deb869cc55162f9e6e438cb00fadf671` |

The proof wheel is 193244 bytes (SHA-256
`cc6fcbba1d823d5bdf2529a3b720169dc1076be9954431c5c393570ff97de282`);
the sdist is 424417 bytes (SHA-256
`e731e4beafb538ce7fd38303c2597a262389b56249daf0f703624373485ecc14`).
All three changed runtime modules match the wheel's packaged source.

Commands run: Focused pytest, Ruff lint/format, strict mypy, full coverage pytest
with JUnit and the 90% floor, isolated build with uv, source/installed-wheel examples,
package installation/dependency check, doctor/import checks outside the checkout,
artifact/member hashes, archive exclusions, Markdown links, publication-content
scan, import/data-flow review and Git whitespace checks.

Results: Focused shrinking/counterfactual regression passed 103 tests. The final
lineage-validation change passed all 10 tamper checks. Full local regression then
passed 815 tests with one expected Windows symlink-permission skip in 320.55 seconds,
at 94% combined statement/branch coverage. Ruff lint/format and strict mypy passed
across 177 Python files and 78 runtime source files respectively. All 16 example
artifacts matched across runtimes. Doctor reported `ready`, imports resolved from
site-packages, and all 17 installed runtime packages had compatible dependencies.
Checked 242 local links across 52 Markdown files before this completion record.
Logs, JUnit, coverage and hashes remain under ignored `runs/v2/`.

Safety review: Category D immutable models and category A analyzers/reducers use
only validated values and the existing fixed local rule harness. Category W example
output uses fixed filenames beneath a new validated local directory. No network,
subprocess, arbitrary callback, external detector, executable fixture content or
dependency was added. Bounds are 16 original/64 candidate events, eight local rules,
256 KiB input, 128 attempted reductions, 258 actual evaluations, 4096 evaluated
events and 32 MiB combined artifacts. Unsafe source inputs are omitted; rejected
unsafe proposals retain no candidate content or observations. V1 APIs, invariants,
artifact names and release history remain compatible.

Known limitations: Event relevance is explicitly scoped by protected IDs, not
inferred from incident meaning. Removed original events change that scope, and
each surviving baseline must independently detect. One V1 family/catalog probe is
supported per study. Minimum claims are local to supported reductions; order can
affect the result and no global minimum or universal cause is claimed. Missing-alert
timing and any other unresolved oracle stop shrinking. Confidence is check
resolution, not statistical certainty; optional repetitions are never fabricated.
JSON validation checks links/derivations, not detector replay, exhaustive trace
production or authenticity. Reproduce from pinned input. These files do not replace
a V1 run bundle or certify the V2 release.

Commit: `4b5e3daf08c92c1d873b11c26b468449475fe3f3` —
`feat(shrinking): preserve oracle consensus while minimizing failures`.

CI status: [GitHub Actions run 35755384215](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35755384215)
passed both `core (3.12)` and `core (3.13)` for the exact implementation commit,
including test/coverage, package, isolated-install, CLI fixture and benchmark gates.

Next card: V2-12 Statistical Confidence Layer.

## V2-12 — Statistical Confidence Layer

Card: V2-12 Statistical Confidence Layer.

Purpose: Add honest statistical uncertainty to measured local scores while
preserving V1 scoring and regression decisions.

Acceptance criteria: Wilson detection/miss intervals, deterministic seeded latency
bootstrap, explicit denominators and sample warnings, seed stability, paired effect
uncertainty, six confidence classes and calibration notes; finding/family/run
attachments; authoritative integrity gates; four artifacts, tests, docs/example,
package proof and green CI.

Files changed: `src/dvi_sentinel/confidence_math.py`, `confidence_models.py`,
`confidence.py`, `tests/test_v2_confidence.py`, `examples/statistical_confidence.py`,
`docs/statistical_confidence.md`, README, changelog, roadmap, V2 architecture and
examples index. Existing V1 runtime files remain compatible.

Behavior implemented: Each bounded seed run retains its original V1 metrics and
uses detected plus missed as its resolved Wilson denominator. Unknown/invalid
cases remain explicit, with worst-case missing-outcome identification bounds.
Detected-alert latency retains observations and seeded mean/p50/p95 bootstrap
replicates. Case-level seed agreement detects opposite failures even when aggregate
rates match. Findings keep their actual one-case sample; seeds and bootstrap
replicates never inflate denominators. Confidence labels require declared sampling
assumptions, warn about finite/dependent fixtures and never override integrity.
Paired recovery/loss effects retain approximate Bonferroni-Wilson uncertainty and
the exact existing V1 comparison decision. Full report validation rechecks gates,
matching, numerical evidence, classifications, warnings and comparison derivations.

Tests added: 82 cases include known Wilson values and complement properties,
empty and invalid denominators, deterministic/bootstrap boundary controls, missing
and invalid outcomes, singleton findings, aggregate-equal but case-disagreeing
seeds, partial/incompatible cohorts, all six precision classes, small/large
regressions, recovery/unchanged effects, uncertainty with unavailable pairs,
safety/provenance ordering, changed matcher/input evidence, canonical ordering,
artifact consistency, numerical/report tampering, duplicate fixtures, changed
expectations, request bounds and the runnable example's output protections.

Docs/examples updated: The [statistical contract](statistical_confidence.md)
explains the sampling unit, formulas, primary references, policy thresholds,
calibration limits, safety boundary and artifact reproduction. The
[local example](../examples/statistical_confidence.py) executes robust and
sensor-dependent rules over three seeds, with 16 sensor changes and 16 unchanged
controls per seed plus an excluded baseline. Each current run detects 16/32,
has a 95% Wilson interval of approximately [0.3363, 0.6637], and remains
`low_confidence` under the default finite-fixture assumption. Each run's paired
effect is -0.5 with an approximate interval [-0.6842, -0.1801]; V1 remains regressed.
Actual finding attachments are `insufficient_sample`.

Artifacts generated: All four artifacts matched byte-for-byte between source
Python 3.13 in `runs/v2/V2-12-source-proof-final` and installed-wheel Python 3.12
in `runs/v2/V2-12-wheel-proof`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| confidence.json | 1612228 | `9d95a5f546761eb1ac55fc981889bcbee7d6d456d0215be7f37515d670d37f40` |
| score_distribution.json | 195671 | `57a8dbe0cb1fb35c5a3c124d4624a8a0d4496b5fe84018db466dff84d0fc91f7` |
| seed_stability.json | 9587 | `42a6108422bd6b34e909093b24795d6b925882c4261e2c1465d966190078de49` |
| statistical_warnings.json | 36554 | `c7b89aa8be35485832d7d28aa77aafe59ffb78759ac85b835b8b6ccc8ae60258` |

The proof wheel is 204327 bytes (SHA-256
`5006ce53828ea34cec8ff77f3c47e1cea666501dcd35686d05c66422bc212fb5`);
the sdist is 447127 bytes (SHA-256
`83887cb2f1ab722d0e441c9ab7e1a02856e5a45f8e22b044cc2b1ee1ff1effb2`).
All three new runtime modules match the wheel; the statistical documentation,
example and tests match the sdist. Archives exclude private/generated content.

Commands run: Focused pytest; Ruff lint/format; strict mypy; full coverage pytest
with JUnit and the 90% floor; isolated build with uv; source and installed-wheel
examples; isolated package/dependency/import/doctor checks; artifact/member hashes;
archive exclusions; Markdown links; publication-content and import/data-flow
review; Git whitespace checks.

Results: Focused checks covered the new statistics and existing V1
scoring/comparison behavior. Full regression passed 897 tests with one expected Windows
symlink-permission skip in 440.28 seconds, at 94% combined statement/branch coverage.
Ruff lint/format passed across 183 Python files, and strict mypy passed all 81
runtime source files. All four artifacts matched across runtimes. Doctor reported
`ready`; imports resolved from site-packages and all 17 runtime packages had
compatible dependencies. Checked 254 local links across 53 Markdown files before
this completion record. Logs, JUnit, coverage and hashes remain under ignored
`runs/v2/`.

Safety review: Category D bounded data models and category A numerical/analyzer
modules use existing V1 matching/scoring/comparison and safety/provenance oracles.
Every actual proof is gated before matching or analysis; blocked inputs are omitted
from output. Category W example output uses fixed names in a new validated local
directory. No network, subprocess, callback, external detector, executable fixture
content or dependency was added to runtime. Bounds are eight runs per side,
128 records per run, 512 total records, eight events/detections per record, 4 MiB
input, 100..1000 bootstrap replicates and 32 MiB combined artifacts.

Known limitations: These are conditional finite-fixture estimates, not calibrated
population probabilities or release certification. IID declarations are unverified;
seeds do not add independent trials. Wilson coverage is approximate and bootstrap
coverage is pointwise/uncorrected, with explicit small/degenerate-sample warnings.
Latency conditions on detected alerts. Preservation/configuration evidence comes
from the producer; statistics do not replay transformations or authenticate it.
Only canonical V1 variant snapshots are supported here. JSON validation reproduces
analysis from retained evidence, not detector execution. Standalone export slices
must be linked to the full report. V2 CLI/report integration remains a later card.

Commit: `54ee6c83f0d5a5aa8ef3c380740445379c4d3dc2` —
`feat(confidence): add statistical uncertainty metrics`.

CI status: [GitHub Actions run 35951883958](https://github.com/AegisTrace/dvi-sentinel/actions/runs/35951883958)
passed both `core (3.12)` and `core (3.13)` for the exact implementation commit,
including test/coverage, package, isolated-install, CLI fixture and benchmark gates.

Next card: V2-13 Drift and Regression Memory.
