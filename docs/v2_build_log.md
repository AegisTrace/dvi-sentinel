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
correction and published release tag. V2-02 is next after the combined main commit
passes CI.
