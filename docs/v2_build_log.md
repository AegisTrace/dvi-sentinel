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
were verified before creating the `codex/v2-semantic-engine` development branch.

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
