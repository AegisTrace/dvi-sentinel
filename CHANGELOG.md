# Changelog

## Unreleased - V2 development

### Added

- Opt-in schema-2 artifact bundles with deterministic parent-hash DAGs, transitive
  integrity failures, ancestry and verification artifacts, and noncircular report
  provenance summaries. Core dependencies and rendered report views are verified;
  legacy bundles remain readable and unknown producer artifacts require declarations.

- Typed detection knowledge graphs from pinned local counterfactual studies, linking
  findings and proposed review actions to observations, source artifacts and tested
  causes. Four JSON views preserve weak edges, diagnostic disagreement and untested
  remedies with deterministic identities and strict source/topology validation.
- Pinned local regression memory with immutable named baselines, detector/version
  and schema-profile compatibility, observed drift classifications and conservative
  confidence-aware gates. Four artifacts preserve trends, paired uncertainty and
  reloadable history; unknown evidence cannot pass and V1 regressions remain failures.
- Conditional statistical confidence with Wilson detection/miss intervals, seeded
  latency bootstrap, per-case seed agreement and paired regression uncertainty.
  Four artifacts attach explicit denominators and calibration limits to findings,
  families and runs while preserving safety/provenance and V1 regression decisions.
- Opt-in oracle-aware failure shrinking using V1 reductions and invariants, explicit
  protected event scopes, measured baseline controls and preserved finding/consensus
  signatures. Four artifacts retain every attempted reduction and shared budgets;
  unresolved or disagreeing evidence stops minimization immediately.
- Local counterfactual failure mining with measured baseline/single/combination
  observations, complete proper-subset controls, conditional minimal failure sets
  and deterministic descriptive effect rankings. Four artifacts preserve actual
  harness/matcher evidence, unknowns, invalid candidates and execution budgets.
- Cross-representation metamorphic comparisons through eight existing fixture/profile
  paths, field-linked findings, retained normalization evidence and a deterministic
  pairwise matrix. Four artifacts distinguish observed losses from unsupported or
  ambiguous evidence; pairwise agreement does not hide shared loss against the source.
- Measured semantic discovery coverage across twelve dimensions, seeded novelty
  retention, exact union growth and a conservative evidence-resolution gate.
  Four artifacts retain actual analysis evidence and explain duplicate, unknown
  and safety-rejected cases without claiming security completeness.
- Finite constraint-guided exploration over existing safe probe operations,
  pairwise/t-way coverage of feasible combinations, invariant/policy filtering,
  deterministic seeded selection and explicit case/event budget omissions.
  Four artifacts link selected cases and coverage to actual input and transform evidence.
- Bounded detection intent parsing and evidence analysis for native declarations,
  a deliberately small Sigma-style metadata/selection subset and validated V1
  rule metadata. The four deterministic intent/loss artifacts retain expected and
  observed values, source digests, unsupported conditions, metadata scope and
  pending time/correlation assumptions; this does not execute rules or compile Sigma.
- Bounded temporal and correlation predicates with stable UTC/event-ID ordering,
  explicit missing-key and timestamp-precision unknowns, benign-context suppression,
  deterministic JSON/JSONL traces and a runnable flow-to-alert proof. Sequence and
  window decisions remain local evidence checks, not production detector execution.
- Nine local oracles with separate eligibility and diagnostic roles, recomputed
  input integrity, preserved disagreement and conservative gap confirmation.
  Four deterministic artifacts retain decisions, input evidence and uncertainty;
  delayed-alert and timely-control fixtures exercise real harness observations.
- Seven revisioned local schema/metadata profiles with explicit field paths, aliases,
  extensions, strict normalization, timestamp/severity loss traces and deterministic
  roundtrip reports. Incomplete Sigma metadata stays unknown; no full standard or
  compiler support is claimed.
- Executable semantic algebra for preservation, required evidence, contradiction,
  implication, equivalence, weakening and finding association. Decisions retain
  field-level values, explicit unknowns and evidence-support denominators; exported
  plans replay against their recorded evidence before serialization.
- Semantic ontology above canonical events: strict immutable signal/evidence models,
  loss-aware equivalence, profile requirements and deterministic exports with a real
  local example. Source provenance stays separate from semantic identity; unresolved
  evidence cannot prove equivalence. Package development version is `2.0.0.dev0`.

### Fixed

- Bound URL-candidate scanning in fixture policy checks by locating delimiters first.
  Long ordinary scalar values no longer trigger quadratic regex backtracking; the
  existing URL detection and rejection semantics are retained and regression-tested.

### Planning

- Defined the semantic-engine scope, ordered implementation cards, safety categories,
  V1 compatibility requirements and release gates in `docs/v2_architecture.md`.
- Added the one-card development standard and separated planned V2 capabilities
  from released V1 behavior. This scope-lock change adds no runtime capability,
  dependency or new command.

## 1.0.0 — 2026-09-14

### Implemented

- Typed canonical events, retained raw evidence, strict local scenario DSL and
  structural safety policy with explicit rejection reasons.
- JSONL/CSV/synthetic EVE normalization and two local detector harnesses.
- Deterministic bounded variations, independent invariants, fixed assumption
  probes and cross-schema differential comparisons.
- Explained detected/missed/unknown matching, per-family frontier metrics,
  compatibility-aware regression and bounded safe counterexample shrinking.
- Verified run bundles, SHA-256 manifests, finding provenance and JSON/Markdown/
  self-contained HTML reports; integrated doctor/validate/run/report/compare/gate CLI.
- Twenty fixture benchmarks with robust controls, meaningful property/metamorphic
  tests, Python 3.12/3.13 CI, installed-wheel checks and confined Docker reproduction.
- Reproduction proof, engineering/source notes, safety audit, architecture/decision
  records and contribution/security documentation.

### Fixed during development

- JSONL parsing now uses physical LF boundaries so U+0085/U+2028/U+2029 inside
  valid JSON strings remain intact. CRLF and terminal-newline behavior are tested.

### Release verification

The project owner confirmed rendered HTML readability on 2026-09-14, completing
the visual check alongside passing content, escaping, provenance and deterministic
regeneration tests. [Release verification](docs/release_v1.md) records the final
checks; the [build log](docs/build_log.md) preserves incremental work and the
[roadmap](docs/roadmap.md) lists intentionally deferred capabilities.
