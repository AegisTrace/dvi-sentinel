# Changelog

## Unreleased - V2 development

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
