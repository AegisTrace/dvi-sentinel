# Changelog

## Unreleased — V1 candidate (`0.1.0.dev0`)

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

### Release status

No V1 release is tagged. The rendered HTML readability check remains open despite
passing content, escaping, provenance and deterministic regeneration tests. The
[build log](docs/build_log.md) records actual incremental work and verification;
the [roadmap](docs/roadmap.md) lists intentionally deferred capabilities.
