# ADR 0002: Narrow V1 scope

Status: accepted; implemented across the V1 engine and benchmark suite.

A general telemetry platform would require broad schema mappings, plugins,
storage and external services before its resilience claims could be verified.

Decision: support local flow/alert/DNS/light-HTTP fixtures, bounded variations,
fixed probes, supported-representation comparisons, explained matching, observed
frontiers and a bounded shrinker. Require concrete benchmark evidence for each
advanced claim. Keep a protocol only where the two real harnesses need it.

Consequence: fewer schema/capability claims can be tested deeply. Unsupported
representations remain explicit. Solvers, full schema exports, analytics engines,
adaptive search and additional report standards stay on the [roadmap](../roadmap.md),
without speculative implementation scaffolding.
