# Behavioral verification

Run the installed development package with `pytest`. CI executes the whole suite
on Python 3.12 and 3.13 with a 90% coverage floor. Tests use real fixture parsers,
transformations, local rule detectors, matching, scoring and artifact consumers.
Mocks are limited to specific environmental failures such as missing package
metadata or a failed filesystem rename; they do not supply detector outcomes for
engine proofs. FixtureHarness tests explicitly distinguish absent observations
from recorded misses. The session network guard rejects Python DNS/socket I/O.

## Reproduce generated cases

`tests/conftest.py` loads the `dvi` Hypothesis profile: deterministic generation,
100 examples by default, no wall-clock deadline, and failure reproduction blobs.
Expensive engine properties declare smaller bounds (8–25 examples) beside the
test. A time deadline is inappropriate for shared CI machines; engine budgets and
exact semantic assertions provide deterministic limits instead. No Hypothesis
health checks are suppressed. Each generated filesystem case owns a fresh
temporary directory, avoiding leaked state between examples.

The test identity and Hypothesis version determine the default generated cases.
For an explicit seed, use the same Python/dependency versions and command:

```sh
pytest tests/test_boundary_properties.py tests/test_metamorphic.py tests/test_artifacts.py tests/test_matching.py --hypothesis-seed=20260910
```

Seed `20260910` was used during Phase 17 validation. It is a verification seed,
not a claim of exhaustive exploration. On failure, retain the printed minimized
input and reproduction blob together with the tool/dependency versions. First
replay that input using `@example(...)` or the emitted `@reproduce_failure(...)`,
then preserve the regression as a readable permanent example after fixing it.
Blobs can depend on the exact Hypothesis version. See the official
[failure replay guide](https://hypothesis.readthedocs.io/en/latest/tutorial/replaying-failures.html)
and [settings reference](https://hypothesis.readthedocs.io/en/latest/reference/api.html).

## What the tests establish

| Contract | Evidence |
| --- | --- |
| Strict event/scenario values | Timestamp offsets, Unicode metadata, sorted sets, JSON/YAML round-trips, invalid scalar types and numeric safety attestations |
| Structural safety | All prohibition families, normalized key spellings and nesting, reserved network boundaries, inert descriptions, path traversal, symlinks, size/depth limits |
| Parsing | Arbitrary bounded bytes produce deterministic structured results; partial failures keep original record positions; real supported schema mappings |
| Variations | Seed determinism, independent invariant checks, protected raw/semantic values, original-event coverage, post-transformation policy, exact resource budgets |
| Matching and probes | Stable reason codes and evidence, inclusive time windows, candidate-order invariance, robust controls, missing/ambiguous observations never counted as fragility |
| Schema equivalence | Real JSONL/CSV/EVE re-encoding preserves exact time, severity, documentation IPv4/IPv6 endpoints and ports; unsupported/lossy representations remain explicit |
| Frontier and regression | Explicit denominators across invalid/unparsed/missing cases, baseline exclusion, latency samples, compatibility rejection, seed-independent regression/recovery symmetry |
| Shrinking | Safe original intent survives; generated count failures converge to the known threshold plus one event; every remaining single-event removal restores detection |
| Artifacts | Complete hash inventory, byte mutations, missing/extra entries, coherent rehash inconsistencies, atomic replacement rollback and exact restoration |
| CLI and reports | Real bounded runs, valid/invalid exits, consumer tamper rejection, overwrite behavior, escaped content, resolving provenance and retained Unicode source labels |

Existing focused subsystem tests cover the individual contracts. The hardening
modules add interactions and generated state spaces. `test_metamorphic.py` uses
eight fixed rows for seven binary parameters: jitter, noise, duplicate bounds,
optional metadata, maximum variants, total event budget and seed. A separate
assertion checks that all four value combinations occur for every parameter pair.
Each row executes the real planner and a robust rule, then verifies budgets,
lineage, invariants, safety and detection outcomes. This is pairwise coverage of
those declared values; it does not cover every higher-order interaction or
combine different transformation families into one new V1 strategy.

Phase 17 uncovered a concrete JSONL bug: Python's general-purpose `splitlines()`
also splits U+0085, U+2028 and U+2029 inside otherwise valid JSON strings. The
parser now splits physical LF record boundaries, accepts CRLF, and does not count
a terminal newline as an additional record. Explicit regressions preserve those
Unicode characters, source indices, the 10,000-line boundary, and complete CLI
artifact verification. No scenario capability or safety policy was broadened.

The single local skip is the real symlink test when Windows denies symlink
creation without privilege. Linux CI executes it. HTML structure, escaping and
links are tested. The project owner confirmed rendered HTML readability on
2026-09-14, resolving the separate Phase 13 visual check. Coverage and passing
properties do not replace visual inspection; see [release verification](release_v1.md).
