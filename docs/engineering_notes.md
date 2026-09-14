# Engineering notes

DVI tests a declared local detector model under bounded telemetry changes. Its
hardest problem is deciding when changed input still supports a meaningful
comparison. The [research sources](research_sources.md) explain the lineage;
these notes explain decisions in the implemented V1.

## Keep meaning separate from representation

A single normalized dictionary would erase the spelling dependencies the probes
need to expose. Keeping only raw records would make every adapter responsible
for matching semantics. DVI retains both: typed normalized events and immutable
raw JSON snapshots with source record positions and digests. Whole fixture bytes
are captured separately because a parsed-payload hash cannot prove whitespace or
line endings. A semantic comparison deliberately excludes raw spelling while an
artifact identity includes it.

This costs storage and duplicate validation. It also makes loss explicit:
nanosecond timestamps are rejected, vendor severity is mapped deliberately, and
unrepresentable cross-schema fields produce unknown results. A round trip through
one encoder is insufficient evidence; differential testing re-parses each format
and compares an independently defined semantic projection. Even then, shared
model mistakes can escape the test, which is why explicit field assertions and
independently supplied disagreement fixtures remain necessary.

## An invariant is a separate check

Trusting a transformation's own claim of preservation would let a broken
generator validate itself. Independent checks retain every original event's
identity and protected semantics, inspect lineage, bound permitted time/metadata
changes, and reapply policy. Noise and duplicates remain distinguishable from
original events. Ordering changes require scenario permission: order is not
universally irrelevant to detection intent.

Invalid variants remain visible but cannot become measured misses. Fixed probe
relations complement seeded variation sampling; they do not discover arbitrary
equivalences. The benchmark suite pairs deliberately fragile rules with robust
controls so that producing many findings alone cannot make the suite pass.

## Unknown is a result with consequences

A Boolean match would conflate no alert with no usable observation. DVI uses
detected, missed and unknown, with stable reason codes and per-criterion evidence.
A complete fixture containing no detections can establish a miss; an absent
fixture, failed parser, unsupported representation or missing time attribution
cannot. Candidate matching is existential: one candidate must satisfy the
expectation, and partial matches from different detections are never combined.

For valid non-baseline variants, DVI reports detected/valid, missed/valid and
unknown/valid alongside detected/(detected+missed). Empty denominators are null.
Reporting only the latter rate could hide unavailable evidence. Latency has its
own sample count. Family distances use different units, so there is no global
hardest-case ranking or weighted headline score. The frontier describes observed
points, not a proven monotonic boundary or a statistical confidence interval.
The CLI gate evaluates variant metrics; probe and adapter findings stay explicit
and are not silently folded into that gate.

## Prefer bounded execution to extensibility

Two concrete harnesses justify a small `Protocol`: explicit detector-result
fixtures and declarative local rules. A generic plugin registry, `eval`, regular
expression engine or scenario command hook would expand both ambiguity and the
safety boundary. V1 has none. Structural policy checks examine normalized keys
and network identifiers at ingestion and after transformation; substring banning
of arbitrary prose would reject harmless descriptions without enforcing a
capability boundary.

Fixed attempts, event-occurrence budgets and file/record limits make resource
use inspectable. A seeded local RNG avoids dependence on global random state.
The cost is finite coverage and occasional exhausted/no-op plans, which are
reported. These checks do not create an operating-system sandbox. The test
socket guard and Docker's disabled network provide separate verification layers;
installation and image building may fetch dependencies before fixture execution.

## Shrink evidence without changing the question

Deleting any event until a detector stops matching would produce easy but
meaningless failures. The shrinker starts with a detected baseline and a valid
miss, retains original intent, and accepts a reduction only after preservation,
policy, the real harness and matching reproduce the same failure reason class.
It removes added events or reverses declared changes under a fixed attempt
budget. Caching avoids rerunning identical candidates; unknowns cannot be accepted.

The minimum is local to the available reductions and budget. It is not a global
optimum. Bounded ablation can show that a retained change is necessary in this
fixture; it cannot establish a universal causal mechanism. The normal CLI run
shrinks the first eligible failure, so its single minimum does not summarize
every finding in a run.

## Reproduction needs identity and a trust boundary

Comparing two aggregate rates would allow changed fixtures or sampled cases to
masquerade as detector regressions. Snapshot compatibility therefore checks
scenario, input and plan identity, seed and exact case contents before comparing
outcomes; detector definitions may differ intentionally. Incompatible evidence
produces exit 2 rather than a regression verdict.

Bundles retain observations and derivations, with typed cross-file verification
and a complete SHA-256 inventory. Hashes establish integrity against a trusted
external manifest digest, not authorship. A coherent rewrite of every file and
manifest is outside an unanchored hash check. Verification recomputes analysis
from recorded observations; it does not independently rerun the detector.

Writing directly into a destination could leave a plausible partial run. DVI
stages, flushes, verifies and renames a bundle. Explicit replacement first
verifies the old inventory, refuses extra files/directories and retains a backup
for rollback. The two directory renames are not a single crash-proof transaction;
concurrent hostile filesystem mutation and power-loss durability are outside the
contract. Analysis bytes are deterministic, while clocks and invocation/git
provenance intentionally make complete run manifests vary.

## Keep reports downstream of evidence

The dependency flow is scenario/fixture validation, normalization, bounded
experiments and observations, matching/analysis, then verified artifacts and
reports. Typed value modules carry contracts; `workflow.py` coordinates actual
I/O and the CLI presents results. Analysis modules do not invoke the CLI or
rendering layer.

Report findings resolve to files, record locations and digests rather than
unsupported narrative. Static HTML uses escaped content, local links and a
restrictive content policy, with no script or remote asset dependency. Source
inventory excludes derived reports to avoid circular hashes. Structural,
escaping and provenance tests establish those contracts; they cannot establish
visual readability. The separate Phase 13 rendered-view check remains open and
must pass before release.

## Verification must be able to disagree with the engine

Tests exercise real parsers, detectors and artifact consumers. Expected benchmark
classes, reason codes, metric ranges and minimum characteristics are evaluated
after execution; changing an oracle cannot change measured evidence. Properties
cover bounded domains, a pairwise matrix covers declared planner interactions,
and golden reports preserve output contracts. None substitutes for a fresh
installed-package run or Docker reproduction.

This approach found a concrete failure: general Unicode `splitlines()` split
valid JSON string contents at U+0085/U+2028/U+2029. Physical LF splitting fixed the
record boundary without weakening JSON validation. The permanent tests cover
those characters, CRLF, terminal newlines and original record indices. Coverage
percentages alone would not have identified that semantic error.
