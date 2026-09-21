# Constraint-guided fixture exploration

V2-07 selects a bounded set of local telemetry cases that covers interactions
between declared transformation choices. It composes existing V1 probes, checks
their actual outputs, and preserves a reason for every rejected or skipped
combination. Selected cases can run through the existing local harness.

Use `plan_exploration(events, space, policy, seed=..., budget=...)` from
`dvi_sentinel.exploration`. `ParameterSpace`, `Parameter`, `Binding`, `Constraint`
and `BudgetPolicy` are immutable typed contracts in `constraint_models.py`.
Inputs are revalidated, including copied models. No V1 scenario or CLI contract
changes are needed.

## Finite choices and constraints

A parameter names a dimension with one through eight distinct options. Each
option is `none` or a named existing V1 probe: ordering, timestamp precision,
timezone spelling, schema alias, severity spelling, sensor/vendor alias,
declared optional-field dropout, one duplicate, bounded volume or benign noise.
An operation belongs to only one dimension. Dimension names and option names
sort canonically; transformations compose in dimension-name order.

A `Constraint` forbids one conjunction of exact parameter/option bindings.
Unknown names, duplicate terms and duplicate constraint IDs are rejected at
the schema boundary. To express an implication, forbid each disallowed
consequent combination. Constraints contain inert data; they cannot supply
expressions, callbacks, shell commands, plugins or network destinations.

Every enumerated assignment is evaluated against:

1. Declared forbidden conjunctions.
2. Existing V1 operation permissions.
3. Existing V1 transformations and independent preservation checks at every step.
4. Canonical schema, count/size bounds and structural safety policy after every step.
5. Final V2 ontology equivalence for every original event, including required evidence.

Failure or unknown semantic equivalence excludes a combination. For example,
dropping a correlation key can be permitted as a V1 probe but still fail V2
semantic equivalence. Two volume operations that create colliding event IDs are
also rejected. Rejections are evidence about the supplied space, not detections.
Unexpected implementation errors propagate; known representation or timestamp
limits produce structured rejection reasons.

## Coverage and budgets

`strength=2` requests pairwise coverage; strengths 1 through 4 are available
within the number of dimensions. The engine exhaustively evaluates the bounded
Cartesian space before selecting cases. An interaction is feasible if at least
one accepted full assignment contains it.

The covering array records theoretical, feasible and covered interaction counts,
the full infeasible-interaction list, and the feasible interactions still uncovered.
A greedy selector chooses the affordable case that covers the most remaining
interactions. A SHA-256 tie ordering derived from the seed and assignment makes
selection reproducible across declaration order and supported Python versions.
It does not promise a mathematically minimal covering array.

Case and selected-event budgets both apply. An expensive case cannot prevent an
affordable alternative from being considered. Every unselected feasible row is
explained as already covered, case-budget limited or event-budget limited.
Budgets limit selected execution cases; validation still visits the complete,
bounded space so the feasible denominator remains known.

State is `complete` only when a nonempty feasible space has all its interactions
covered, `partial` when feasible interactions remain, or `infeasible` when no row
passes filtering. An empty feasible set never becomes a successful coverage claim.
Parameter coverage measures declared choices. A no-op option can produce the same
telemetry as another choice; this does not establish unique semantic coverage or
novel detection evidence. Semantic novelty accounting belongs to V2-08.

## Evidence and safety

Candidate validation retains compact eligibility metadata. Only selected cases
are materialized for output; each is replayed and its digest must match the first
evaluation. The plan retains the original events, configuration, selected events,
per-step input/output hashes and independent invariant checks. Every full
assignment is accounted for exactly once as selected, rejected or skipped.

`exploration_artifacts` takes actual inputs and recomputes the plan, emitting:

- `constraint_plan.json`: complete configuration, retained input, selected cases,
  rejection/skip reasons and covering summary.
- `covering_array.json`: selected parameter rows and measured interaction coverage.
- `invalid_combinations.json`: rejected and skipped rows with their explanations.
- `exploration_manifest.json`: input/configuration linkage, counts, state and
  SHA-256 hashes of the other three artifact files.

Hashes establish content linkage and reproducibility, not source authenticity.
These are analysis artifacts, not a replacement for the V1 verified run bundle.

Limits: 2 through 6 dimensions, at most 512 full combinations, at most 32
constraints, 1 through 32 original telemetry events, 128 events per transformed
case, 2 MiB per input/candidate, at most 128 selected cases, 4096 selected events
and 32 MiB combined artifact output. The finite existing probe set bounds each
transformation; unsupported operations cannot enter the engine.

Models and analyzers perform no filesystem, subprocess or network I/O. The
example writes fixed filenames to a new local directory and rejects symlink
ancestors. No optional solver or new dependency is required. Larger search spaces,
numeric parameter synthesis, global optimality and external solver backends are
not implemented by this card.

Run the [example](../examples/constraint_exploration.py):

```powershell
.venv\Scripts\python.exe examples/constraint_exploration.py --out runs/v2/exploration-proof
```

Its four binary dimensions define 16 assignments; one forbidden conjunction
excludes four. Five selected cases cover all 23 feasible pairs out of 24 theoretical
pairs. The robust local control detects all five; the sensor-dependent control
detects three. [Behavioral tests](../tests/test_v2_constraints.py) verify these
controls, one-/two-/three-/four-way coverage, budgets, constraints, safety,
semantic unknowns, composition failures, replay and artifact integrity.
