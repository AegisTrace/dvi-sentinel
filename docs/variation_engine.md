# Deterministic variation planner

`plan_variations(scenario_id, events, policy, seed)` returns a typed, immutable
VariationPlan. It does not execute a detector or write artifacts. Inputs must
contain 1..10,000 uniquely identified, policy-safe normalized events. Seed is an
integer in 0..2^63-1. Run `uv run python examples/plan_variations.py` for a real
fixture-based plan summary and reproducibility digest.

Each VariationStrategy declares a stable ID, allowed changes, protected
invariants, bounds, and local_synthetic safety class. Each VariationCase contains
parameters, transformed events, event lineage, a semantic-preservation result,
and an explicitly defined distance. Lineage distinguishes surviving originals,
copies, and synthetic background additions. The baseline is always first.

## Implemented transformations

| Family | Changes | Restrictions |
|---|---|---|
| timing | Independent integer-millisecond jitter to event and observation time | Within max_jitter_ms; observation delay preserved |
| ordering | Permute input sequence | Requires order_independent; no event values changed |
| metadata | Uppercase/lowercase or fixed synthetic alias of sensor/vendor metadata | Only fields declared optional |
| noise | Add simple synthetic UDP background records | Documentation endpoints, no correlation, unknown severity, explicit background label; max_noise_events |
| volume | Duplicate original observations with new canonical IDs | Originals retained; lineage links each copy; max_duplicates |
| dropout | Remove optional metadata | Only declared sensor/vendor/labels/tags/correlation_id/confidence |

All transformations preserve original EventSemantics, severity, source payloads,
and undeclared metadata. Scenario validation prevents required matching evidence
from also being declared droppable. No transformation modifies input objects.
Raw payload strings/digests stay as immutable evidence of the source observation;
canonical metadata/timestamps describe the variation. Thus `raw.*` local-rule
conditions see the original payload, while normalized-field conditions see the
variation. Metadata aliases here are sensor/vendor *values*, not schema-key edits.

Jitter permission explicitly allows bounded changes in relative timestamps; it
does not prove that an arbitrary application-specific temporal invariant holds.
Ordering permission concerns the event sequence. Scenarios must declare bounds
that preserve their intended fixture meaning. DVI verifies its declared invariant
set rather than claiming universal equivalence for every detector.

## Independent validation

`check_candidate` compares candidates against originals instead of trusting the
transformation implementation. Checks have stable IDs and boolean outcomes:

- DVI-INV-IDENTITY: unique candidate IDs and complete lineage.
- DVI-INV-COVERAGE: every original remains exactly once.
- DVI-INV-PROTECTED: unchanged semantics, severity, raw payload, undeclared fields.
- DVI-INV-TIMING: bounded jitter and preserved observation delay.
- DVI-INV-TRANSFORM: allowed metadata forms; dropout only removes values.
- DVI-INV-NOISE: explicit, uncorrelated synthetic background.
- DVI-INV-BOUNDS: declared family and bounded additions/total event count.
- DVI-INV-ORDER: explicit permission for order changes.
- DVI-INV-POLICY: safety policy re-evaluated on the transformed events.

Invalid candidates remain inspectable in `cases` with failed checks, and are
excluded from `valid_cases`. Callers must execute only `valid_cases`. Invalid
baseline input raises an error before planning. Overflow or model-limit failures
that prevent construction are recorded as typed omissions with DVI-VAR-OVERFLOW
or DVI-VAR-FIELD-LIMIT. These are not detection misses.

## Determinism and bounds

Strategies run in sorted family order. Each attempt gets an independent local
RNG derived from seed, attempt index, family, input digest, and config digest;
global random state is untouched. IDs also include scenario identity, parameters,
and tool version. Canonical JSON serialization makes repeated plans byte-stable.
Input representation/provenance contributes to input identity; semantic equality
alone does not imply the same plan IDs.

max_variants includes baseline. Planning stops at that limit, four times that
many attempts, or an aggregate event budget. The default/hard maximum event
budget is 50,000 event occurrences across cases; a lower explicit event_budget
can be supplied and becomes part of config identity. Exhaustion records
DVI-VAR-EVENT-BUDGET. No-op/duplicate candidate content is suppressed and counted.
Small state spaces can yield fewer cases than requested. There is no adaptive
search, mixed-family interaction planner, or constraint solver in this phase.

Distance is a documented edit cost, not universal case difficulty. Timing sums
absolute offsets divided by max(1, configured jitter bound); ordering counts
moved positions divided by event count; metadata/dropout count changed
event-fields; noise/volume count added records. Compare family-specific distances
first. Cross-family totals depend on these chosen units and policy bounds.

## Proof

`uv run pytest tests/test_variations.py` covers every family, deterministic JSON
round-trips, multiple seeds/bounds, invalid baseline inputs, protected-field and
policy violations, arbitrary edits disguised as dropout, lineage loss, ordering
permission, source integrity, finite budgets, timestamp overflow, and actual
execution of valid cases through the local rule harness. Hypothesis uses bounded,
deterministic examples without timing-based deadlines for these properties.
