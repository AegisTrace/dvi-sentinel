# Failure shrinking and fixture-local ablation

`FailureShrinker(harness).shrink(original, case, policy, expected, ...)` reduces
a nontrivial safe counterfactual only after the original is detected and the
candidate is a measured miss. An accepted reduction must pass independent
semantic/policy checks and retain the original matcher reason as well as missed
status. The finding class is bound to the variation family or a validated probe
catalog entry. Robust, unknown, and invalid starting cases receive no invented
root-cause ranking.

## Supported reductions

- Remove added duplicate or benign background events one at a time. All original
  events must survive: Phase 5 declares their full coverage as an invariant, so
  the shrinker cannot guess that an original event is irrelevant.
- Reduce individual timing offsets toward the original, preserving observation
  delay. Proposals include zero, successively closer fractional reductions, and
  one-microsecond reductions. No monotonic detector response is assumed.
- Restore changed optional metadata fields individually, including nonessential
  fields within the same family.
- Undo adjacent ordering inversions toward the original sequence; ordering must
  have explicit permission.
- Restore independently validated source representation changes one record at
  a time. Their normalized projection must remain identical, and source content
  must be either the original or the catalog's exact safe rewrite. Other probe
  classes use their corresponding normalized family and preserve the probe class.

The planner currently produces one family per variation. Shrinking does not
invent cross-family mixtures or a stronger semantic equivalence than the scenario
declares. Every accepted proposal simplifies one supported transformation.

## Minimum claims, bounds, and replay

Candidates use stable content-derived `shrink:` case IDs. A FixtureHarness must
contain explicit observations for those IDs; absent observations are unknown.
Reverting exactly to the original uses the already measured baseline. An unchanged
input cannot become a counterexample merely because a fixture lookup ID changes.

The default search permits 128 distinct reduction attempts and 32 ablations;
each budget can be 0–512. Inputs are bounded at 10,000 original events. Accepted
reductions restart the deterministic scan. Previously evaluated content is not
re-evaluated. `minimized` means no supported single reduction still reproduces
the same failure; it does not mean the globally smallest possible scenario.
Budget exhaustion remains explicit. Unavailable reduction observations leave
minimality unknown even when the retained candidate is a proven miss.

`MinimalCounterexample` retains original events, policy, expectation, optional
probe definition, final events/lineage, initial/final matches, preservation checks,
and the reduction trace. Replay uses the same local harness definition from the
scenario; the result does not embed an executable detector. Artifacts remain
inert local data.

## Ablation and root-cause ranking

After reduction, a separate bounded pass reverts each remaining transformation
component (or removes one remaining added event). `RootCauseRanker` places
`necessary_in_fixture` observations first: removing that component restored the
expected detection. It retains `failure_persists`, `different_failure`, unknown,
and invalid results instead of forcing certainty. Necessity is conditional on
this fixture and these tested ablations. It is not universal causality, proof of
an implementation defect, or a statistical confidence estimate. No available
ablation observations means unknown, not a measured cause.

`shrink_artifacts` serializes `minimal_case.json`, `minimal_case.md`,
`shrinking_trace.jsonl`, and `root_cause.json` without I/O. Run
`uv run python examples/shrink_failure.py` to write the concrete proof beneath
`runs/shrinking-proof/`. It reduces eight events to four: two protected originals
and two duplicates needed to exceed the rule's count-three threshold.

`tests/test_shrinking.py` proves that minimum, one added noise event, one affected
metadata/source record, one ordering inversion, and an exact 10.001 ms timing
boundary. Tests also verify restoring nonessential metadata, preserving class
and matcher reason, rejecting lost intent/unsafe content, deterministic replay,
artifact round trips, zero budgets, unknown fixture reductions, and robust cases
without fake causes. No scenario commands, network operations, attack generation,
or adaptive discovery queue are introduced.
