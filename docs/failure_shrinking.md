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

## V2-11 oracle-aware reduction

`shrink_with_oracles` in `dvi_sentinel.consensus_shrinking` adds an opt-in mode
above the same V1 proposal and independent invariant machinery. The V1 API and
its artifacts retain their existing behavior. The new mode takes an
`OracleShrinkInput`, not caller-supplied oracle votes or an arbitrary detector:

```python
from dvi_sentinel.consensus_shrinking import shrink_with_oracles

input_digest = request.stable_digest()
report = shrink_with_oracles(request, expected_digest=input_digest)
```

The request embeds original events, a V1 `VariationCase`, variation policy,
detection expectation, optional catalog probe, bounded local rule configuration,
precision requirement and execution budget. Policy, integrity and initial
invariants are checked before detector evaluation. Missing ontology evidence stops
consumption. A detected original baseline and a measured initial miss with
**confirmed** nine-oracle consensus are prerequisites for shrinking.

### Explicit event scope and supported changes

`protected_event_ids` is required and nonempty. It names the original events that
must survive; all expectation event IDs must be included. Declaring the remaining
original events removable is an explicit scope decision. The analyzer does not
infer which incident evidence is dispensable. To preserve V1's full original
coverage, protect every original event.

Event removal tries coarse chunks, then progressively smaller chunks and individual
events in deterministic order. Each proposed scope is independently validated,
and its surviving **original baseline is actually evaluated again**. It must still
detect with resolved oracle evidence before the reduced candidate can be accepted.
Protected identities, normalized meaning and undeclared fields remain protected
within that scope. This does not claim preservation of the complete removed
scenario's meaning. Added duplicates/background follow the existing lineage rules.

After event removal, the analyzer reuses V1 reductions: timestamps move toward the
original at microsecond resolution; optional metadata is restored field by field;
catalog aliases are restored record by record; declared optional correlation-key
changes are restored independently; ordering reductions retain explicit permission.
Each study uses one declared V1 variation family, with its existing catalog-probe
exception for source representations. Arbitrary cross-family mixtures are rejected.
Timing and optional correlation changes preserve the scenario's declared V1
invariant, not an assertion that every timestamp/key is identical. The independent
semantic and temporal oracles must also remain resolved.

Accepted proposals strictly decrease a lexicographic cost: event count, changed
components/order, then total absolute timestamp offset. Acceptance restarts the
scan. This gives a local minimum under supported reductions, without assuming
monotonic detector behavior or guaranteeing a global minimum.

### Finding and consensus preservation

The target class is bound to the V1 family or validated catalog probe. Actual
remaining changes must still contain that class. For example, restoring every
changed correlation key cannot leave a correlation finding supported only by a
vendor change, even if both would have the same matcher reason.

Every measured candidate runs the existing fixed `RuleLogicHarness`, matcher and
[nine oracle checks](oracle_consensus.md). To accept it, the matcher must retain
missed status and the original reason, and the oracle signature must retain the
initial state, confidence, and each oracle's decision, confidence and reason codes.
Only content-specific evidence links may change. A shared state label alone is
insufficient. Statistical and differential oracles remain explicitly not applicable
when no optional evidence was collected; the shrinker never fabricates repeats.

An unknown, ambiguous, probable or otherwise unresolved baseline/candidate stops
the search immediately. The last proven case remains available with state `unknown`.
Known invalid/unsafe proposals are rejected before evaluation; their trace retains
hashes and rejection checks without unsafe candidate content. Restored detections,
lost baseline detection, changed class/reason or changed resolved consensus are
rejected. Unexpected engine errors propagate.

A missing alert can be a measured matcher miss while alert timing is unknown.
Such a V2-10 [counterfactual finding](counterfactual_causality.md) cannot be promoted
to confirmed consensus by shrinking: the new mode stops with its missing evidence.
Confidence describes finite check resolution, not a probability or statistical
confidence interval.

### Trace, budgets and artifacts

Every distinct proposal considered in a scan receives an `OracleShrinkAttempt`,
including rejections, invalidity, uncertainty and mid-attempt exhaustion. Identical
proposals within one scan are deduplicated before attempting them. Repeated content
across scans reuses the measured observation with its original evaluation index;
the new attempt is still recorded. The trace links parent/candidate hashes, lineage,
cost, invariants, actual classes, baseline controls, matcher results and oracle evidence.

Bounds are 1-16 original events, 1-64 candidate events, eight local rules and
256 KiB per request. `OracleShrinkBudget` permits 0-128 attempts, 0-258 actual
evaluations and 0-4096 evaluated events, shared by the original baseline, initial
case and all reduced controls/candidates. Default limits are the maxima. A budget
stop names the pending reduction; an unattempted proposal is never counted as an
observation or miss. Only state `minimized` supports the local minimum claim.

`oracle_shrink_artifacts(request, expected_digest=input_digest)` recomputes four
files, limited to 32 MiB combined:

- `shrunk_case.json`: pinned input, initial/final evidence, complete trace and budgets.
- `shrunk_case.md`: state, retained event count, actual evaluations and scope limits.
- `shrinking_trace.jsonl`: one record for each attempted reduction.
- `oracle_preservation.json`: initial/final consensus and linked per-attempt signatures.

Models validate observation links, matcher/consensus derivations, actual costs and
classes for measured proposals, accepted invariants, trace chains and unique
evaluation accounting. Loading JSON does not rerun the local detector or prove
that a producer supplied every attempt; reproduce from the pinned input. Hashes
provide content linkage, not authenticity. These files do not replace a verified
V1 run bundle or certify a V2 release.

Run the [four-control example](../examples/oracle_shrinking.py):

```powershell
.venv\Scripts\python.exe examples/oracle_shrinking.py --out runs/v2/oracle-shrinking-proof
```

Each fixture starts with six events and finishes with one protected event.
Metadata restores the irrelevant vendor change, schema and correlation retain
one required changed record, and timing reaches the measured 10.001 ms boundary
against a 10 ms expectation. All preserve confirmed consensus. The example writes
only fixed filenames beneath a new validated local directory.
