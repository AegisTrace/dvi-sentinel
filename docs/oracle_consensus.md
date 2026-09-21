# Local oracle consensus

V2-06 evaluates the specific claim that a supplied local fixture shows a detection
gap. Nine checks retain their own decision, evidence references, reasons,
uncertainty, confidence basis and content digest. A successful safety check is an
eligibility condition; it does not vote against a measured miss.

The public inputs are `OracleEvidence` in `oracle_models.py`,
`evaluate_oracles(evidence, expected_digest=...)` in `oracle.py`, and
`build_consensus(results)` / `oracle_artifacts(evidence, expected_digest=...)` in
`oracle_consensus.py`. Evidence contains actual canonical input events, an existing
V1 detection expectation and local harness observation, plus optional repeated
observations and representation bytes. The engine does not accept a caller's
match status, statistical score or Boolean provenance attestation as proof.

| Oracle | Measured check | Role |
| --- | --- | --- |
| Safety | Structural policy over all input and detection records, repeated observations, expectations and parsed representations. | Required gate; rejects unsafe consumption. |
| Schema | Revalidation of V1 canonical models, raw digests, unique event IDs and subject linkage. Invalid schemas are rejected at the input boundary. | Required gate. |
| Semantic | Existing ontology extraction and required bindings over input events; explicit benign/control context. | Required gate. |
| Temporal | Finite alert windows and requested correlation-key equality using actual event references. | Diagnostic. |
| Differential | Independent normalization of supplied canonical JSONL, CSV or EVE representations and comparison of actual fields. | Corroborating check; no duplicate matcher vote. |
| Detection | Existing explainable matcher, rerun against the actual expectation and observation. | Diagnostic. |
| Statistical | Counts of detected/missed/unknown in supplied local repetitions, each evaluated by the matcher. | Diagnostic repeatability check. |
| Evidence | Required paths resolve within the retained input, including the mandatory events, expectation and observation. | Required gate. |
| Provenance | SHA-256 recomputed from complete canonical input and compared with the producer's pinned digest. | Required gate; mismatch blocks consumption. |

Each decision is `pass`, `fail`, `warn`, `unknown`, `not_applicable` or
`unsafe_rejected`. Diagnostic failure supports the gap claim; diagnostic success
opposes it. A timing pass and metadata-based matcher miss remain a visible
disagreement because their checks have different scopes. No majority hides that
disagreement. Optional repetitions and representations may be not applicable;
missing required evidence is unknown.

## Consensus rules

Decisions must have unique, recognized oracle IDs and identical subject/input
digests. They are revalidated and sorted by oracle ID before combination.

- A blocking safety or provenance failure yields `unsafe_rejected`. The evaluator
  records the remaining checks as not applicable and does not call their analyzers.
- Missing/nonpassing required gates, gate confidence below 0.75, or absent primary diagnostics yield
  `not_enough_evidence` with zero confidence.
- Matching explicit benign/control context from both semantic and temporal checks
  suppresses attribution as `suppressed_false_positive`, after the other gates pass.
- Opposing diagnostic decisions yield `ambiguous`; both sides remain recorded.
- Required unknown diagnostic evidence prevents confirmation, even if other
  diagnostics have decisive failures.
- At least two diagnostic failures, passing gates and no unknowns can yield
  `confirmed`. Warnings lower it to `probable`.
- At least two diagnostic passes with no warnings suppress the proposed gap as
  `suppressed_false_positive`. Insufficient support remains `probable`, `unknown`
  or `not_enough_evidence`, according to the retained evidence.

Confidence measures resolution of these finite checks: decisive observations are
1, warnings at most 0.5, unknown/not-applicable observations 0. Consensus uses the
minimum supporting resolution; warnings cap it at 0.5 and required missing evidence
at 0. It is **not a probability, statistical confidence interval or guarantee**.
Multiple analytical views may share the same fixture. Repetitions reuse the
matcher and must not be described as independent samples. The minimum repetition
count (default 3) is an explicit repeatability policy, not a significance threshold.
Primary observations and repeated case IDs cannot inflate the repetition count.

## Timing and evidence scope

Temporal checks use the declared reference timestamp or the latest uniquely
referenced input event. A sole input event can be the reference when no IDs are
declared. Missing referenced IDs, missing correlation keys, absent alerts or
incomplete observations remain unknown. An empty *complete* detector observation
is a matcher miss, but supplies no measurable alert timestamp to the timing check.
Candidates are combined existentially and identified by the declared detector.
Timing does not independently validate every metadata constraint of the matcher.
Benign/control markers apply to the supplied fixture as a whole, following the
V2-05 context predicate; they do not establish a causal relationship to one alert.
Callers must choose the bounded context for the candidate being evaluated.

With `precision_digits > 0`, retained source text must contain enough fractional
digits and normalize to the actual canonical timestamp. The expectation's explicit
reference timestamp has no retained resolution record, so that combination remains
unknown. Windows remain bounded by the existing 0..24-hour expectation contract.
The oracle calls the relevant V2-05 predicates directly; the V2-05 demonstration
summary includes both `before` and `after` and is not a conjunctive detection contract.

The input producer pins `evidence.stable_digest()` before consumers process it.
Missing provenance prevents confirmation; a changed digest blocks consumption.
Hashes establish byte/content linkage, not authenticity of external assertions.
A caller that supplies both changed evidence and a new digest creates a different
input, not an authenticated historical observation.

## Artifacts and limits

`oracle_artifacts` re-evaluates actual evidence and emits exactly four files:

- `oracle_decisions.jsonl`: one decision per oracle, sorted by ID, with a digest
  over the canonical record excluding its `digest` field.
- `oracle_consensus.json`: claim, state, supporting/opposing/blocking IDs, all
  decisions and the full validated `evidence` object. Decision paths resolve
  relative to that object. Blocked inputs are omitted instead of re-exported.
- `uncertainty_report.json`: unresolved checks, reasons and confidence limitations.
- `oracle_matrix.json`: check roles, decisions, confidence and linked result digests.

Limits: 128 input events, 128 detections per observation, 128 uniquely identified
repetitions, 3 representations, 32 extra evidence paths, 2 MiB total canonical input,
9 decisions and 32 MiB combined output. Representation parsing retains the existing
adapter record/size bounds. Path selectors traverse only inert dictionaries and
numeric array positions. No network, subprocess, expression, query, plugin or
detector service is executed. Analyzers are pure; the example writes fixed filenames
under a new local directory and refuses existing output or symlink ancestors.

Run the real delayed-alert and timely-control proof:

```powershell
.venv\Scripts\python.exe examples/oracle_consensus.py --out runs/v2/oracle-proof
```

The delayed local harness alert is 2 seconds after its signal against a 1-second
expectation and is confirmed by matcher, temporal and repeated-observation checks.
The 0.5-second control suppresses the proposed gap. See the
[example](../examples/oracle_consensus.py) and
[behavioral tests](../tests/test_v2_oracles.py). Population statistics, V2 CLI wiring
and integrated reports belong to later cards.
