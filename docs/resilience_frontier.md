# Resilience frontier and fragility taxonomy

`summarize(assessments, probes=(), differential=None)` consumes typed local
measurements. It performs no harness execution or I/O. The baseline assessment is
retained separately and excluded from variant metrics. IDs must be unique and
there can be at most one baseline. Invalid cases and parser failures cannot
contribute detected outcomes even if the supplied matcher says detected.

## Exact formulas

Every ratio serializes numerator, denominator, and value. A zero denominator
produces `null`, never zero or one. Let `N` be non-baseline assessments, `V` those
with passing semantic preservation, and `D/M/U` their detected/missed/unknown
partition. A valid case with failed/unknown parsing or no match is unknown.

| Metric | Formula / population |
| --- | --- |
| total / tested | N / assessments with an available MatchResult, including guarded unknowns |
| semantically_valid / invalid | V / N - V |
| detection / miss / unknown rate | D/V, M/V, U/V |
| measured_detection_rate | D/(D+M); excludes unknown observations explicitly |
| invariant_pass_rate | passing individual checks / all recorded individual checks |
| semantic_preservation_rate | V/N; an empty check set does not establish preservation |
| parser_success_rate | true / (true + false); null parser states counted separately |
| evidence_completeness | available configured comparisons / configured comparisons assessed |
| adapter_disagreement_rate | disagree / (agree + disagree); unknown cases counted separately |

Evidence aggregation uses the matcher's decisive candidate selection, preserving
its semantics. Passes and contradictions are available evidence; missing/unknown
comparisons are unavailable. Only valid, successfully parsed assessments with
candidate comparisons participate; `evidence_cases` reports that sample count.
Unknown guards and empty detections supply no invented comparison count. Thus a
complete severity failure can have evidence completeness 1.0, while a no-alert
miss has no measured completeness. See `matching.md`.

Latency includes only detected, valid, successfully parsed variants with a
reported delay. Report the sample count and p50/p95 using linear interpolation
at sorted position `(n-1)*p`. A single sample yields itself at both percentiles;
an empty sample yields null. These are observed alert delays, not harness runtime
or a statistical population claim.

## Observed boundaries

Every represented variation family gets its own metrics and boundary:
`minimal_miss_distance`, `easiest_safe_missed`, and `hardest_safe_detected`.
Only eligible measured misses/detections participate. Ties use lexicographic case
ID. These boundaries describe tested points, not a monotonic failure threshold.
No global hardest-case ranking mixes timing distance with duplicate counts or
other family-specific units. An absent boundary is null. Baseline success is not
required to describe raw outcomes, but it is required to infer variation-associated
fragility.

## Taxonomy and evidence

The finite taxonomy includes schema, timestamp/timezone, ordering, optional-field
dependency, severity normalization, correlation-key dependency, noise sensitivity,
volume sensitivity, and adapter disagreement. A missed valid variant following a
detected valid baseline is associated with its declared family. That association
does not prove cause. Probe findings retain the probe rationale and passed
preservation; differential findings retain measured field/outcome disagreement.

Finding IDs bind class, evidence source, and case ID. Repeated identical findings
are deduplicated; distinct sources can corroborate the same class. Evidence paths
are logical selectors over variations, matches, probes, and differential cases.
The artifact/report phases will resolve those selectors into files. No weighted
headline score, confidence interval, or adaptive discovery model is implemented.

`tests/test_scoring.py` checks exact formulas, empty/baseline-only/unknown cases,
invalid and parser guards, unknown denominator handling, interpolation, ID ties,
determinism, round trips, and outcome partitions with Hypothesis. Real variation
fixtures give miss rate 1.0 and minimum miss distance one for an exact-count rule;
the robust control gives detection rate 1.0. Real probe/differential results verify
taxonomy deduplication and a one-third adapter disagreement rate.
