# Temporal and correlation evidence

V2-05 evaluates finite event sequences after canonical event validation. It
normalizes timezone-aware timestamps to UTC and orders events by `(timestamp,
event_id)`, so input order and equal-time ties cannot change a result. It does
not use a wall clock or search beyond the supplied bounded fixture.

The ten predicates are `before`, `after`, `within`, `same_entity`, `same_flow`,
`same_correlation_key`, `at_least_k_of_n`, `no_contradictory_context`,
`alert_within_window` and `sequence_order`. They return a typed supported,
contradicted or unknown decision. Unknown is used when required evidence is
missing: entities, complete flow endpoints, correlation IDs, detection subtype,
declared pattern events or retained timestamp precision. A benign/control marker
(`benign`, `control`, `allow`, `allowed` or `expected`) is explicit contradictory
context and suppresses a sequence finding.

`within` and `alert_within_window` use inclusive finite millisecond windows from
0 through 24 hours. `sequence_order` matches event IDs, semantic categories or
actions as an ordered subsequence. `at_least_k_of_n` requires a supplied finite
set of exactly enough evidence; a shorter set remains unknown. Same-flow checks
compare source endpoint, destination endpoint and protocol. Same-entity checks
require a shared explicit `(kind, value)` reference. Correlation compares the
retained `correlation_id` string and never generates a key.

The optional `precision_digits` argument declares the minimum fractional digits
required in each event's retained `raw.original_timestamp`. If source text has
fewer digits or is unavailable, the temporal decision is unknown with a
`timestamp_precision_loss` reason. This describes representation evidence only;
it does not claim clock accuracy or sensor resolution. Offset timestamps that
represent the same instant compare equally after UTC normalization.

`temporal_artifacts(events, ...)` revalidates actual events and emits four
canonical files:

- `temporal_trace.jsonl` — ordered predicate traces, normalized timestamps,
  source precision and field-level decisions;
- `correlation_evidence.json` — retained correlation-key values and state;
- `sequence_findings.json` — deterministic predicate findings and reason codes;
- `temporal_summary.json` — input digest, stable event order, traces, findings and
  aggregate state.

Inputs are limited to 128 unique events and 2 MiB of combined canonical event
data. Windows and patterns are finite and capped at 24 hours/128 tokens; each
artifact is bounded by the existing 32 MiB local artifact limit. All four files
are derived from the validated input on every call and contain no external
network, filesystem, subprocess, query or expression execution.

Run the executable proof with a new output directory:

```powershell
.venv\Scripts\python.exe examples/temporal_correlation.py --out runs/v2/temporal-proof
```

The implementation is in [temporal_models.py](../src/dvi_sentinel/temporal_models.py)
and [temporal.py](../src/dvi_sentinel/temporal.py), with behavioral coverage in
[test_v2_temporal.py](../tests/test_v2_temporal.py).
