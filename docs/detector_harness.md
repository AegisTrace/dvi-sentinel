# Local detector harness

`DetectorHarness.evaluate(HarnessRequest)` accepts a case ID and immutable local
telemetry. It returns `HarnessResult`: case ID, complete/unknown status, typed
detections, issues, and rule traces. Complete with no detections is an observed
empty result. Unknown means the observation is unavailable or invalid, not a
confirmed miss. Expected-vs-observed matching is a separate subsystem.

Two concrete implementations justify the small Protocol. There is no plugin
registry, subprocess API, command templating, socket client, or live integration.
Requests for capabilities other than `local_fixture` return
`DVI-HARNESS-UNSUPPORTED`. Input IDs must be unique; policy rejection produces an
unknown result with an explicit issue. Input objects and files remain unchanged.

## FixtureHarness

Load with `FixtureHarness.from_file(root, relative_path)`. Bounded local path
checks apply. JSON must contain schema_version `1` and a `cases` array; each case
has case_id and an explicit detections array of canonical DetectionEvent objects.
Case IDs and per-case detection IDs must be unique. Duplicate JSON keys and
non-finite constants fail. Malformed schema produces DVI-HARNESS-MALFORMED;
file-access rejection retains the underlying DVI-POL rule ID.

Only the requested case's declared observation is returned. No matching case
returns DVI-HARNESS-NO-FIXTURE, not an empty successful observation. Fixture
results are fixed observations, not fresh execution of an external detector.
They must correspond to the cases the experiment actually requests.

## RuleLogicHarness

Scenario `harness.kind: rule_logic` declares 1..32 rules with unique IDs. Each
rule requires detector, signature, title, and 1..16 conditions. All conditions
must hold for a telemetry event to be a candidate.

Fields: category, action, protocol, severity, sensor, vendor, labels, tags,
correlation_id, timestamp_text (original spelling), or a bounded `raw.key...`
path through JSON objects. Paths never traverse Python attributes, index arrays,
evaluate code, or call functions. Raw fields support intentionally fragile local
examples; robust rules should generally rely on normalized semantics.

Operators: `eq` is type-sensitive equality, `contains` is case-sensitive string
substring or collection membership, `gte` is numeric comparison excluding
booleans, and `exists` means non-null (an empty string still exists). Missing
fields fail comparisons. There is no regex or arbitrary expression language.

Count bounds are min_count (default 1), optional max_count and max_total_events.
Optional require_time_order checks candidate input order; window_ms bounds the
span of candidate event times. All counts/durations are finite and bounded by
the model. Conditions, count, order, then window determine the rule trace.
Reason codes: RULE_MATCH, RULE_CONDITION_MISS, RULE_COUNT_MISS, RULE_ORDER_MISS,
RULE_WINDOW_MISS. A count trace is evidence, not a probability.

A match emits one aggregate detection with sorted related event IDs. Its time
is the latest candidate time plus bounded delay_ms. Output severity defaults to
4; labels/tags are explicit rule values. A shared correlation ID is carried
only if every candidate has the same value. IDs derive from case/rule/event IDs.
Rules execute in stable rule-ID order. No wall clock is used. Invalid timestamp
overflow or output validation produces unknown; policy applies to outputs too.

## Verification and limitations

`uv run pytest tests/test_harness.py` executes real rules and local fixture reads,
covering hits, measured misses, unknowns, malformed/duplicate data, typed
operators, safety, unsupported operations, ordering, windows, and determinism.
The foundation scenario selects a simple category rule. This harness does not
implement Sigma, Suricata rules, production correlation, detection fidelity,
or real SIEM/NDR/IDS execution. Its bounded rules are controlled examples for
testing the resilience engine; findings apply to these declared fixture models.
