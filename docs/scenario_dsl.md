# Scenario DSL

The V1 boundary is a single UTF-8 YAML object. `scenario.py` defines the contract;
`scenario_io.py` parses it and validates safety. Unknown fields are errors.
Use `load_scenario(Path(...))` to validate a scenario and verify fixture paths.
It returns the typed scenario and allow/warn policy decisions, or `PolicyError`
with explicit rejection evidence. It does not execute a detector.

`examples/foundation_scenario.yaml` is a working validation example:

```sh
uv run python -c "from pathlib import Path; from dvi_sentinel.scenario_io import load_scenario; s, p = load_scenario(Path('examples/foundation_scenario.yaml')); print(s.metadata.id); print([d.rule_id for d in p])"
```

## Fields

| Field | Contract |
|---|---|
| schema_version | Literal string `1`; default `1` |
| metadata | Required id, title, description |
| inputs | 1..16 entries: relative path, format, provenance |
| expected | Required detector; optional signature/title containment and evidence constraints |
| harness | Required `rule_logic` rules or `fixture` result-file path |
| variations | Allowed families and finite bounds; defaults to baseline-only |
| scoring | Minimum detection rate (1.0), maximum unknown rate (0.0), both in 0..1 |
| reporting | Plain report title; no template paths or executable expressions |
| safety | All three booleans explicitly true: local_only, synthetic_only, no_execution |

Input formats are `jsonl`, `csv`, and `suricata_eve`. Provenance is `synthetic`
or `documentation`. Paths resolve beneath the scenario directory. Input fixture
parsing belongs to adapters. Local detector evaluation is defined by the
[harness contract](detector_harness.md); no external detector is launched.

Expected fields: detector identity, signature, title_contains, min_severity
(DVI integer 0..5), labels, tags, techniques, event_ids, correlation_id,
reference_time (quoted RFC3339), max_delay_ms (0..86,400,000; default 60,000), and
required_fields. The latter accepts signature, title, severity, labels,
correlation_id, related_event_ids; default is signature. An omitted constraint
adds no assertion. Matcher decision rules belong to the matching subsystem.

Variation families are timing, ordering, metadata, noise, volume, dropout.
Bounds: max_variants 1..1000 (default 32), max_jitter_ms 0..60,000,
max_noise_events 0..1000, max_duplicates 0..100. The last three default to zero.
Ordering requires `order_independent: true`. Optional non-critical fields may
be sensor, vendor, labels, tags, correlation_id, confidence. Required matching
evidence cannot also be declared droppable. Repeated policy entries fail.
These are validated permissions, not a claim that variations already execute.

## Parsing and failure behavior

Integers reject booleans and strings; declaration booleans reject `1` and
`"true"`. Pydantic errors retain field paths. Duplicate YAML keys, aliases,
anchors, non-string keys, unsafe tags, invalid UTF-8, and excessive nesting are
rejected. Maximum scenario size is 128 KiB and maximum fixture size is 2 MiB.
Quoted timestamps avoid YAML implicit date conversion. Config is canonicalized
through model serialization for deterministic comparison.

Run `uv run pytest tests/test_policy.py` to exercise accepted examples, negative
policy cases, malformed YAML, resource bounds, documentation addresses, and
post-transformation event inspection. See [safety model](safety_model.md) for
the precise boundary and limitations.
