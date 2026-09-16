# Detection intent and semantic loss

V2-04 parses a finite local declaration and checks whether supplied canonical
telemetry contains the declared evidence. The result describes evidence support
for one event at a time; it does not execute a detector, compile Sigma, or claim
that a multi-event rule fired.

The typed contract is `DetectionIntent` with field requirements, literal
operators (`eq`, `contains`, `gte`, `exists`), source metadata, input or output
severity scope, evidence references, correlation and time-window expectations,
and explicit assumptions. Values are canonical JSON snapshots. Field paths are
inert selectors resolved through the existing ontology binding and alias rules;
conflicting aliases remain ambiguous.

Native declarations use `condition_shape: all` and a finite `fields` array. Each
field names one or more explicit paths such as `semantics.category` and carries
one or more operator records. An equality value for DNS is written as the
canonical snapshot `value_json: '"dns"'`; a substring value is written as
`value_json: '"example"'`. No regex, expression, query or dynamic selector is
accepted or evaluated.

The optional Sigma-style adapter accepts explicit `taxonomy: dvi`, one flat
selection dictionary and a condition naming that selection. Scalar values and a
single `contains` or `exists` modifier are supported. Lists, boolean condition
expressions, wildcards, multiple modifiers and unknown logsource mappings are
retained as unknown diagnostics. A Sigma `level` is output/detection severity;
it is never compared with ordinary input-event severity. V1 `LocalRule` metadata
is converted to the same contract, while count, ordering, delay and window
constraints remain pending assumptions for the later sequence engine.

Analysis distinguishes a known mismatch from unavailable evidence. It records
missing required fields, optional absence, unsupported operators/shapes,
logsource and severity mismatches, alias ambiguity, normalization loss,
correlation-key absence, unrepresentable timestamp precision, dropped metadata
and dropped technique tags. A pending assumption keeps the overall result
unknown, even if a field comparison happens to match. With no global unknowns,
support is existential across supplied events: one supported candidate can
support the declaration, while an all-contradicted set is contradicted.

`intent_artifacts(parsed, events)` revalidates both arguments and emits four
canonical files:

- `detection_intent.json` — parsed declaration and source digest;
- `semantic_loss_report.json` — actual candidate bindings, expected/observed
  values, checks and overall state;
- `unsupported_conditions.json` — unsupported parser/analyzer conditions;
- `intent_assumptions.json` — retained pending and informational assumptions.

The artifact function has no filesystem, network, subprocess or expression
execution capability. Inputs are limited to 128 KiB for a declaration, 128
events and 2 MiB of combined canonical telemetry; generated files are bounded
to 32 MiB. Evidence paths associate a fixture record with a declaration but do
not authenticate its source. Timestamp checks establish representation and
retained precision only; cross-event windows, sequence order and same-value
correlation are V2-05 behavior.

Run the executable proof with a new output directory:

```powershell
.venv\Scripts\python.exe examples/detection_intent.py --out runs/v2/intent-proof
```

The implementation is in [intent_models.py](../src/dvi_sentinel/intent_models.py),
[intent_parsing.py](../src/dvi_sentinel/intent_parsing.py) and
[detection_intent.py](../src/dvi_sentinel/detection_intent.py), with behavioral
coverage in [test_v2_intent.py](../tests/test_v2_intent.py).
