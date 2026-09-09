# Cross-schema differential testing

`run_differential(events, harness)` starts from one canonical event sequence,
encodes canonical JSONL, flat CSV, and synthetic EVE independently, normalizes
through the actual adapters, and compares every normalized field plus local
detector/signature observations. `examples/compare_schemas.py` produces real
`differential_schema_report.json` artifacts for robust and fragile local rules.

Each case embeds source text, SHA-256 source digest in the normalization result,
normalized events with raw provenance, parser diagnostics, detector observations,
and typed field differences with expected/observed values. JSON Pointer evidence
paths are relative to the case object; the report retains the original sequence
and baseline observation. The output is deterministic and versioned.

## Meaning and classification

Normalized timestamps compare exact UTC instants, severities compare DVI levels,
and labels/tags compare their normalized sorted values. Source spelling, original
raw JSON, source record indices, and adapter warnings are provenance rather than
semantic differences. Optional fields, sensor/vendor, and correlation remain in
the comparison. Explicit event IDs align records; missing IDs are not guessed
from position. Sequence order must also survive this encoding operation.

| Difference | Finding class |
| --- | --- |
| Unsupported normalized value changes | adapter_disagreement |
| Equal normalized meaning, different observed identities | schema_fragility |
| Missing event or mapped semantic field | field_mapping_loss |
| Changed timestamp/observation instant | timestamp_precision_drift |
| Changed normalized severity | severity_normalization_drift |
| Changed or absent optional metadata | optional_field_loss |
| Changed or absent correlation identifier | correlation_key_loss |

An input with a known normalized difference never gets a schema-fragility claim:
its detector result is confounded by changed input meaning. A complete mapping
disagreement can still be reported when detector observations are unknown. When
semantics agree, unavailable, empty baseline, or repeated ambiguous detection
identities make the detector comparison unknown. Complete empty candidate
observations against a nonempty baseline are a measured schema disagreement.
Additional detector identities also count as disagreement. The comparison does
not yet inspect expected title/evidence/latency semantics; that matcher is Phase 8.

## Supported encodings and limits

The encoders create local differential fixtures, not full standards exports.
Canonical JSONL retains all canonical fields. CSV and EVE use the mappings in
`adapters.md`; rich observed_at/confidence/entities/evidence values unsupported by
those adapters cause explicit encoding-unknown results instead of data loss.
EVE can retain severities 2/3/4 for alerts and 0 for other supported categories.
Category-specific fields must fit their category. Explicit `dvi_*` fixture fields
retain identity, action/outcome, and labels/tags in the synthetic EVE subset.

Callers may supply 1–3 distinct `FixtureRepresentation` objects to examine
independently prepared fixtures. The canonical sequence is the declared reference;
DVI measures disagreement, not whether an external fixture author intended it.
Every supplied record must pass parsing and policy. Partial parses remain unknown
and do not reach the harness. Inputs are bounded at 10,000 unique events, sources
at 2 MiB through the adapter, and representations at three. Baseline and candidate
data pass the existing safety policy. No files, processes, or network are accessed
by the engine or encoders.

## Executable proof

Run `uv run python examples/compare_schemas.py`. The robust normalized category
rule agrees in all three representations. The deliberately raw-field-dependent
rule agrees on CSV but disagrees on canonical JSONL and EVE, despite equivalent
normalized semantics. Reports are written beneath `runs/differential-proof/`.

`tests/test_differential.py` verifies each finding class with actual re-parsed
fixtures, source-format-only suppression, field coverage/order, ambiguous or
missing observations, malformed partial inputs, safety rejection, unsupported
encodings, deterministic evidence, and a Hypothesis matrix of exact fractional
timestamps and all supported EVE alert severities. This does not imply Zeek,
OCSF/ECS, or OpenTelemetry export support.
