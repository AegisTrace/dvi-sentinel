# ADR 0004: DVI-native canonical events

Status: accepted; implemented in event models, adapters and differential testing.

Raw-only matching would duplicate source interpretation in every engine.
Normalization without source retention would hide representation dependencies.
Claiming a complete external schema would exceed the tested V1 scope.

Decision: use typed DVI-native normalized events alongside immutable raw JSON
snapshots and separately captured original fixture bytes. Normalize timestamps
to UTC at microsecond precision, map source severity explicitly, and reject
unsupported ambiguity. Compare protected semantic projections independently.

Consequence: models are small enough to test, source evidence remains inspectable,
and representation loss is visible. Storage/validation work is duplicated, and
full OCSF/ECS/OTLP/EVE compatibility is not claimed. See [event model](../event_model.md)
and [research sources](../research_sources.md).
