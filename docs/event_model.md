# Canonical event model

`models.py` defines DVI-native Pydantic boundaries. These values carry normalized
telemetry, source evidence, and local detections. They perform no I/O and do not
imply that an input is safe to run; scenario policy is a separate responsibility.

## Fields and contracts

`TelemetryEvent` requires a stable caller-supplied `event_id`, timezone-aware
`timestamp`, `semantics`, and `raw` source snapshot. `schema_version` is `1`.
IDs are limited to 128 word, dot, colon, slash, or hyphen characters. Unknown
fields fail validation so misspellings cannot silently change meaning.

`timestamp` is the event time; optional `observed_at` is observation time. Both
normalize to UTC. Text must use RFC3339 with timezone and up to six fractional
digits. Epoch numbers, naive timestamps, invalid calendar dates, and excess
precision are rejected instead of guessed or silently truncated. Original
timestamp spelling can be retained in `raw.original_timestamp`.

`EventSemantics` contains category (flow, DNS, HTTP, alert), required action,
outcome (unknown by default), optional transport protocol, source/destination
endpoints, and light DNS/HTTP metadata. `NetworkEndpoint` uses validated IPv4/IPv6
addresses and optional integer ports in 0..65535. No DNS lookups occur. Scoped
IPv6 addresses are unsupported. This layer validates syntax, not allowed networks.

Severity uses DVI's own scale: unknown=0, informational=1, low=2, medium=3,
high=4, critical=5. Unknown is not a claim of low risk. Source adapters must map
vendor scales explicitly. Optional `confidence` is source-provided evidence
metadata in 0..1, never a matching decision or inferred probability.

`labels` and `tags` are sorted unique tuples, case-sensitive at this boundary.
`correlation_id` is optional; absence must not be replaced by a guessed identity.
`entities` carries typed host/sensor/service/flow references. `evidence` contains
paths and descriptions. `warnings` contains stable code, path, and explanation.
Ordered evidence, entities, and warnings retain source order.

`DetectionEvent` additionally requires detector identity, signature, and title;
its semantics category must be alert. Related event IDs and technique strings
are optional sorted unique tuples. Technique labels do not assert ATT&CK coverage.

## Evidence and digests

`RawSource` records adapter identity, optional one-based record index, original
timestamp, sensor/vendor, canonical JSON payload text, and verified SHA-256 digest.
`from_payload` snapshots a parsed JSON object; `payload` returns a fresh dictionary.
Neither caller mutation nor mutation of the returned dictionary changes evidence.
All stored model collections are tuples or strings. Pydantic models are frozen.
Use validation when reconstructing values; Pydantic's unchecked `model_copy` and
`model_construct` are not input-validation APIs.

Canonical serialization sorts object keys, retains array order, uses compact
ASCII-escaped JSON, and rejects non-finite numbers. This is a documented DVI
contract, not RFC 8785. Raw digest measures parsed payload content, not the
original file bytes or whitespace. Whole-file provenance belongs to run artifacts.
`stable_digest()` hashes all model fields, including provenance; semantic
equivalence should compare declared semantics, not whole-event digests.

## Design influences and limitations

Separating event and observation time follows the
[OpenTelemetry log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/).
Explicit network endpoints follow the organizational idea of
[ECS source fields](https://www.elastic.co/docs/reference/ecs/ecs-source).
DVI implements neither OTLP nor ECS export/compliance. Its severity scale and
microsecond datetime representation are DVI-specific; it does not preserve
nanosecond precision. There is no unbounded arbitrary attribute bag in normalized
semantics; unsupported source fields remain in the raw snapshot.

Verify with `uv run pytest tests/test_models.py`. Tests cover rejected input,
UTC normalization, immutable raw snapshots, digest integrity, key-order
invariance, endpoint ranges, sorted references, and JSON round-trips.
