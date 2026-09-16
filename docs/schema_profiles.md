# Loss-aware schema profiles

The V2 development library projects local canonical fixtures into seven declared
subsets and measures what survives normalization. Profile revision `1` records exact
field paths, aliases, conversion rules and local extensions. These projections do
not claim complete standards conformance, live ingestion or vendor integration.

## Supported subsets and primary references

| Profile ID | Implemented mapping | Deliberate boundary |
| --- | --- | --- |
| `dvi` | Complete canonical `TelemetryEvent` or `DetectionEvent`, including raw evidence, warnings and subtype fields. | DVI event schema `1`; canonical input remains strict. |
| `ocsf_like` | `metadata.uid`, millisecond `time`, `activity_name`, `severity_id`, source/destination endpoint IP/port and connection protocol name. | Category, outcome, DNS/HTTP resource and correlation fields use named `unmapped.dvi_*` extensions. No OCSF class/category/type identifiers or full required metadata. |
| `ecs_like` | `event.id`, `@timestamp`, `event.created`, `event.action`, `event.outcome`, `event.severity`, endpoint IP/port, `network.transport`, DNS question, HTTP method, URL path and tags. | DVI category/correlation use `dvi.*` extensions; no full ECS categorization or Elasticsearch mapping. |
| `otel_like` | Integer nanosecond `Timestamp`/`ObservedTimestamp`; selected canonical identity, semantics, security severity and correlation under `Attributes["dvi.<field>"]`. | An in-memory Logs Data Model subset, not OTLP JSON/protobuf. DVI security severity does not populate native log severity. |
| `suricata_eve` | Existing V1 flow/alert/DNS/HTTP encoder and adapter: time, endpoints, transport, flow ID, selected resource fields and alert severity. | Explicit `dvi_event_id`, `dvi_action`, `dvi_outcome`, label/tag extensions; legacy `dns.rrname` subset. No complete EVE record or modern DNS-array projection. |
| `zeek_like` | `ts`, literal dotted endpoint keys, `proto` and connection `uid` from canonical correlation ID. | Exact decimal-text seconds plus a small `dvi` identity/category/action/outcome object. No native TSV writer, full connection record, DNS/HTTP log or inferred connection state. |
| `sigma_metadata` | Canonical severity 1-5 to metadata `level`, plus tags. | No rule condition, rule identity, event time/action, inferred logsource or compiler. Event reconstruction is explicitly unavailable. |

The OCSF subset uses the [1.6.0 dictionary](https://github.com/ocsf/ocsf-schema/blob/1.6.0/dictionary.json),
[metadata object](https://github.com/ocsf/ocsf-schema/blob/1.6.0/objects/metadata.json)
and [connection fields](https://github.com/ocsf/ocsf-schema/blob/1.6.0/objects/network_connection_info.json).
OCSF defines milliseconds since the epoch and named event-severity values; this local
subset retains values 0-5 and reports unsupported values rather than guessing them.

ECS field names follow [9.1.0 event fields](https://github.com/elastic/ecs/blob/v9.1.0/schemas/event.yml),
[network fields](https://github.com/elastic/ecs/blob/v9.1.0/schemas/network.yml) and
[DNS fields](https://github.com/elastic/ecs/blob/v9.1.0/schemas/dns.yml).
`event.severity` preserves DVI's source scale, rather than assuming a universal ECS
severity scale. The exported profile definition identifies every local extension.

The [OpenTelemetry 1.55.0 Logs Data Model](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.55.0/specification/logs/data-model.md)
distinguishes event time from observed time and defines log severity with error/fatal
meaning. A security priority alone cannot establish those log meanings. Therefore
DVI security severity stays in `Attributes["dvi.severity"]`; an incoming native
`SeverityNumber` is unsupported in this local profile and yields an unknown result.

The [Suricata 8.0.3 EVE reference](https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-format.html)
describes the relevant endpoint, HTTP and alert fields. Its default DNS format uses
version 3; this profile deliberately retains the V1 adapter's legacy single-question
projection. Other DNS structures are reported as outside this profile's subset.
The V1 adapter itself retains its existing separately documented input support.

The Zeek field reference is the [7.0.10 connection record](https://github.com/zeek/zeek/blob/v7.0.10/scripts/base/protocols/conn/main.zeek).
Its connection identifier is distinct from canonical event identity. This local
profile uses decimal text to avoid a binary floating-point export step; it does not
claim that this representation is a native Zeek JSON record.

[Sigma 2.1.0](https://github.com/SigmaHQ/sigma-specification/blob/v2.1.0/specification/sigma-rules-specification.md)
describes detection rules and their metadata. A metadata-only projection cannot
identify an observed event. Normalization returns the mapped metadata traces,
missing event fields and `event = null`, with an unknown decision. No event fields
are fabricated to complete a roundtrip.

## Library API and field evidence

```python
from dvi_sentinel.schema_mapping import project_profile, normalize_profile, roundtrip_profile

projection = project_profile(event, "ecs_like")
normalized = normalize_profile(projection.payload_json, "ecs_like")
report = roundtrip_profile(event, "ecs_like")
```

`event` is a validated local fixture using the existing event-model boundary.
`normalize_profile` accepts a JSON string or bytes. Malformed JSON, duplicate keys,
size/depth violations and policy rejection raise errors. Well-formed unsupported
content or missing/invalid mapped values produces an explained unknown result.
It does not infer event identity or action from vendor fields outside the mapping.

`schema_profile(profile_id)` returns the immutable definition. Each field declares
its canonical name, primary path, accepted aliases, finite codec and extension flag.
Paths are arrays of literal dictionary keys; `("id.orig_h",)` is different from
`("id", "orig_h")`. No path evaluates an expression, wildcard or array traversal.
Callers select a built-in profile, rather than supplying executable mapping behavior.

Projection and normalization retain per-field source/target JSON and states `mapped`,
`unmapped`, `lossy` or `unknown`. Normalization traces record the actual canonical
values, including V1 EVE casing normalization. Unsupported input fields remain issues;
available events receive mapping warnings so downstream ontology extraction cannot
silently treat unresolved conversion as known evidence.

Present aliases must agree as canonical JSON before conversion. Equal aliases retain
all contributing paths; conflicting aliases yield `alias_ambiguity` and prevent
event reconstruction. Even two timestamp strings denoting the same instant can be
ambiguous representations. Explicit null values do not count as populated aliases.
All alias candidates receive fixture-policy checks before a value is selected.

## Time, severity and roundtrip decisions

Millisecond/nanosecond conversion uses integer arithmetic. OCSF projection truncates
sub-millisecond values with `timestamp_precision_loss`. OpenTelemetry timestamps must
fit unsigned 64-bit nanoseconds. Incoming finer-than-microsecond values retain the
representable part and report loss/unknown. Zeek-like seconds accept bounded plain
decimal text or JSON numbers; exponent notation is unsupported. Binary numeric input
cannot recover precision already lost before parsing. RFC3339 requires explicit time
zones and at most six fractional digits, following the canonical timestamp contract.

These checks measure representable timestamp values, not clock accuracy or the
original sensor's measurement resolution. Normalized raw timestamp text describes
the profile representation; original source metadata remains in the roundtrip report.

EVE severity maps DVI low/medium/high to 3/2/1. Critical also projects to 1 and returns
as high, producing `severity_mapping_drift`. Unknown/informational alert severity has
no declared EVE entry; the profile omits that field and normalization remains unknown.
ECS/OCSF preserve supported DVI numeric values. Sigma maps 1-5 to its five named levels.
Unrecognized severity values are reported without coercion into a valid known level.

`decision` answers whether the complete supported canonical field inventory survived:

- `lossless`: known evidence, no mapped/unmapped value loss, and equivalent meaning.
- `lossy`: a known roundtrip with measured field loss, including dropped optional
  metadata or added normalization warnings.
- `unknown`: reconstruction or supporting evidence is incomplete/ambiguous, or
  normalization contains unresolved warnings or loss. Actual loss traces remain visible.

`semantic_decision` separately uses [ontology equivalence](semantic_ontology.md).
A timestamp value change can be lossy while default meaning stays equivalent, because
absolute event time is not part of the default semantic identity. This is why semantic
equivalence alone is insufficient to claim a lossless roundtrip.

Raw adapter, payload/hash, record index and source timestamp text are provenance,
reported through `provenance_changed`, rather than counted as semantic field loss.
The source event stays in the report. DVI preserves it exactly; other profiles capture
the newly normalized payload as raw evidence. No hidden original-event copy is placed
inside a vendor extension to create an artificial lossless result.

## Runnable proof and artifacts

```sh
python examples/schema_profiles.py --out runs/v2/profile-proof
```

Use a new local directory. The [example](../examples/schema_profiles.py) projects a
synthetic flow timestamp ending in `.123456`. Its measured results are:

| Profile | Roundtrip | Reason where not lossless |
| --- | --- | --- |
| DVI, ECS-like, OpenTelemetry-like, Zeek-like | lossless | Supported fixture fields survive. |
| OCSF-like | lossy | Milliseconds cannot retain the final 456 microseconds. |
| Suricata EVE | lossy | V1 records a warning for absent optional flow severity; meaning remains equivalent. |
| Sigma metadata | unknown | Required event evidence is unavailable. |

`mapping_artifacts(events)` evaluates all seven profiles from actual input events:

- `schema_profiles/<profile>.json`: seven revisioned definitions and references.
- `mapping_report.json`: source, projection, normalized evidence, field traces and issues.
- `lossy_fields.json`: issues per source/profile, including unknown and provenance reasons.
- `field_alias_graph.json`: primary/alias edges to canonical fields, without inferred edges.
- `roundtrip_report.json`: decisions, source/payload/destination digests and provenance flags.

Serialization is deterministic in event-ID/profile order. The export API accepts source
events and evaluates them afresh; it does not serialize caller-supplied result claims.
Typed result validation checks shape/references, not authenticity of original source
assertions. Standalone outputs are not verified V1 run bundles or V2 provenance DAGs.

## Bounds and verification

Analysis is pure and requires no new dependency or network access. Payloads are at most
2 MiB, object depth is at most 16 and at most 256 leaf fields are accepted. Artifact
evaluation accepts 1-32 unique events and at most 2 MiB combined canonical input;
each serialized artifact is bounded at 32 MiB. The example writes eleven fixed names
beneath a new directory, rejecting network paths, symlink/junction ancestors and
existing destinations.

[Mapping tests](../tests/test_v2_mapping.py) cover all profiles, lossless controls,
application resources, timestamp arithmetic, severity drift, incomplete metadata,
alias conflicts, policy checks, bounds, subtype retention, deterministic artifacts
and the executed example. Full standards, production telemetry, intent compilation
and combined CLI integration remain outside this card.
