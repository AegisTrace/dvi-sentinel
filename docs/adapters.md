# Defensive telemetry adapters

`normalize(content: bytes, adapter: str)` is a pure fixture parser.
`load_input(root, FixtureInput)` adds bounded, policy-checked local file access.
Supported adapters are `jsonl`, `csv`, `suricata_eve`. No network access, live
capture, packet generation, or external detector invocation occurs.

`NormalizationResult` records adapter identity, SHA-256 of original bytes,
normalized events, and structured errors (code, record index, path, explanation).
`parser_success` is true only for a nonempty result with no errors. Successful
records in a partial failure remain inspectable but must not imply a successful
experiment. JSONL indices are physical lines; CSV indices are record numbers,
counting the header as record 1, not physical lines within quoted cells.
JSONL accepts LF or CRLF record terminators. Unicode line/paragraph characters
inside JSON strings remain part of the string; they do not create records.

## Generic JSONL and CSV mapping

Flat records require timestamp and category. CSV uses a unique header row,
strict CSV quoting, and exactly matching row widths. Integer strings are parsed
explicitly. CSV labels/tags cells contain JSON string arrays; blank cells mean
absent. Generic JSONL uses actual arrays. JSON duplicate keys are rejected.

| Source field(s) | Canonical field / behavior |
|---|---|
| timestamp, @timestamp | UTC timestamp; retain original spelling |
| category, event_type | flow, dns, http, alert |
| action / outcome | observed / unknown if absent |
| protocol, proto | Lowercase tcp/udp/icmp/other; unknown names rejected |
| src_ip, source_ip | Source address |
| dst_ip, dest_ip, destination_ip | Destination address |
| src_port, source_port / dst_port, dest_port, destination_port | Optional ports; require address |
| severity | DVI integer 0..5 or unknown/informational/low/medium/high/critical, case-insensitive |
| dns_name | Lowercase question name with trailing dot removed |
| http_method / http_path | Uppercase method / inert resource path |
| correlation_id | Optional text; never guessed |
| labels / tags | Sorted, unique strings |
| sensor, sensor_name / vendor | Retained source metadata |
| event_id | Explicit ID; otherwise raw digest prefix plus record index |

If multiple aliases are present, differing values produce
DVI-ADAPTER-ALIAS-CONFLICT. This check precedes normalization; redundant aliases
should use exactly equal values. A port without an address fails. DNS records
require a question name; HTTP records require a method. Severity absence produces
unknown with DVI-ADAPTER-SEVERITY-MISSING; invalid severity is an error.

JSONL also accepts serialized canonical TelemetryEvent objects. Their existing
raw snapshots are validated and safety-checked before the entire input record is
captured as the new adapter evidence. This is telemetry ingestion, not loading
DetectionEvent result fixtures; those use FixtureHarness.

## Synthetic Suricata EVE subset

The mapping follows field shapes described in the
[Suricata EVE documentation](https://docs.suricata.io/en/suricata-8.0.4/output/eve/eve-json-format.html).
DVI supports synthetic alert, flow, DNS, and HTTP-like records only. event_type
selects category; src_ip/src_port and dest_ip/dest_port define endpoints; proto
defines transport; flow_id becomes a text correlation ID. Original raw fields
are retained, including fields outside this narrow normalized projection.

`alert.severity` 1/2/3 maps to DVI high/medium/low (4/3/2).
`alert.action` maps action; absent action defaults to observed. DNS supports
`dns.rrname` or exactly one `dns.queries[].rrname`; conflicting/multiple questions
fail rather than silently dropping semantics. HTTP maps http_method and url.
Relative HTTP resource paths are inert and allowed; protocol-relative external
URLs are rejected. Offset timestamps such as +0000 are converted to +00:00 with
DVI-ADAPTER-TIMEZONE warning; precision beyond microseconds remains unsupported.

Synthetic fixture extensions `dvi_event_id`, `dvi_labels`, `dvi_tags`, `dvi_action`,
and `dvi_outcome` carry explicit DVI semantics. They are not claims about standard
Suricata fields. Sensor aliases and vendor are optional fixture metadata.

## Integrity, safety, and limitations

Every event includes immutable raw content, its canonical-content digest, adapter
identity, and record index. CSV raw payload retains string cells exactly as
parsed; quoting and line-ending bytes belong to the whole-input digest. Original
record order is preserved. Explicit duplicate event IDs fail; implicit IDs differ
by record index. Blank records are ignored. UTF-8 BOM is accepted. Files are
limited to 2 MiB and 10,000 records (JSONL includes blank lines in its limit).

Policy runs before and after normalization. Unsupported/malformed records return
errors with DVI-ADAPTER codes; policy errors also retain the DVI-POL code. Unknown
source fields remain raw and are not automatically interpreted as semantics.
Packet/byte counts, arbitrary vendor attributes, alert signature interpretation,
and complex DNS answer sets are outside the normalized subset. Full Suricata
compatibility, Zeek, OCSF/ECS export, and real captures are not implemented.

Verify with `uv run pytest tests/test_adapters.py`. Committed fixtures in
`examples/telemetry/` encode equivalent flow/DNS/HTTP/alert semantics across all
three adapters; tests prove agreement in endpoints, event time, severity, labels,
and correlation IDs while retaining distinct original representations. Other
tests cover alias conflict, malformed CSV/JSON, partial failure, unsafe content,
generated IDs, invalid domains/ports, and canonical raw-payload safety.
