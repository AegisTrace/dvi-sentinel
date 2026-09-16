"""Versioned local subsets: explicit mappings, extensions and finite codec choices."""

from dvi_sentinel.mapping_models import Codec, FieldProjection, ProfileId, SchemaProfile

PROFILE_IDS: tuple[ProfileId, ...] = (
    "dvi",
    "ocsf_like",
    "ecs_like",
    "otel_like",
    "suricata_eve",
    "zeek_like",
    "sigma_metadata",
)


def _field(
    name: str,
    path: str,
    codec: Codec = "identity",
    *,
    extension: bool = False,
    aliases: tuple[str, ...] = (),
) -> FieldProjection:
    # Slash separates object keys; dots inside a key are literal (Zeek/OTel attributes).
    return FieldProjection(
        canonical_field=name,
        path=tuple(path.split("/")),
        codec=codec,
        extension=extension,
        aliases=tuple(tuple(item.split("/")) for item in aliases),
    )


def schema_profile(profile_id: ProfileId) -> SchemaProfile:
    """Return a fresh immutable built-in definition; input never supplies executable mappings."""
    fields: list[FieldProjection] = []
    if profile_id == "dvi":
        reference = "https://github.com/AegisTrace/dvi-sentinel/blob/main/docs/event_model.md"
        version = "DVI event schema 1"
        fields = [
            _field(name, name)
            for name in (
                "schema_version",
                "event_id",
                "timestamp",
                "observed_at",
                "semantics",
                "raw",
                "severity",
                "confidence",
                "labels",
                "tags",
                "correlation_id",
                "entities",
                "evidence",
                "warnings",
                "detector",
                "signature",
                "title",
                "related_event_ids",
                "techniques",
            )
        ]
    elif profile_id == "ocsf_like":
        reference = "https://github.com/ocsf/ocsf-schema/blob/1.6.0/dictionary.json"
        version = "OCSF 1.6.0 field subset"
        fields = [
            _field("event_id", "metadata/uid"),
            _field("timestamp", "time", "epoch_ms"),
            _field("semantics.action", "activity_name"),
            _field("severity", "severity_id"),
            _field("semantics.source.address", "src_endpoint/ip"),
            _field("semantics.source.port", "src_endpoint/port"),
            _field("semantics.destination.address", "dst_endpoint/ip"),
            _field("semantics.destination.port", "dst_endpoint/port"),
            _field("semantics.protocol", "connection_info/protocol_name"),
        ]
        fields += [
            _field(name, "unmapped/dvi_" + name.removeprefix("semantics."), extension=True)
            for name in (
                "semantics.category",
                "semantics.outcome",
                "semantics.dns_name",
                "semantics.http_method",
                "semantics.http_path",
                "correlation_id",
            )
        ]
    elif profile_id == "ecs_like":
        reference = "https://github.com/elastic/ecs/tree/v9.1.0/schemas"
        version = "ECS 9.1.0 field subset"
        fields = [
            _field("event_id", "event/id"),
            _field("timestamp", "@timestamp", "rfc3339", aliases=("timestamp",)),
            _field("observed_at", "event/created", "rfc3339"),
            _field("semantics.category", "dvi/category", extension=True),
            _field("semantics.action", "event/action"),
            _field("semantics.outcome", "event/outcome"),
            _field("severity", "event/severity"),
            _field("tags", "tags"),
            _field("semantics.source.address", "source/ip", aliases=("source_ip",)),
            _field("semantics.source.port", "source/port"),
            _field("semantics.destination.address", "destination/ip", aliases=("destination_ip",)),
            _field("semantics.destination.port", "destination/port"),
            _field("semantics.protocol", "network/transport"),
            _field("semantics.dns_name", "dns/question/name"),
            _field("semantics.http_method", "http/request/method"),
            _field("semantics.http_path", "url/path"),
            _field("correlation_id", "dvi/correlation_id", extension=True),
        ]
    elif profile_id == "otel_like":
        reference = "https://github.com/open-telemetry/opentelemetry-specification/blob/v1.55.0/specification/logs/data-model.md"
        version = "OpenTelemetry 1.55.0 Logs Data Model subset"
        fields = [
            _field("timestamp", "Timestamp", "epoch_ns"),
            _field("observed_at", "ObservedTimestamp", "epoch_ns"),
        ]
        fields += [
            _field(name, "Attributes/dvi." + name, extension=True)
            for name in (
                "event_id",
                "semantics.category",
                "semantics.action",
                "semantics.outcome",
                "semantics.protocol",
                "semantics.source.address",
                "semantics.source.port",
                "semantics.destination.address",
                "semantics.destination.port",
                "semantics.dns_name",
                "semantics.http_method",
                "semantics.http_path",
                "severity",
                "correlation_id",
            )
        ]
    elif profile_id == "suricata_eve":
        reference = "https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-format.html"
        version = "Suricata 8.0.3 EVE, legacy single-question DNS subset"
        fields = [
            _field("event_id", "dvi_event_id", extension=True),
            _field("timestamp", "timestamp", "rfc3339"),
            _field("semantics.category", "event_type"),
            _field("semantics.action", "dvi_action", extension=True, aliases=("alert/action",)),
            _field("semantics.outcome", "dvi_outcome", extension=True),
            _field("semantics.protocol", "proto"),
            _field("semantics.source.address", "src_ip"),
            _field("semantics.source.port", "src_port"),
            _field("semantics.destination.address", "dest_ip"),
            _field("semantics.destination.port", "dest_port"),
            _field("semantics.dns_name", "dns/rrname"),
            _field("semantics.http_method", "http/http_method"),
            _field("semantics.http_path", "http/url"),
            _field("severity", "alert/severity", "eve_severity"),
            _field("correlation_id", "flow_id"),
            _field("labels", "dvi_labels", extension=True),
            _field("tags", "dvi_tags", extension=True),
            _field("raw.sensor", "sensor", aliases=("sensor_name",)),
            _field("raw.vendor", "vendor"),
        ]
    elif profile_id == "zeek_like":
        reference = (
            "https://github.com/zeek/zeek/blob/v7.0.10/scripts/base/protocols/conn/main.zeek"
        )
        version = "Zeek 7.0.10 connection fields with decimal-text time"
        fields = [
            _field("timestamp", "ts", "epoch_seconds"),
            _field("semantics.source.address", "id.orig_h"),
            _field("semantics.source.port", "id.orig_p"),
            _field("semantics.destination.address", "id.resp_h"),
            _field("semantics.destination.port", "id.resp_p"),
            _field("semantics.protocol", "proto"),
            _field("correlation_id", "uid"),
        ]
        fields += [
            _field(name, "dvi/" + name.removeprefix("semantics."), extension=True)
            for name in ("event_id", "semantics.category", "semantics.action", "semantics.outcome")
        ]
    elif profile_id == "sigma_metadata":
        reference = "https://github.com/SigmaHQ/sigma-specification/blob/v2.1.0/specification/sigma-rules-specification.md"
        version = "Sigma specification 2.1.0 metadata subset"
        fields = [_field("severity", "level", "sigma_level"), _field("tags", "tags")]
    else:
        raise ValueError("DVI-MAPPING-PROFILE: unsupported profile")
    return SchemaProfile(
        profile_id=profile_id,
        reference_version=version,
        reference_url=reference,
        scope=(
            "Metadata projection only; no detection condition, event reconstruction or compiler."
            if profile_id == "sigma_metadata"
            else "Local field subset with explicit extensions; no complete standard compliance."
        ),
        fields=tuple(fields),
        metadata_only=profile_id == "sigma_metadata",
    )
