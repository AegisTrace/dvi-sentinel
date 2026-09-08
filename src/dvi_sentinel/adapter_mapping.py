"""Explicit field mappings for the three supported fixture representations."""

import re
from typing import cast

from pydantic import JsonValue

from dvi_sentinel.models import RawSource, TelemetryEvent, ValidationWarning
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.serialization import parse_json

JsonObject = dict[str, JsonValue]


def alias(record: JsonObject, *names: str) -> JsonValue:
    present = [(name, record[name]) for name in names if record.get(name) not in (None, "")]
    if present and any(value != present[0][1] for _, value in present[1:]):
        raise ValueError(f"DVI-ADAPTER-ALIAS-CONFLICT: {','.join(name for name, _ in present)}")
    return present[0][1] if present else None


def integer(value: JsonValue) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("DVI-ADAPTER-FIELD: boolean is not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value):
        return int(value)
    raise ValueError("DVI-ADAPTER-FIELD: integer field has invalid representation")


def string_list(value: JsonValue) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("DVI-ADAPTER-FIELD: labels/tags must be JSON string arrays")
    return tuple(cast(list[str], value))


def object_field(record: JsonObject, key: str, *, required: bool = False) -> JsonObject:
    value = record.get(key)
    if value is None and not required:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"DVI-ADAPTER-FIELD: {key} must be an object")
    return value


def eve_projection(record: JsonObject) -> JsonObject:
    """Project supported EVE fields; never generate or execute Suricata traffic/rules."""
    kind = record.get("event_type")
    if kind not in ("alert", "flow", "dns", "http"):
        raise ValueError("DVI-ADAPTER-UNSUPPORTED: EVE event_type must be alert/flow/dns/http")
    alert = object_field(record, "alert", required=kind == "alert")
    dns = object_field(record, "dns", required=kind == "dns")
    http = object_field(record, "http", required=kind == "http")
    dns_name = dns.get("rrname")
    if "queries" in dns:
        queries = dns["queries"]
        if not isinstance(queries, list) or len(queries) != 1 or not isinstance(queries[0], dict):
            raise ValueError(
                "DVI-ADAPTER-UNSUPPORTED: DNS queries must contain exactly one question"
            )
        queried_name = queries[0].get("rrname")
        if dns_name is not None and queried_name != dns_name:
            raise ValueError("DVI-ADAPTER-ALIAS-CONFLICT: DNS rrname/queries disagree")
        dns_name = queried_name
    source_severity = alert.get("severity")
    severity: JsonValue = None
    if source_severity is not None:
        severity_number = integer(source_severity)
        if severity_number not in (1, 2, 3):
            raise ValueError("DVI-ADAPTER-FIELD: supported EVE alert severity is 1, 2, or 3")
        severity = {1: 4, 2: 3, 3: 2}[severity_number]
    flow_id = record.get("flow_id")
    if isinstance(flow_id, bool) or (flow_id is not None and not isinstance(flow_id, str | int)):
        raise ValueError("DVI-ADAPTER-FIELD: flow_id must be text or integer")
    return {
        "event_id": record.get("dvi_event_id"),
        "timestamp": record.get("timestamp"),
        "category": kind,
        "action": record.get("dvi_action", alert.get("action", "observed")),
        "outcome": record.get("dvi_outcome", "unknown"),
        "src_ip": record.get("src_ip"),
        "src_port": record.get("src_port"),
        "dst_ip": record.get("dest_ip"),
        "dst_port": record.get("dest_port"),
        "protocol": record.get("proto"),
        "severity": severity,
        "dns_name": dns_name,
        "http_method": http.get("http_method"),
        "http_path": http.get("url"),
        "correlation_id": str(flow_id) if flow_id is not None else None,
        "labels": record.get("dvi_labels"),
        "tags": record.get("dvi_tags"),
        "sensor": alias(record, "sensor", "sensor_name"),
        "vendor": record.get("vendor"),
    }


def normalize_record(record: JsonObject, adapter: str, index: int) -> TelemetryEvent:
    warnings: list[ValidationWarning] = []
    if adapter == "jsonl" and "semantics" in record:
        event = TelemetryEvent.model_validate(record)
        decisions = evaluate_events((event,))
        if decisions:
            raise PolicyError(decisions)
        raw = RawSource.from_payload(
            record,
            adapter=adapter,
            record_index=index,
            original_timestamp=str(record["timestamp"]),
            sensor=event.raw.sensor,
            vendor=event.raw.vendor,
        )
        return TelemetryEvent.model_validate(event.model_dump() | {"raw": raw})
    data = eve_projection(record) if adapter == "suricata_eve" else dict(record)
    if adapter == "csv":
        for name in ("labels", "tags"):
            encoded = data.get(name)
            if isinstance(encoded, str) and encoded:
                data[name] = parse_json(encoded)
    timestamp = alias(data, "timestamp", "@timestamp")
    if not isinstance(timestamp, str):
        raise ValueError("DVI-ADAPTER-FIELD: timestamp text is required")
    normalized_time = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", timestamp)
    if normalized_time != timestamp:
        warnings.append(
            ValidationWarning(
                code="DVI-ADAPTER-TIMEZONE",
                path="timestamp",
                explanation="colon inserted in numeric UTC offset",
            )
        )
    severity_raw = data.get("severity")
    levels = {"unknown": 0, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    severity: int | None
    if severity_raw in (None, ""):
        severity = 0
        warnings.append(
            ValidationWarning(
                code="DVI-ADAPTER-SEVERITY-MISSING",
                path="severity",
                explanation="severity absent; retained as unknown",
            )
        )
    elif isinstance(severity_raw, str) and severity_raw.lower() in levels:
        severity = levels[severity_raw.lower()]
    else:
        severity = integer(severity_raw)
    protocol = alias(data, "protocol", "proto")
    if isinstance(protocol, str):
        protocol = protocol.lower()
    category = alias(data, "category", "event_type")
    source = alias(data, "src_ip", "source_ip")
    destination = alias(data, "dst_ip", "dest_ip", "destination_ip")
    source_port = alias(data, "src_port", "source_port")
    destination_port = alias(data, "dst_port", "dest_port", "destination_port")
    if (source is None and source_port is not None) or (
        destination is None and destination_port is not None
    ):
        raise ValueError("DVI-ADAPTER-FIELD: port requires an address")
    sensor = alias(data, "sensor", "sensor_name")
    vendor = data.get("vendor")
    if any(value is not None and not isinstance(value, str) for value in (sensor, vendor)):
        raise ValueError("DVI-ADAPTER-FIELD: sensor/vendor must be text")
    raw = RawSource.from_payload(
        record,
        adapter=adapter,
        record_index=index,
        original_timestamp=timestamp,
        sensor=cast(str | None, sensor),
        vendor=cast(str | None, vendor),
    )
    event_id = data.get("event_id") or f"evt:{raw.raw_digest[:24]}:{index}"
    semantics = {
        "category": category,
        "action": data.get("action") or "observed",
        "outcome": data.get("outcome") or "unknown",
        "protocol": protocol,
        "source": {"address": source, "port": integer(source_port)} if source is not None else None,
        "destination": {"address": destination, "port": integer(destination_port)}
        if destination is not None
        else None,
        "dns_name": data.get("dns_name") or None,
        "http_method": data.get("http_method") or None,
        "http_path": data.get("http_path") or None,
    }
    if isinstance(semantics["dns_name"], str):
        semantics["dns_name"] = semantics["dns_name"].lower().rstrip(".")
    if isinstance(semantics["http_method"], str):
        semantics["http_method"] = semantics["http_method"].upper()
    if category == "dns" and not semantics["dns_name"]:
        raise ValueError("DVI-ADAPTER-FIELD: DNS fixtures require a question name")
    if category == "http" and not semantics["http_method"]:
        raise ValueError("DVI-ADAPTER-FIELD: HTTP fixtures require a method")
    return TelemetryEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": normalized_time,
            "semantics": semantics,
            "raw": raw,
            "severity": severity,
            "labels": string_list(data.get("labels")),
            "tags": string_list(data.get("tags")),
            "correlation_id": data.get("correlation_id") or None,
            "warnings": tuple(warnings),
        }
    )
