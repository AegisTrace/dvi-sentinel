"""Loss-aware encoders for local differential fixtures, not standards exporters."""

import csv
import io
from typing import Literal

from pydantic import JsonValue

from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.serialization import canonical_json

Representation = Literal["canonical_jsonl", "csv", "suricata_eve"]
REPRESENTATIONS: tuple[Representation, ...] = ("canonical_jsonl", "csv", "suricata_eve")


class EncodingError(ValueError):
    """The supported representation cannot retain the supplied canonical fields."""


def _flat(event: TelemetryEvent) -> dict[str, JsonValue]:
    missing = [
        field
        for field in ("observed_at", "confidence", "entities", "evidence")
        if getattr(event, field) not in (None, ())
    ]
    if missing:
        raise EncodingError("DVI-ENCODING-UNSUPPORTED: " + ",".join(missing))
    semantics = event.semantics
    data: dict[str, JsonValue] = {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(timespec="microseconds"),
        "category": semantics.category,
        "action": semantics.action,
        "outcome": semantics.outcome,
        "protocol": semantics.protocol,
        "severity": int(event.severity),
        "dns_name": semantics.dns_name,
        "http_method": semantics.http_method,
        "http_path": semantics.http_path,
        "sensor": event.raw.sensor,
        "vendor": event.raw.vendor,
        "labels": list(event.labels),
        "tags": list(event.tags),
        "correlation_id": event.correlation_id,
    }
    for prefix, endpoint in (("src", semantics.source), ("dst", semantics.destination)):
        data[f"{prefix}_ip"] = str(endpoint.address) if endpoint else None
        data[f"{prefix}_port"] = endpoint.port if endpoint else None
    return data


def _eve(event: TelemetryEvent) -> dict[str, JsonValue]:
    flat = _flat(event)
    kind = event.semantics.category
    if (kind == "alert" and event.severity not in (2, 3, 4)) or (
        kind != "alert" and event.severity != 0
    ):
        raise EncodingError("DVI-ENCODING-UNSUPPORTED: EVE severity outside supported mapping")
    if (kind != "dns" and event.semantics.dns_name is not None) or (
        kind != "http"
        and (event.semantics.http_method is not None or event.semantics.http_path is not None)
    ):
        raise EncodingError("DVI-ENCODING-UNSUPPORTED: category-specific fields cannot be retained")
    rename = {
        "event_id": "dvi_event_id",
        "category": "event_type",
        "action": "dvi_action",
        "outcome": "dvi_outcome",
        "protocol": "proto",
        "dst_ip": "dest_ip",
        "dst_port": "dest_port",
        "labels": "dvi_labels",
        "tags": "dvi_tags",
        "correlation_id": "flow_id",
    }
    record: dict[str, JsonValue] = {
        rename.get(key, key): value
        for key, value in flat.items()
        if key not in {"severity", "dns_name", "http_method", "http_path"} and value is not None
    }
    if kind == "alert":
        record["alert"] = {
            "severity": {4: 1, 3: 2, 2: 3}[event.severity],
            "action": event.semantics.action,
        }
    elif kind == "dns":
        record["dns"] = {"rrname": event.semantics.dns_name}
    elif kind == "http":
        record["http"] = {
            "http_method": event.semantics.http_method,
            "url": event.semantics.http_path,
        }
    elif kind == "flow":
        record["flow"] = {}
    return record


def encode_fixture(events: tuple[TelemetryEvent, ...], representation: Representation) -> str:
    if representation == "canonical_jsonl":
        return "".join(canonical_json(event) + "\n" for event in events)
    if representation == "suricata_eve":
        return "".join(canonical_json(_eve(event)) + "\n" for event in events)
    if representation != "csv":
        raise EncodingError("DVI-ENCODING-UNSUPPORTED: unknown representation")
    output = io.StringIO(newline="")
    rows = [_flat(event) for event in events]
    if not rows:
        return ""
    fields = sorted(rows[0])
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                key: canonical_json(value) if isinstance(value, list) else value
                for key, value in row.items()
            }
        )
    return output.getvalue()
