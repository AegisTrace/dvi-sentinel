"""Re-parse equivalent source spellings; original raw records remain immutable."""

import csv
import io
import re
from datetime import timedelta, timezone

from pydantic import JsonValue

from dvi_sentinel.adapters import normalize
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.serialization import canonical_json


def _encoded(record: dict[str, JsonValue], adapter: str) -> bytes:
    if adapter != "csv":
        return canonical_json(record).encode("utf-8")
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(record)
    writer.writerow(record.values())
    return output.getvalue().encode("utf-8")


def source_variant(event: TelemetryEvent, mode: str) -> TelemetryEvent:
    """One record in/out permits explicit logical-ID alignment after re-parsing."""
    adapter = event.raw.adapter
    if adapter not in {"jsonl", "csv", "suricata_eve"}:
        return event
    record = event.raw.payload
    before = canonical_json(record)
    canonical = "semantics" in record and adapter == "jsonl"
    if mode in {"timestamp_precision", "timezone"}:
        key = "timestamp" if "timestamp" in record else "@timestamp"
        if key not in record:
            return event
        spelling = str(record[key])
        match = re.fullmatch(r"(.{19})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:?\d{2})", spelling)
        if match is None:
            return event
        prefix, fraction, suffix = match.groups()
        if mode == "timezone":
            # Fixed offsets have no DST dependence. Avoid converting out of datetime's range.
            offset = timezone(timedelta(hours=2))
            value = event.timestamp.astimezone(offset).isoformat(timespec="microseconds")
            if suffix in {"+02:00", "+0200"}:
                value = event.timestamp.isoformat(timespec="microseconds")
            value = (
                value[:19] + ("." + value[20 : 20 + len(fraction)] if fraction else "") + value[-6:]
            )
        else:
            digits = (fraction or "").rstrip("0")
            if digits == (fraction or ""):
                digits = digits.ljust(6, "0")
            value = prefix + ("." + digits if digits else "") + suffix
        record[key] = value
    elif mode == "schema_alias" and not canonical:
        pairs = (
            (("sensor", "sensor_name"),)
            if adapter == "suricata_eve"
            else (
                ("src_ip", "source_ip"),
                ("dst_ip", "destination_ip"),
                ("timestamp", "@timestamp"),
                ("sensor", "sensor_name"),
            )
        )
        # One field per record: a precise counterfactual, not a bundle of schema changes.
        for left, right in pairs:
            if left in record and right not in record:
                record[right] = record.pop(left)
                break
            if right in record and left not in record:
                record[left] = record.pop(right)
                break
    elif mode == "severity_normalization" and not canonical:
        if adapter == "suricata_eve":
            alert = record.get("alert")
            if isinstance(alert, dict) and "severity" in alert:
                level = alert["severity"]
                alert["severity"] = str(level) if isinstance(level, int) else int(str(level))
        elif record.get("severity") not in (None, ""):
            names = ("unknown", "informational", "low", "medium", "high", "critical")
            value_before = record["severity"]
            record["severity"] = (
                names[event.severity]
                if isinstance(value_before, int) or str(value_before).isdigit()
                else str(int(event.severity))
                if adapter == "csv"
                else int(event.severity)
            )
    if canonical_json(record) == before:
        return event
    result = normalize(_encoded(record, adapter), adapter)
    if not result.parser_success or len(result.events) != 1:
        raise ValueError("DVI-PROBE-PARSE: transformed record did not normalize uniquely")
    parsed = result.events[0]
    return TelemetryEvent.model_validate(parsed.model_dump() | {"event_id": event.event_id})


def semantic_projection(event: TelemetryEvent) -> dict[str, object]:
    """Retain all normalized meaning, including optional metadata and logical identity."""
    data: dict[str, object] = event.model_dump(mode="json", exclude={"raw", "warnings"})
    data["sensor"] = event.raw.sensor
    data["vendor"] = event.raw.vendor
    return data
