from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.models import (
    DetectionEvent,
    EventSemantics,
    NetworkEndpoint,
    RawSource,
    Severity,
    TelemetryEvent,
    utc_timestamp,
)
from dvi_sentinel.serialization import canonical_json, digest


def event_data() -> dict:
    return {
        "event_id": "evt:1",
        "timestamp": "2026-01-01T03:00:00+03:00",
        "semantics": {"category": "flow", "action": "observed", "protocol": "tcp"},
        "raw": RawSource.from_payload({"count": 1}, adapter="jsonl"),
    }


def test_event_roundtrip_and_utc() -> None:
    event = TelemetryEvent.model_validate(event_data())
    assert event.timestamp == datetime(2026, 1, 1, tzinfo=UTC)
    assert event.severity == Severity.UNKNOWN
    assert TelemetryEvent.model_validate_json(canonical_json(event)) == event
    assert event.stable_digest() == digest(event)


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-01",
        "2026-01-01T00:00:00",
        123,
        True,
        "2026-02-30T00:00:00Z",
        "2026-01-01T00:00:00.1234567Z",
        datetime(2026, 1, 1),
    ],
)
def test_invalid_timestamps(value: object) -> None:
    with pytest.raises(ValidationError, match="DVI-EVT-TIME"):
        TelemetryEvent.model_validate(event_data() | {"timestamp": value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity", True),
        ("severity", "3"),
        ("severity", 6),
        ("confidence", float("nan")),
        ("confidence", 1.1),
        ("confidence", "0.5"),
        ("event_id", ""),
        ("event_id", "spaces forbidden"),
        ("extra_field", 1),
    ],
)
def test_strict_boundaries(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        TelemetryEvent.model_validate(event_data() | {field: value})


@pytest.mark.parametrize("port", [-1, 65536, True, "80", 1.5])
def test_invalid_ports(port: object) -> None:
    with pytest.raises(ValidationError):
        NetworkEndpoint.model_validate({"address": "192.0.2.1", "port": port})


@pytest.mark.parametrize("address", [123, True, "example.com", "fe80::1%eth0", "999.1.1.1"])
def test_invalid_addresses(address: object) -> None:
    with pytest.raises(ValidationError):
        NetworkEndpoint.model_validate({"address": address})


def test_ip_normalization() -> None:
    endpoint = NetworkEndpoint(address="2001:0db8:0:0::1", port=0)
    assert endpoint.model_dump(mode="json") == {"address": "2001:db8::1", "port": 0}


def test_raw_snapshot_is_immutable_and_retains_original_time() -> None:
    payload = {"nested": [1, {"x": "value"}]}
    source = RawSource.from_payload(payload, adapter="csv", original_timestamp="original")
    payload["nested"].append(2)
    extracted = source.payload
    extracted["nested"] = []
    assert source.payload == {"nested": [1, {"x": "value"}]}
    assert source.original_timestamp == "original"
    with pytest.raises(ValidationError, match="frozen_instance"):
        source.adapter = "eve"


def test_raw_integrity_and_nonfinite_values() -> None:
    source = RawSource.from_payload({"a": 1}, adapter="jsonl")
    for changes in [
        {"raw_digest": "0" * 64},
        {"payload_json": "[]"},
        {"payload_json": '{"a": 1}'},
        {"payload_json": "invalid"},
    ]:
        with pytest.raises(ValidationError, match="DVI-EVT-RAW"):
            RawSource.model_validate(source.model_dump() | changes)
    with pytest.raises(ValueError):
        RawSource.from_payload({"x": float("inf")}, adapter="jsonl")


def test_sets_are_sorted_without_mutating_inputs() -> None:
    labels = ["b", "a", "b"]
    event = TelemetryEvent.model_validate(event_data() | {"labels": labels})
    assert event.labels == ("a", "b")
    assert labels == ["b", "a", "b"]


def test_detection_requires_alert_semantics_and_identity() -> None:
    data = event_data() | {"detector": "lab", "signature": "rule:1", "title": "Fixture alert"}
    with pytest.raises(ValidationError, match="DVI-EVT-DETECTION"):
        DetectionEvent.model_validate(data)
    data["semantics"] = EventSemantics(category="alert", action="observed")
    detection = DetectionEvent.model_validate(data | {"related_event_ids": ["b", "a", "a"]})
    assert detection.related_event_ids == ("a", "b")
    assert DetectionEvent.model_validate_json(canonical_json(detection)) == detection
    with pytest.raises(ValidationError):
        DetectionEvent.model_validate(event_data())


@given(st.dictionaries(st.text(max_size=20), st.integers(), max_size=15))
def test_raw_hash_independent_of_object_key_order(payload: dict[str, int]) -> None:
    reverse = dict(reversed(list(payload.items())))
    left = RawSource.from_payload(payload, adapter="jsonl")
    right = RawSource.from_payload(reverse, adapter="jsonl")
    assert left.raw_digest == right.raw_digest
    assert left.payload == payload
    assert RawSource.model_validate_json(canonical_json(left)) == left


@given(st.integers(min_value=-23 * 60, max_value=23 * 60))
def test_timezone_normalization_preserves_instant(minutes: int) -> None:
    instant = datetime(2026, 4, 2, 12, 5, 3, 123456, tzinfo=UTC)
    represented = instant.astimezone(timezone(timedelta(minutes=minutes)))
    assert utc_timestamp(represented.isoformat()) == instant


@given(st.integers(min_value=0, max_value=65535))
def test_endpoint_port_roundtrip(port: int) -> None:
    value = NetworkEndpoint(address="192.0.2.1", port=port)
    assert NetworkEndpoint.model_validate_json(canonical_json(value)) == value
