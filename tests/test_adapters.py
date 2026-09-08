import csv
import io
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from dvi_sentinel.adapters import load_input, normalize
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.scenario import FixtureInput
from dvi_sentinel.serialization import canonical_json, digest

EXAMPLES = Path(__file__).parents[1] / "examples"


def flat(kind: str = "flow") -> dict:
    return {
        "event_id": "equivalent:1",
        "timestamp": "2026-01-01T03:00:00.123456+03:00",
        "category": kind,
        "action": "observed",
        "protocol": "TCP",
        "src_ip": "192.0.2.10",
        "src_port": 42000,
        "dst_ip": "198.51.100.20",
        "dst_port": 443,
        "severity": "high" if kind == "alert" else "unknown",
        "correlation_id": "123",
        "labels": ["lab"],
        "sensor": "lab-sensor",
        "vendor": "synthetic",
        **({"dns_name": "Example.TEST."} if kind == "dns" else {}),
        **({"http_method": "get", "http_path": "/status"} if kind == "http" else {}),
    }


def eve(kind: str = "flow") -> dict:
    return {
        "dvi_event_id": "equivalent:1",
        "timestamp": "2026-01-01T00:00:00.123456+0000",
        "event_type": kind,
        "proto": "TCP",
        "src_ip": "192.0.2.10",
        "src_port": 42000,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "flow_id": 123,
        "dvi_labels": ["lab"],
        "sensor_name": "lab-sensor",
        "vendor": "synthetic",
        **(
            {"alert": {"severity": 1, "signature": "Synthetic", "action": "observed"}}
            if kind == "alert"
            else {}
        ),
        **(
            {"dns": {"queries": [{"rrname": "example.test", "rrtype": "A"}]}}
            if kind == "dns"
            else {}
        ),
        **({"http": {"http_method": "GET", "url": "/status"}} if kind == "http" else {}),
    }


def csv_bytes(record: dict) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(record), lineterminator="\n")
    writer.writeheader()
    writer.writerow(
        {
            key: canonical_json(value) if isinstance(value, list) else value
            for key, value in record.items()
        }
    )
    return stream.getvalue().encode()


@pytest.mark.parametrize("kind", ["flow", "dns", "http", "alert"])
def test_equivalent_real_adapters(kind: str) -> None:
    generic = flat(kind)
    contents = [
        canonical_json(generic).encode(),
        csv_bytes(generic),
        canonical_json(eve(kind)).encode(),
    ]
    results = [
        normalize(data, adapter)
        for data, adapter in zip(contents, ("jsonl", "csv", "suricata_eve"), strict=True)
    ]
    assert all(result.parser_success for result in results), [r.errors for r in results]
    first = results[0].events[0]
    for result, original in zip(results, contents, strict=True):
        event = result.events[0]
        assert event.semantics == first.semantics
        assert (event.timestamp, event.severity, event.labels, event.correlation_id) == (
            first.timestamp,
            first.severity,
            first.labels,
            first.correlation_id,
        )
        assert event.raw.adapter == result.adapter
        assert event.raw.raw_digest == digest(event.raw.payload)
        assert normalize(original, result.adapter) == result
    assert results[0].events[0].raw.payload == generic
    assert results[1].events[0].raw.payload["src_port"] == "42000"
    assert results[1].events[0].raw.payload["labels"] == '["lab"]'
    assert results[2].events[0].raw.payload == eve(kind)
    assert any(w.code == "DVI-ADAPTER-TIMEZONE" for w in results[2].events[0].warnings)


def test_canonical_input_and_source_evidence(tmp_path: Path) -> None:
    payload = (EXAMPLES / "canonical_event.json").read_bytes()
    result = normalize(payload, "jsonl")
    original = TelemetryEvent.model_validate_json(payload)
    assert result.parser_success
    assert result.events[0].semantics == original.semantics
    assert result.events[0].raw.payload["event_id"] == original.event_id
    (tmp_path / "events.jsonl").write_bytes(payload)
    assert (
        load_input(
            tmp_path, FixtureInput(path="events.jsonl", format="jsonl", provenance="synthetic")
        )
        == result
    )


@pytest.mark.parametrize(
    "payload,adapter,code",
    [
        (b"", "jsonl", "DVI-ADAPTER-EMPTY"),
        (b"broken", "jsonl", "DVI-ADAPTER-JSON"),
        (b'{"x":1,"x":2}', "jsonl", "DVI-ADAPTER-JSON"),
        (b'{"x":NaN}', "jsonl", "DVI-ADAPTER-JSON"),
        (b"[]", "jsonl", "DVI-ADAPTER-FIELD"),
        (b"{}", "jsonl", "DVI-ADAPTER-FIELD"),
        (b"\xff", "jsonl", "DVI-ADAPTER-PARSE"),
        (b"a,a\n1,2", "csv", "DVI-ADAPTER-CSV"),
        (b"a,b\n1", "csv", "DVI-ADAPTER-CSV"),
        (b'a,b\n"unclosed', "csv", "DVI-ADAPTER-PARSE"),
        (b"{}", "zeek", "DVI-ADAPTER-UNSUPPORTED"),
    ],
)
def test_malformed_input(payload: bytes, adapter: str, code: str) -> None:
    result = normalize(payload, adapter)
    assert not result.parser_success and not result.events
    assert result.errors[0].code == code


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"src_ip": "8.8.8.8"}, "DVI-ADAPTER-POLICY"),
        ({"command": "inert"}, "DVI-ADAPTER-POLICY"),
        ({"src_port": True}, "DVI-ADAPTER-FIELD"),
        ({"source_ip": "192.0.2.11"}, "DVI-ADAPTER-ALIAS-CONFLICT"),
        ({"timestamp": "2026-01-01"}, "DVI-ADAPTER-FIELD"),
        ({"src_port": 65536}, "DVI-ADAPTER-FIELD"),
        ({"severity": True}, "DVI-ADAPTER-FIELD"),
        ({"severity": "loud"}, "DVI-ADAPTER-FIELD"),
        ({"labels": [1]}, "DVI-ADAPTER-FIELD"),
        ({"sensor": 1}, "DVI-ADAPTER-FIELD"),
        ({"src_ip": None}, "DVI-ADAPTER-FIELD"),
    ],
)
def test_invalid_records_and_conflicting_aliases(changes: dict, code: str) -> None:
    result = normalize(canonical_json(flat() | changes).encode(), "jsonl")
    assert not result.parser_success and not result.events
    assert result.errors[0].code == code
    assert result.errors[0].record_index == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"event_type": "tls"},
        {"alert": []},
        {"alert": {"severity": 4}},
        {"flow_id": True},
    ],
)
def test_unsupported_eve_record_shapes(changes: dict) -> None:
    result = normalize(canonical_json(eve("alert") | changes).encode(), "suricata_eve")
    assert not result.parser_success and result.errors


def test_dns_ambiguity_and_missing_semantic_fields() -> None:
    for dns in (
        {},
        {"queries": []},
        {"queries": [{"rrname": "a.test"}, {"rrname": "b.test"}]},
        {"rrname": "a.test", "queries": [{"rrname": "b.test"}]},
    ):
        result = normalize(canonical_json(eve("dns") | {"dns": dns}).encode(), "suricata_eve")
        assert not result.parser_success
    result = normalize(canonical_json(eve("http") | {"http": {}}).encode(), "suricata_eve")
    assert not result.parser_success


def test_partial_errors_preserve_line_locations_and_fail_parser_success() -> None:
    result = normalize((canonical_json(flat()) + "\nbroken\n").encode(), "jsonl")
    assert len(result.events) == 1 and len(result.errors) == 1
    assert result.errors[0].record_index == 2
    assert not result.parser_success
    duplicate = normalize(
        (canonical_json(flat()) + "\n" + canonical_json(flat())).encode(), "jsonl"
    )
    assert duplicate.errors[0].code == "DVI-ADAPTER-DUPLICATE-ID"


def test_missing_severity_and_generated_ids_are_explicit() -> None:
    record = flat()
    del record["severity"]
    del record["event_id"]
    result = normalize(canonical_json(record).encode(), "jsonl")
    event = result.events[0]
    assert event.severity == 0
    assert event.event_id == f"evt:{event.raw.raw_digest[:24]}:1"
    assert event.warnings[0].code == "DVI-ADAPTER-SEVERITY-MISSING"


def test_canonical_raw_payload_cannot_hide_unsafe_content() -> None:
    original = TelemetryEvent.model_validate_json((EXAMPLES / "canonical_event.json").read_bytes())
    changed = TelemetryEvent.model_validate(
        original.model_dump()
        | {
            "raw": RawSource.from_payload({"command": "inert"}, adapter="jsonl"),
        }
    )
    result = normalize(canonical_json(changed).encode(), "jsonl")
    assert not result.events and result.errors[0].code == "DVI-ADAPTER-POLICY"


@given(st.sampled_from([0, 1, 2, 3, 4, 5]))
def test_csv_jsonl_severity_equivalence(severity: int) -> None:
    record = flat() | {"severity": severity}
    left = normalize(canonical_json(record).encode(), "jsonl")
    right = normalize(csv_bytes(record), "csv")
    assert left.events[0].severity == right.events[0].severity == severity


def test_committed_equivalent_fixture_files() -> None:
    results = [
        normalize((EXAMPLES / "telemetry" / name).read_bytes(), adapter)
        for name, adapter in (
            ("generic.jsonl", "jsonl"),
            ("generic.csv", "csv"),
            ("suricata_eve.jsonl", "suricata_eve"),
        )
    ]
    assert all(r.parser_success and len(r.events) == 4 for r in results)
    for offset in range(4):
        assert len({r.events[offset].semantics.stable_digest() for r in results}) == 1
        assert len({r.events[offset].timestamp for r in results}) == 1
        assert len({r.events[offset].severity for r in results}) == 1
