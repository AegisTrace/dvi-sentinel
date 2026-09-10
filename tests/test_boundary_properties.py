"""Generated boundary data must preserve meaning or fail with structured evidence."""

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from hypothesis import example, given
from hypothesis import strategies as st

from dvi_sentinel.adapters import NormalizationResult, normalize
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events, inspect_content
from dvi_sentinel.scenario import Scenario
from dvi_sentinel.scenario_io import parse_scenario
from dvi_sentinel.serialization import canonical_json

ROOT = Path(__file__).parents[1] / "examples"


@given(st.binary(max_size=1024), st.sampled_from(["jsonl", "csv", "suricata_eve"]))
def test_arbitrary_fixture_bytes_have_deterministic_structured_outcomes(content, adapter):
    result = normalize(content, adapter)
    assert result.input_digest == hashlib.sha256(content).hexdigest()
    assert result == normalize(content, adapter)
    assert NormalizationResult.model_validate_json(canonical_json(result)) == result
    assert not evaluate_events(result.events)
    assert result.parser_success == bool(result.events and not result.errors)
    assert result.events or result.errors


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_jsonl_unicode_inside_strings_does_not_split_records(separator):
    records = [json.loads(line) for line in (ROOT / "probes/events.jsonl").read_text().splitlines()]
    records[0]["labels"] = [f"lab{separator}fixture"]
    content = "\n".join(json.dumps(row, ensure_ascii=False) for row in records).encode()
    result = normalize(content, "jsonl")
    assert result.parser_success, result.errors
    assert len(result.events) == 2
    assert [e.raw.record_index for e in result.events] == [1, 2]
    assert result.events[0].labels == (f"lab{separator}fixture",)
    assert result.events[0].raw.payload == records[0]


def test_jsonl_terminal_newline_does_not_consume_a_record_slot():
    bounded = normalize(b"null\n" * 10_000, "jsonl")
    assert len(bounded.errors) == 10_000
    assert bounded.errors[-1].record_index == 10_000
    assert {e.code for e in bounded.errors} == {"DVI-ADAPTER-FIELD"}
    over = normalize(b"null\n" * 10_001, "jsonl")
    assert over.errors[-1].code == "DVI-ADAPTER-SIZE"


@given(
    st.sampled_from(["\n", "\r\n"]),
    st.integers(min_value=0, max_value=4),
    st.sampled_from(["{broken", "null", "[]", '{"event_id":"missing-fields"}']),
)
def test_partial_jsonl_keeps_physical_line_evidence(newline, blank_lines, malformed):
    rows = (ROOT / "probes/events.jsonl").read_text().splitlines()
    content = newline.join([rows[0], *("" for _ in range(blank_lines)), malformed, rows[1]])
    result = normalize(content.encode(), "jsonl")
    assert not result.parser_success and len(result.events) == 2
    assert {error.record_index for error in result.errors} == {blank_lines + 2}
    assert [event.raw.record_index for event in result.events] == [1, blank_lines + 3]


@given(
    st.datetimes(min_value=datetime(2000, 1, 2), max_value=datetime(2030, 12, 30)),
    st.integers(min_value=-1439, max_value=1439),
    st.lists(st.text(alphabet="abcXYZ012-_:éΩ", min_size=1, max_size=12), max_size=8),
)
def test_full_event_roundtrip_normalizes_offsets_and_metadata(instant, offset, labels):
    original = normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events[0]
    stamp = instant.replace(tzinfo=UTC)
    represented = stamp.astimezone(timezone(timedelta(minutes=offset)))
    event = TelemetryEvent.model_validate(
        original.model_dump() | {"timestamp": represented.isoformat(), "labels": labels}
    )
    roundtrip = TelemetryEvent.model_validate_json(canonical_json(event))
    assert roundtrip == event and event.timestamp == stamp
    assert event.labels == tuple(sorted(set(labels)))
    assert event.raw == original.raw and event.semantics == original.semantics
    assert not evaluate_events((event,))


@given(
    st.sampled_from(
        ["echo $(inert)", "<script>inert</script>", "{{ value }}", "credential command"]
    ),
    st.integers(min_value=0, max_value=60000),
    st.integers(min_value=1, max_value=1000),
)
def test_inert_scenario_descriptions_and_valid_bounds_roundtrip(description, jitter, variants):
    data = yaml.safe_load((ROOT / "foundation_scenario.yaml").read_text())
    data["metadata"]["description"] = description
    data["variations"].update(max_jitter_ms=jitter, max_variants=variants)
    first = parse_scenario(yaml.safe_dump(data, sort_keys=False))
    reordered = parse_scenario(yaml.safe_dump(data, sort_keys=True))
    assert first == reordered
    assert Scenario.model_validate_json(canonical_json(first)) == first
    assert first.metadata.description == description
    assert first.variations.max_jitter_ms == jitter


@example(0)
@example(1)
@given(st.integers(min_value=-1000, max_value=1000))
def test_numeric_safety_declarations_never_coerce_to_attestation(value):
    data = yaml.safe_load((ROOT / "foundation_scenario.yaml").read_text())
    data["safety"]["local_only"] = value
    with pytest.raises(PolicyError) as error:
        parse_scenario(yaml.safe_dump(data))
    assert any(d.rule_id == "DVI-POL-003" for d in error.value.decisions)


@pytest.mark.parametrize(
    "key,rule",
    [
        ("command", "004"),
        ("payload", "005"),
        ("credential", "006"),
        ("stealth", "007"),
        ("target", "008"),
    ],
)
@given(st.sampled_from(["upper", "spaced", "fullwidth"]), st.integers(min_value=0, max_value=3))
def test_policy_key_formatting_and_nesting_keep_rule_identity(key, rule, spelling, depth):
    altered = (
        key.upper()
        if spelling == "upper"
        else "_".join(key)
        if spelling == "spaced"
        else "".join(chr(ord(c) + 0xFEE0) for c in key)
    )
    data = {altered: "inert fixture text"}
    path = "$"
    for _ in range(depth):
        data = {"notes": [data]}
        path += ".notes[0]"
    decisions = inspect_content(data)
    assert len(decisions) == 1
    assert decisions[0].rule_id == f"DVI-POL-{rule}"
    assert decisions[0].decision == "reject" and decisions[0].path == f"{path}.{altered}"
