import csv
import io
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential import run_differential
from dvi_sentinel.differential_models import DifferentialReport, FixtureRepresentation
from dvi_sentinel.fixture_encoding import REPRESENTATIONS, encode_fixture
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import FixtureResults, LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.serialization import canonical_json

ROOT = Path(__file__).parents[1] / "examples"


def events():
    return normalize((ROOT / "telemetry/generic.jsonl").read_bytes(), "jsonl").events


def harness(field="category", operator="eq", value="alert"):
    return RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic",
            rules=(
                LocalRule(
                    id="test",
                    detector="lab",
                    signature="fixture",
                    title="Local fixture observation",
                    conditions=(RuleCondition(field=field, operator=operator, value=value),),
                ),
            ),
        )
    )


def test_equivalent_real_roundtrips_and_stable_report():
    result = run_differential(events(), harness())
    assert {c.status for c in result.cases} == {"agree"}
    assert tuple(c.representation for c in result.cases) == REPRESENTATIONS
    assert len({c.normalized.input_digest for c in result.cases}) == 3
    assert all(c.observation.detections and not c.differences for c in result.cases)
    assert canonical_json(result) == canonical_json(run_differential(events(), harness()))
    assert DifferentialReport.model_validate_json(canonical_json(result)) == result
    for case in result.cases:
        assert case.normalized.events[0].raw.payload != events()[0].raw.payload


def test_raw_schema_dependency_is_real_fragility_not_semantic_loss():
    result = run_differential(events(), harness("raw.category", "exists", None))
    by_format = {c.representation: c for c in result.cases}
    assert by_format["csv"].status == "agree"
    for representation in ("canonical_jsonl", "suricata_eve"):
        case = by_format[representation]
        assert case.status == "disagree"
        assert [d.finding_class for d in case.differences] == ["schema_fragility"]
        assert not case.observation.detections


@pytest.mark.parametrize(
    ("field", "value", "finding"),
    [
        ("timestamp", "2026-01-01T00:00:00Z", "timestamp_precision_drift"),
        ("severity", "low", "severity_normalization_drift"),
        ("labels", "[]", "optional_field_loss"),
        ("correlation_id", "", "correlation_key_loss"),
        ("src_ip", "", "field_mapping_loss"),
        ("action", "different", "adapter_disagreement"),
    ],
)
def test_deliberately_lossy_csv_fixture_is_classified(field, value, finding):
    original = (events()[-1],)
    source = encode_fixture(original, "csv")
    reader = csv.DictReader(io.StringIO(source))
    rows = list(reader)
    rows[0][field] = value
    if field == "src_ip":
        rows[0]["src_port"] = ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    result = run_differential(
        original,
        harness(),
        (FixtureRepresentation(representation="csv", content=output.getvalue()),),
    )
    case = result.cases[0]
    assert case.status == "disagree"
    assert finding in {d.finding_class for d in case.differences}
    assert "schema_fragility" not in {d.finding_class for d in case.differences}
    assert all(d.expected != d.observed for d in case.differences)


def test_formatting_only_differences_are_suppressed():
    sources = tuple(
        FixtureRepresentation(
            representation=representation,
            content=encode_fixture(events(), representation)
            .replace("2026-01-01T00:00:00.123456+00:00", "2026-01-01T03:00:00.123456+03:00")
            .replace("\n", "\r\n"),
        )
        for representation in REPRESENTATIONS
    )
    assert all(
        c.status == "agree" and not c.differences
        for c in run_differential(events(), harness(), sources).cases
    )


def test_unsupported_fields_and_missing_detector_fixture_are_unknown():
    rich = tuple(
        TelemetryEvent.model_validate(e.model_dump() | {"confidence": 0.5}) for e in events()
    )
    result = run_differential(rich, harness())
    assert result.cases[0].status == "agree"
    assert all(c.status == "unknown" and "confidence" in c.reason for c in result.cases[1:])
    empty = run_differential(events(), FixtureHarness(FixtureResults(cases=())))
    assert all(c.status == "unknown" and not c.differences for c in empty.cases)
    no_alert = run_differential(events(), harness("action", "eq", "missing"))
    assert all(c.status == "unknown" for c in no_alert.cases)


def test_partial_parse_and_unsafe_sources_never_become_measured_misses():
    valid = encode_fixture(events(), "canonical_jsonl")
    for content in (valid + "{bad}\n", valid + '{"command":"inert"}\n'):
        result = run_differential(
            events(),
            harness(),
            (FixtureRepresentation(representation="canonical_jsonl", content=content),),
        )
        case = result.cases[0]
        assert case.status == "unknown" and case.observation is None and not case.differences
        assert case.normalized.events and case.normalized.errors
    unsafe = (
        TelemetryEvent.model_validate(
            events()[0].model_dump()
            | {
                "raw": RawSource.from_payload({"credential": "inert"}, adapter="jsonl"),
            }
        ),
    )
    with pytest.raises(PolicyError):
        run_differential(unsafe, harness())


def test_alignment_requires_explicit_ids_and_preserves_order():
    source = encode_fixture(tuple(reversed(events())), "canonical_jsonl")
    case = run_differential(
        events(),
        harness(),
        (FixtureRepresentation(representation="canonical_jsonl", content=source),),
    ).cases[0]
    assert any(d.path == "/event_order" for d in case.differences)
    case = run_differential(
        events(),
        harness(),
        (
            FixtureRepresentation(
                representation="canonical_jsonl",
                content=encode_fixture(events()[1:], "canonical_jsonl"),
            ),
        ),
    ).cases[0]
    assert any(
        d.path == "/event_id" and d.finding_class == "field_mapping_loss" for d in case.differences
    )


@settings(max_examples=16, deadline=None, derandomize=True)
@given(st.integers(min_value=0, max_value=999999), st.sampled_from([2, 3, 4]))
def test_exact_time_and_severity_across_representations(microseconds, severity):
    event = TelemetryEvent.model_validate(
        events()[-1].model_dump()
        | {
            "timestamp": f"2026-01-01T00:00:00.{microseconds:06d}Z",
            "severity": severity,
        }
    )
    result = run_differential((event,), harness())
    assert all(c.status == "agree" and not c.differences for c in result.cases)


def test_bounds_and_duplicate_representation_rejection():
    with pytest.raises(ValueError, match="unique"):
        run_differential((events()[0], events()[0]), harness())
    one = FixtureRepresentation(representation="csv", content=encode_fixture(events(), "csv"))
    with pytest.raises(ValueError, match="distinct"):
        run_differential(events(), harness(), (one, one))
