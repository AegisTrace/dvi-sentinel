"""Behavioral proof for bounded temporal and correlation predicates."""

import pytest

from dvi_sentinel.models import DetectionEvent, RawSource, TelemetryEvent
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.temporal import (
    after,
    alert_within_window,
    at_least_k_of_n,
    before,
    evaluate_temporal,
    no_contradictory_context,
    same_correlation_key,
    same_entity,
    same_flow,
    sequence_order,
    temporal_artifacts,
    within,
)


def event(
    event_id: str,
    timestamp: str,
    *,
    category: str = "flow",
    correlation_id: str | None = "flow:1",
    entities: tuple[dict[str, str], ...] = ({"kind": "host", "value": "demo.example"},),
    labels: tuple[str, ...] = (),
    source: str = "192.0.2.1",
    destination: str = "198.51.100.2",
    protocol: str | None = "tcp",
) -> TelemetryEvent:
    semantics: dict[str, object] = {
        "category": category,
        "action": "observed" if category != "alert" else "match",
    }
    if protocol is not None:
        semantics["protocol"] = protocol
    if category == "flow":
        semantics["source"] = {"address": source, "port": 1234}
        semantics["destination"] = {"address": destination, "port": 443}
    return TelemetryEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "semantics": semantics,
            "raw": RawSource.from_payload(
                {"kind": category}, adapter="jsonl", original_timestamp=timestamp
            ),
            "correlation_id": correlation_id,
            "entities": entities,
            "labels": labels,
        }
    )


def detection(event_id: str, timestamp: str) -> DetectionEvent:
    return DetectionEvent.model_validate(
        event(event_id, timestamp, category="alert").model_dump()
        | {
            "severity": 4,
            "detector": "fixture:detector",
            "signature": "fixture:signature",
            "title": "Fixture alert",
        }
    )


def test_before_after_within_and_timezone_normalize_to_the_same_instant():
    first = event("fixture:first", "2026-01-01T00:00:00+03:00")
    second = event("fixture:second", "2025-12-31T21:00:01Z")
    assert before(first, second).outcome == "supported"
    assert after(second, first).outcome == "supported"
    assert within(first, second, 1_800_000).outcome == "supported"
    equal = event("fixture:equal", "2025-12-31T21:00:00Z")
    assert before(first, equal).outcome == "contradicted"


def test_out_of_order_input_and_duplicate_timestamps_have_stable_order():
    late = event("fixture:z", "2026-01-01T00:00:01Z")
    early = event("fixture:a", "2026-01-01T00:00:00Z")
    same_b = event("fixture:b", "2026-01-01T00:00:00Z")
    summary = evaluate_temporal((late, same_b, early), pattern=("fixture:a", "fixture:z"))
    assert summary.ordered_event_ids == ("fixture:a", "fixture:b", "fixture:z")
    assert summary.traces[-1].check.outcome == "supported"
    assert summary.traces[-1].normalized_timestamps[0] == '"2026-01-01T00:00:00Z"'


def test_entity_flow_and_correlation_predicates_require_explicit_evidence():
    left = event("fixture:left", "2026-01-01T00:00:00Z")
    right = event("fixture:right", "2026-01-01T00:00:01Z")
    assert same_entity(left, right).outcome == "supported"
    assert same_flow(left, right).outcome == "supported"
    assert same_correlation_key(left, right).outcome == "supported"
    assert (
        same_entity(left, event("fixture:missing", "2026-01-01T00:00:01Z", entities=())).outcome
        == "unknown"
    )
    assert (
        same_flow(
            left, event("fixture:flow-missing", "2026-01-01T00:00:01Z", protocol=None)
        ).outcome
        == "unknown"
    )
    assert (
        same_correlation_key(
            left, event("fixture:key-missing", "2026-01-01T00:00:01Z", correlation_id=None)
        ).outcome
        == "unknown"
    )


def test_finite_count_and_missing_event_evidence_are_distinct():
    one = event("fixture:one", "2026-01-01T00:00:00Z")
    two = event("fixture:two", "2026-01-01T00:00:01Z")
    assert at_least_k_of_n((one, two), 1, 2).outcome == "supported"
    missing = at_least_k_of_n((one,), 1, 2)
    assert missing.outcome == "unknown" and "event_evidence_missing" in missing.reason_codes
    with pytest.raises(ValueError, match="DVI-TEMPORAL-WINDOW"):
        within(one, two, 86_400_001)


def test_precision_loss_is_a_warning_and_does_not_pass_a_declared_requirement():
    first = event("fixture:one", "2026-01-01T00:00:00.123Z")
    second = event("fixture:two", "2026-01-01T00:00:00.124Z")
    check = within(first, second, 10, precision_digits=6)
    assert check.outcome == "unknown"
    assert check.reason_codes == ("timestamp_precision_loss",)


def test_alert_window_and_benign_context_suppression_are_explicit():
    signal = event("fixture:signal", "2026-01-01T00:00:00Z")
    alert = detection("fixture:alert", "2026-01-01T00:00:02Z")
    assert alert_within_window(signal, alert, 3_000).outcome == "supported"
    assert (
        alert_within_window(
            signal, detection("fixture:late", "2026-01-01T00:00:04Z"), 3_000
        ).outcome
        == "contradicted"
    )
    benign = event("fixture:benign", "2026-01-01T00:00:00Z", labels=("benign",))
    suppressed = no_contradictory_context((signal, benign))
    assert suppressed.outcome == "contradicted"
    assert suppressed.reason_codes == ("contradictory_benign_context",)


def test_sequence_order_matches_ids_categories_or_actions():
    first = event("fixture:first", "2026-01-01T00:00:00Z")
    second = event("fixture:second", "2026-01-01T00:00:01Z", category="dns")
    assert sequence_order((second, first), ("flow", "dns")).outcome == "supported"
    assert sequence_order((first,), ("flow", "dns")).outcome == "unknown"
    assert sequence_order((second, first), ("dns", "flow")).outcome == "contradicted"


def test_temporal_artifacts_are_deterministic_and_canonical():
    first = event("fixture:first", "2026-01-01T00:00:00Z")
    second = event("fixture:second", "2026-01-01T00:00:01Z")
    artifacts = temporal_artifacts((second, first), pattern=("flow",), window_ms=2_000)
    assert set(artifacts) == {
        "temporal_trace.jsonl",
        "correlation_evidence.json",
        "sequence_findings.json",
        "temporal_summary.json",
    }
    summary = parse_json(artifacts["temporal_summary.json"])
    assert summary["ordered_event_ids"] == ["fixture:first", "fixture:second"]
    assert artifacts == temporal_artifacts((first, second), pattern=("flow",), window_ms=2_000)
