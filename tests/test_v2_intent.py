"""Behavioral proof for bounded local detection intent analysis."""

import pytest
from pydantic import ValidationError

from dvi_sentinel.detection_intent import analyze_intent, intent_artifacts
from dvi_sentinel.intent_parsing import parse_intent
from dvi_sentinel.models import DetectionEvent, RawSource, TelemetryEvent
from dvi_sentinel.scenario_io import parse_local_yaml
from dvi_sentinel.serialization import parse_json


def event(**changes: object) -> TelemetryEvent:
    value: dict[str, object] = {
        "event_id": "fixture:dns-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "semantics": {
            "category": "dns",
            "action": "query",
            "dns_name": "www.example.com",
        },
        "raw": RawSource.from_payload(
            {"kind": "dns", "logsource": {"category": "dns"}},
            adapter="jsonl",
            original_timestamp="2026-01-01T00:00:00.123Z",
        ),
    }
    value.update(changes)
    return TelemetryEvent.model_validate(value)


NATIVE = """
intent_id: fixture:dns-intent
title: DNS lookup
condition_shape: all
fields:
  - field: category
    paths: [semantics.category]
    operators:
      - name: eq
        value_json: '\"dns\"'
  - field: dns_name
    paths: [semantics.dns_name]
    operators:
      - name: contains
        value_json: '\"example\"'
"""


def test_native_intent_supports_matching_event_and_replays_artifacts():
    parsed = parse_intent(NATIVE)
    result = analyze_intent(parsed, (event(),))
    assert result.state == "supported"
    assert [item.specification.field for item in result.candidates[0].bindings] == [
        "category",
        "dns_name",
    ]
    first = intent_artifacts(parsed, (event(),))
    assert first == intent_artifacts(parsed, (event(),))
    assert set(first) == {
        "detection_intent.json",
        "semantic_loss_report.json",
        "unsupported_conditions.json",
        "intent_assumptions.json",
    }


def test_unsupported_operator_is_inert_and_blocks_support():
    text = NATIVE.replace("name: contains", "name: regex").replace(
        "value_json: '\"example\"'", "value_json: '\"^example\"'"
    )
    result = analyze_intent(parse_intent(text), (event(),))
    assert result.state == "unknown"
    assert any(item.code == "unsupported_operator" for item in result.global_checks)


def test_unsupported_condition_shape_and_logsource_mismatch_stay_visible():
    malformed = NATIVE.replace("condition_shape: all", "condition_shape: any")
    result = analyze_intent(parse_intent(malformed), (event(),))
    assert result.state == "unknown"
    assert any(item.code == "unsupported_condition_shape" for item in result.global_checks)

    source = NATIVE.replace("condition_shape: all", "logsource:\n  adapter: eve")
    result = analyze_intent(parse_intent(source), (event(),))
    assert result.state == "contradicted"
    assert any(item.code == "logsource_mismatch" for item in result.candidates[0].checks)


def test_missing_required_field_is_unknown_and_optional_absence_is_explicit():
    text = NATIVE.replace("field: dns_name", "field: http_path").replace(
        "paths: [semantics.dns_name]", "paths: [semantics.http_path]"
    )
    missing = analyze_intent(parse_intent(text), (event(),))
    assert missing.state == "unknown"
    assert any(item.code == "missing_required_field" for item in missing.candidates[0].checks)

    parsed = parse_intent(NATIVE)
    optional = parsed.intent.fields[1].model_copy(update={"required": False})
    changed = parsed.intent.model_copy(update={"fields": (parsed.intent.fields[0], optional)})
    result = analyze_intent(
        parsed.model_copy(update={"intent": changed}),
        (event(semantics={"category": "dns", "action": "query"}),),
    )
    assert any(item.code == "optional_evidence_absent" for item in result.candidates[0].checks)


def test_alias_conflict_and_correlation_key_remain_unknown():
    text = """
intent_id: fixture:alias
title: endpoint intent
fields:
  - field: endpoint
    paths: [semantics.source.address, semantics.destination.address]
    operators:
      - name: exists
  - field: correlation_id
    paths: [correlation_id]
    operators:
      - name: exists
correlation:
  field: correlation_id
  same_value_required: true
"""
    result = analyze_intent(
        parse_intent(text),
        (
            event(
                semantics={
                    "category": "flow",
                    "action": "observed",
                    "source": {"address": "192.0.2.1", "port": 1},
                    "destination": {"address": "198.51.100.2", "port": 2},
                }
            ),
        ),
    )
    assert result.state == "unknown"
    assert any(item.code == "field_alias_ambiguity" for item in result.candidates[0].checks)
    assert any(item.code == "correlation_key_missing" for item in result.candidates[0].checks)
    assert any(item.field == "pending:correlation-equality" for item in result.global_checks)


def test_casefold_alias_normalization_is_reported_as_loss():
    text = NATIVE.replace(
        "field: dns_name\n    paths:",
        "field: dns_name\n    normalization: casefold\n    paths:",
    )
    upper = event(semantics={"category": "dns", "action": "query", "dns_name": "WWW.Example.COM"})
    result = analyze_intent(parse_intent(text), (upper,))
    assert result.state == "unknown"
    assert any(item.code == "normalization_loss" for item in result.candidates[0].checks)


def test_time_window_is_pending_until_sequence_card():
    text = (
        NATIVE
        + """
time_window:
  duration_ms: 5000
  timestamp_field: category
  precision_digits: 3
"""
    )
    with pytest.raises(ValidationError):
        parse_intent(text)
    valid = """
intent_id: fixture:time
title: timed DNS lookup
fields:
  - field: category
    paths: [semantics.category]
    operators:
      - name: eq
        value_json: '\"dns\"'
  - field: timestamp
    paths: [timestamp]
    operators:
      - name: exists
time_window:
  duration_ms: 5000
  timestamp_field: timestamp
  precision_digits: 3
"""
    result = analyze_intent(parse_intent(valid), (event(),))
    assert result.state == "unknown"
    assert any(item.field == "pending:time-window" for item in result.global_checks)


def test_unrepresentable_time_precision_is_unknown():
    text = """
intent_id: fixture:time-precision
title: precise timestamp
fields:
  - field: timestamp
    paths: [timestamp]
    operators:
      - name: exists
time_window:
  duration_ms: 1000
  timestamp_field: timestamp
  precision_digits: 4
"""
    result = analyze_intent(parse_intent(text), (event(),))
    assert any(item.code == "time_window_unrepresentable" for item in result.candidates[0].checks)


def test_sigma_subset_retains_level_and_technique_metadata():
    sigma = """
title: DNS Sigma subset
id: fixture:sigma
taxonomy: dvi
logsource:
  category: dns
detection:
  selection:
    dns_name|contains: example
  condition: selection
level: high
tags: [attack.t1071]
"""
    parsed = parse_intent(sigma, source_format="sigma_metadata")
    assert parsed.intent.technique_tags == ("attack.t1071",)
    assert parsed.intent.severity is not None and parsed.intent.severity.scope == "detection"
    assert not parsed.unsupported
    result = analyze_intent(parsed, (event(),))
    assert result.state == "unknown"  # output severity cannot be inferred from input telemetry
    assert any(item.code == "technique_tag_dropped" for item in result.candidates[0].checks)


def test_detection_output_severity_requires_detection_evidence():
    text = (
        NATIVE
        + """
severity:
  minimum: 4
  maximum: 4
  scope: detection
"""
    )
    parsed = parse_intent(text)
    plain = analyze_intent(parsed, (event(severity=4),))
    assert any(
        item.code == "severity_mismatch" and item.outcome == "unknown"
        for item in plain.candidates[0].checks
    )
    detection = DetectionEvent.model_validate(
        event(severity=4).model_dump()
        | {
            "detector": "fixture:detector",
            "signature": "fixture:signature",
            "title": "Fixture detection",
            "semantics": {"category": "alert", "action": "match"},
        }
    )
    checked = analyze_intent(parsed, (detection,))
    assert any(
        item.field == "severity" and item.outcome == "supported"
        for item in checked.candidates[0].checks
    )


def test_v1_rule_metadata_is_converted_and_pending_constraints_are_retained():
    rule = """
id: fixture:rule
detector: fixture:detector
signature: fixture:signature
title: fixture rule
conditions:
  - field: category
    operator: eq
    value: dns
severity: 4
min_count: 2
require_time_order: true
window_ms: 5000
"""
    parsed = parse_intent(rule, source_format="v1_rule")
    assert parsed.intent.severity is not None and parsed.intent.severity.scope == "detection"
    assert any(
        item.assumption_id == "rule-sequence-and-count" for item in parsed.intent.assumptions
    )
    assert analyze_intent(parsed, (event(),)).state == "unknown"


def test_yaml_loader_rejects_duplicate_and_anchor_content():
    with pytest.raises(ValueError):
        parse_local_yaml("title: a\ntitle: b\n", kind="intent")
    with pytest.raises(ValueError):
        parse_local_yaml("base: &x {value: 1}\ncopy: *x\n", kind="intent")


def test_nested_assumption_capability_fields_are_rejected():
    unsafe = (
        NATIVE
        + """
assumptions:
  - assumption_id: fixture:unsafe
    explanation: unsafe metadata
    detail_json: '{\"command\": \"echo blocked\"}'
"""
    )
    with pytest.raises(ValueError):
        parse_intent(unsafe)


def test_artifacts_are_canonical_and_link_actual_event_digest():
    parsed = parse_intent(NATIVE)
    files = intent_artifacts(parsed, (event(),))
    report = parse_json(files["semantic_loss_report.json"])
    assert report["candidates"][0]["event_id"] == "fixture:dns-1"
    assert report["candidates"][0]["event_digest"]
