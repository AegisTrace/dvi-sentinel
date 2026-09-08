from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from dvi_sentinel.harness import FixtureHarness, HarnessError, RuleLogicHarness
from dvi_sentinel.harness_models import (
    FixtureCase,
    FixtureResults,
    HarnessRequest,
    LocalRule,
    RuleCondition,
    RuleHarnessConfig,
)
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.scenario_io import load_scenario
from dvi_sentinel.serialization import canonical_json

EXAMPLES = Path(__file__).parents[1] / "examples"


def event(event_id: str = "a", offset_ms: int = 0, **updates: object) -> TelemetryEvent:
    base = TelemetryEvent.model_validate_json((EXAMPLES / "canonical_event.json").read_text())
    return TelemetryEvent.model_validate(
        base.model_dump()
        | {
            "event_id": event_id,
            "timestamp": base.timestamp + timedelta(milliseconds=offset_ms),
        }
        | updates
    )


def config(**updates: object) -> RuleHarnessConfig:
    rule = {
        "id": "rule:1",
        "detector": "lab",
        "signature": "synthetic",
        "title": "Synthetic flow",
        "conditions": [{"field": "category", "operator": "eq", "value": "flow"}],
    }
    return RuleHarnessConfig.model_validate({"kind": "rule_logic", "rules": [rule | updates]})


def test_real_rule_observation_and_determinism() -> None:
    harness = RuleLogicHarness(config(delay_ms=20, labels=["lab"]))
    request = HarnessRequest(case_id="baseline", events=(event(),))
    result = harness.evaluate(request)
    assert result.status == "complete"
    assert result.issues == ()
    assert result.traces[0].reason == "RULE_MATCH"
    assert result.detections[0].related_event_ids == ("a",)
    assert result.detections[0].timestamp - request.events[0].timestamp == timedelta(
        milliseconds=20
    )
    assert result.detections[0].labels == ("lab",)
    assert canonical_json(result) == canonical_json(harness.evaluate(request))
    assert request.events[0].event_id == "a"


@pytest.mark.parametrize(
    "updates,events,reason",
    [
        ({"min_count": 2}, (event(),), "RULE_COUNT_MISS"),
        ({"max_count": 1}, (event(), event("b")), "RULE_COUNT_MISS"),
        ({"max_total_events": 1}, (event(), event("b")), "RULE_COUNT_MISS"),
        ({"require_time_order": True}, (event("b", 10), event()), "RULE_ORDER_MISS"),
        ({"window_ms": 5}, (event(), event("b", 6)), "RULE_WINDOW_MISS"),
        ({}, (), "RULE_CONDITION_MISS"),
    ],
)
def test_explicit_local_rule_misses(updates: dict, events: tuple, reason: str) -> None:
    result = RuleLogicHarness(config(**updates)).evaluate(
        HarnessRequest(case_id="x", events=events)
    )
    assert result.status == "complete"
    assert result.detections == ()
    assert result.traces[0].reason == reason


@pytest.mark.parametrize(
    "field,operator,value,matched",
    [
        ("raw.count", "gte", 2, True),
        ("raw.count", "eq", 2, True),
        ("raw.count", "eq", True, False),
        ("raw.flag", "gte", 1, False),
        ("raw.nested.name", "contains", "afe", True),
        ("raw.nested.missing", "exists", None, False),
        ("raw.count.name", "exists", None, False),
        ("sensor", "exists", None, True),
        ("labels", "contains", "lab", True),
        ("timestamp_text", "contains", "+03:00", True),
        ("severity", "gte", 1, False),
    ],
)
def test_condition_semantics(field: str, operator: str, value: object, matched: bool) -> None:
    raw = RawSource.from_payload(
        {"count": 2, "flag": True, "nested": {"name": "safe"}},
        adapter="jsonl",
        sensor="lab",
        original_timestamp="+03:00",
    )
    harness = RuleLogicHarness(
        config(conditions=[{"field": field, "operator": operator, "value": value}])
    )
    result = harness.evaluate(HarnessRequest(case_id="x", events=(event(raw=raw, labels=["lab"]),)))
    assert bool(result.detections) == matched
    assert result.status == "complete"


def test_order_independent_rule_keeps_stable_output() -> None:
    harness = RuleLogicHarness(config())
    first = harness.evaluate(HarnessRequest(case_id="x", events=(event(), event("b", 2))))
    second = harness.evaluate(HarnessRequest(case_id="x", events=(event("b", 2), event())))
    assert first == second


def test_fixture_observed_miss_is_distinct_from_missing_data(tmp_path: Path) -> None:
    observed = RuleLogicHarness(config()).evaluate(HarnessRequest(case_id="hit", events=(event(),)))
    payload = FixtureResults(
        cases=(
            FixtureCase(case_id="hit", detections=observed.detections),
            FixtureCase(case_id="miss", detections=()),
        )
    )
    (tmp_path / "results.json").write_text(canonical_json(payload), encoding="utf-8")
    harness = FixtureHarness.from_file(tmp_path, "results.json")
    hit = harness.evaluate(HarnessRequest(case_id="hit", events=(event(),)))
    miss = harness.evaluate(HarnessRequest(case_id="miss", events=(event(),)))
    unknown = harness.evaluate(HarnessRequest(case_id="absent", events=(event(),)))
    assert hit.detections == observed.detections
    assert miss.status == "complete" and miss.detections == ()
    assert unknown.status == "unknown" and unknown.issues[0].code == "DVI-HARNESS-NO-FIXTURE"


@pytest.mark.parametrize(
    "text",
    [
        "{}",
        "[]",
        "broken",
        '{"cases":[],"cases":[]}',
        '{"cases":[{"case_id":"x","detections":[{}]}]}',
    ],
)
def test_malformed_result_fixtures(tmp_path: Path, text: str) -> None:
    (tmp_path / "results.json").write_text(text, encoding="utf-8")
    with pytest.raises(HarnessError, match="DVI-HARNESS-MALFORMED"):
        FixtureHarness.from_file(tmp_path, "results.json")


@pytest.mark.parametrize(
    "harness", [RuleLogicHarness(config()), FixtureHarness(FixtureResults(cases=()))]
)
def test_unsupported_unsafe_and_duplicate_inputs(harness: object) -> None:
    unsupported = harness.evaluate(
        HarnessRequest(case_id="x", events=(), capability="live_detector")
    )
    assert unsupported.status == "unknown"
    assert unsupported.issues[0].code == "DVI-HARNESS-UNSUPPORTED"
    duplicate = harness.evaluate(HarnessRequest(case_id="x", events=(event(), event())))
    assert duplicate.issues[0].code == "DVI-HARNESS-DUPLICATE-ID"
    unsafe = event(raw=RawSource.from_payload({"command": "inert"}, adapter="jsonl"))
    rejected = harness.evaluate(HarnessRequest(case_id="x", events=(unsafe,)))
    assert rejected.issues[0].code == "DVI-HARNESS-POLICY"
    assert rejected.detections == ()


@pytest.mark.parametrize(
    "data",
    [
        {"field": "__class__", "operator": "exists"},
        {"field": "raw.a[0]", "operator": "exists"},
        {"field": "sensor", "operator": "regex", "value": "x"},
        {"field": "sensor", "operator": "exists", "value": "x"},
        {"field": "severity", "operator": "gte", "value": "x"},
        {"field": "severity", "operator": "eq"},
    ],
)
def test_rule_contract_rejects_unsupported_operations(data: dict) -> None:
    with pytest.raises(ValidationError):
        RuleCondition.model_validate(data)


def test_duplicate_rules_cases_and_bad_counts() -> None:
    rule = config().rules[0]
    with pytest.raises(ValidationError, match="duplicate rule"):
        RuleHarnessConfig(kind="rule_logic", rules=(rule, rule))
    case = FixtureCase(case_id="x", detections=())
    with pytest.raises(ValidationError, match="duplicate fixture"):
        FixtureResults(cases=(case, case))
    with pytest.raises(ValidationError, match="max_count"):
        LocalRule.model_validate(rule.model_dump() | {"min_count": 3, "max_count": 2})


def test_scenario_declares_real_harness() -> None:
    scenario, _ = load_scenario(EXAMPLES / "foundation_scenario.yaml")
    assert scenario.harness.kind == "rule_logic"
    result = RuleLogicHarness(scenario.harness).evaluate(
        HarnessRequest(case_id="baseline", events=(event(),))
    )
    assert result.detections[0].signature == scenario.expected.signature


def test_output_policy_and_timestamp_overflow_are_unknown() -> None:
    unsafe = RuleLogicHarness(config(title="https://real-service.com"))
    result = unsafe.evaluate(HarnessRequest(case_id="x", events=(event(),)))
    assert result.status == "unknown" and result.issues[0].code == "DVI-HARNESS-POLICY"
    overflow = RuleLogicHarness(config(delay_ms=1000))
    result = overflow.evaluate(
        HarnessRequest(case_id="x", events=(event(timestamp="9999-12-31T23:59:59.999999Z"),))
    )
    assert result.status == "unknown" and result.issues[0].code == "DVI-HARNESS-MALFORMED"


def test_fixture_rejects_unsafe_output_and_duplicate_detection_ids() -> None:
    result = RuleLogicHarness(config()).evaluate(HarnessRequest(case_id="x", events=(event(),)))
    detection = result.detections[0]
    with pytest.raises(ValidationError, match="duplicate detection"):
        FixtureCase(case_id="x", detections=(detection, detection))
    from dvi_sentinel.models import DetectionEvent

    unsafe = DetectionEvent.model_validate(
        detection.model_dump()
        | {
            "raw": RawSource.from_payload({"credentials": "inert"}, adapter="jsonl"),
        }
    )
    harness = FixtureHarness(
        FixtureResults(cases=(FixtureCase(case_id="x", detections=(unsafe,)),))
    )
    result = harness.evaluate(HarnessRequest(case_id="x", events=(event(),)))
    assert result.status == "unknown" and result.issues[0].code == "DVI-HARNESS-POLICY"
