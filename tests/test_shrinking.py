from datetime import timedelta
from pathlib import Path

import pytest

from dvi_sentinel.adapters import normalize
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import (
    FixtureCase,
    FixtureResults,
    HarnessRequest,
    LocalRule,
    RuleHarnessConfig,
)
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.probe_transforms import specifications, transform
from dvi_sentinel.reductions import validate_reduction
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json, parse_json
from dvi_sentinel.shrinking import FailureShrinker, shrink_artifacts
from dvi_sentinel.shrinking_models import MinimalCounterexample
from dvi_sentinel.variation_models import EventLineage, VariationCase
from dvi_sentinel.variations import plan_variations

ROOT = Path(__file__).parents[1] / "examples"


def originals():
    return normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events


def harness(**changes):
    rule = LocalRule.model_validate(
        {
            "id": "rule",
            "detector": "lab",
            "signature": "expected",
            "title": "Local reduction proof",
            "conditions": [{"field": "action", "operator": "eq", "value": "observed"}],
        }
        | changes
    )
    return RuleLogicHarness(RuleHarnessConfig(kind="rule_logic", rules=(rule,)))


def expectation(**changes):
    return DetectionExpectation.model_validate(
        {"detector": "lab", "signature": "expected"} | changes
    )


def lineage(events):
    return tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in events
    )


def case(original, candidate, policy, family):
    refs = lineage(original)
    return VariationCase(
        id="initial",
        family=family,
        parameters=(),
        events=candidate,
        lineage=refs,
        preservation=check_candidate(original, candidate, refs, policy, family),
        distance=1.0,
    )


@pytest.mark.parametrize(
    ("family", "rule", "minimum_added"),
    [
        ("volume", {"max_count": 3}, 2),
        ("noise", {"max_total_events": 2}, 1),
    ],
)
def test_complex_added_events_reduce_to_known_minimum(family, rule, minimum_added):
    original = originals()
    policy = VariationPolicy(
        families=(family,), max_duplicates=6, max_noise_events=6, max_variants=40
    )
    plan = plan_variations("shrink-proof", original, policy, 42)
    initial = max(plan.cases, key=lambda c: len(c.events))
    assert len(initial.events) >= len(original) + 4
    engine = FailureShrinker(harness(**rule))
    result = engine.shrink(original, initial, policy, expectation())
    assert result.status == "minimized" and len(result.events) == len(original) + minimum_added
    assert result.final.status == "missed" and result.initial.reason == result.final.reason
    assert result.preservation.valid
    assert all(a.association == "necessary_in_fixture" for a in result.root_cause.ranked)
    assert {e.event_id for e in original} <= {e.event_id for e in result.events}
    assert canonical_json(result) == canonical_json(
        engine.shrink(original, initial, policy, expectation())
    )
    assert MinimalCounterexample.model_validate_json(canonical_json(result)) == result
    artifacts = shrink_artifacts(result)
    assert set(artifacts) == {
        "minimal_case.json",
        "minimal_case.md",
        "shrinking_trace.jsonl",
        "root_cause.json",
    }
    assert parse_json(artifacts["minimal_case.json"])["status"] == "minimized"


def test_jitter_minimizes_to_exact_failure_boundary_without_changing_meaning():
    original = originals()
    policy = VariationPolicy(families=("timing",), max_jitter_ms=100)
    changed = tuple(
        TelemetryEvent.model_validate(
            e.model_dump()
            | {
                "timestamp": e.timestamp + timedelta(milliseconds=80),
            }
        )
        for e in original
    )
    expected = expectation(reference_time=original[-1].timestamp, max_delay_ms=10)
    result = FailureShrinker(harness()).shrink(
        original, case(original, changed, policy, "timing"), policy, expected
    )
    assert result.status == "minimized"
    assert result.events[0].timestamp == original[0].timestamp
    assert result.events[1].timestamp - original[1].timestamp == timedelta(microseconds=10001)
    assert result.final.reason == "DVI-MATCH-LATE" and result.final.alert_delay_ms == 10.001
    assert len(result.trace) <= 128 and all(
        e.semantics == original[0].semantics for e in result.events
    )
    assert result.root_cause.ranked[0].association == "necessary_in_fixture"


@pytest.mark.parametrize(
    ("name", "family", "condition", "kind"),
    [
        (
            "name:sensor",
            "metadata",
            {"field": "sensor", "operator": "eq", "value": "lab-sensor"},
            "optional_field_dependency",
        ),
        (
            "drop:correlation_id",
            "dropout",
            {"field": "correlation_id", "operator": "eq", "value": "123"},
            "correlation_key_dependency",
        ),
        ("schema_alias", "metadata", {"field": "raw.src_ip", "operator": "exists"}, "schema"),
    ],
)
def test_metadata_and_source_probes_preserve_class_and_reduce_to_one_record(
    name, family, condition, kind
):
    original = originals()
    policy = VariationPolicy(families=(family,), optional_fields=("sensor", "correlation_id"))
    spec = next(s for s in specifications() if s.name == name)
    candidate, refs, preservation = transform(spec, original, policy)
    initial = VariationCase(
        id="probe-case",
        family=family,
        parameters=(),
        events=candidate,
        lineage=refs,
        preservation=preservation,
        distance=2.0,
    )
    result = FailureShrinker(harness(conditions=[condition], min_count=2)).shrink(
        original,
        initial,
        policy,
        expectation(),
        probe=spec,
    )
    assert result.status == "minimized" and result.finding_class == kind
    assert sum(left != right for left, right in zip(original, result.events, strict=True)) == 1
    assert result.root_cause.ranked[0].association == "necessary_in_fixture"
    assert result.preservation.valid


def test_ordering_reduces_to_one_inversion_with_explicit_permission():
    original = (
        *originals(),
        *(
            TelemetryEvent.model_validate(
                originals()[1].model_dump()
                | {
                    "event_id": f"extra:{i}",
                    "timestamp": originals()[1].timestamp + timedelta(seconds=i),
                }
            )
            for i in (1, 2)
        ),
    )
    policy = VariationPolicy(families=("ordering",), order_independent=True)
    initial = case(original, tuple(reversed(original)), policy, "ordering")
    result = FailureShrinker(harness(require_time_order=True)).shrink(
        original, initial, policy, expectation()
    )
    assert result.status == "minimized"
    order = [e.timestamp for e in result.events]
    assert sum(a > b for i, a in enumerate(order) for b in order[i + 1 :]) == 1
    assert result.root_cause.ranked[0].association == "necessary_in_fixture"


def test_invalid_reductions_cannot_drop_original_intent_or_hide_unsafe_data():
    original = originals()
    policy = VariationPolicy(families=("ordering",), order_independent=True)
    checked = validate_reduction(original, original[1:], lineage(original)[1:], policy, "ordering")
    assert (
        not checked.valid
        and not next(c for c in checked.checks if c.id == "DVI-INV-COVERAGE").passed
    )
    unsafe = (
        TelemetryEvent.model_validate(
            original[0].model_dump()
            | {
                "raw": RawSource.from_payload({"command": "inert"}, adapter="jsonl"),
            }
        ),
        original[1],
    )
    result = FailureShrinker(harness()).shrink(
        original, case(original, unsafe, policy, "ordering"), policy, expectation()
    )
    assert result.status == "invalid" and not result.trace and result.initial is None
    assert result.root_cause.status == "not_applicable"


def test_robust_and_budget_limited_cases_never_invent_a_minimum_or_cause():
    original = originals()
    policy = VariationPolicy(families=("ordering",), order_independent=True)
    initial = case(original, tuple(reversed(original)), policy, "ordering")
    robust = FailureShrinker(harness()).shrink(original, initial, policy, expectation())
    assert robust.status == "not_a_failure" and not robust.root_cause.ranked
    bounded = FailureShrinker(harness(require_time_order=True)).shrink(
        original,
        initial,
        policy,
        expectation(),
        max_attempts=0,
        max_ablations=0,
    )
    assert bounded.status == "budget_exhausted" and not bounded.trace
    assert bounded.root_cause.status == "unknown" and bounded.root_cause.budget_exhausted


def test_missing_reduction_fixture_keeps_minimality_unknown():
    original = (
        *originals(),
        TelemetryEvent.model_validate(
            originals()[-1].model_dump()
            | {
                "event_id": "third",
                "timestamp": originals()[-1].timestamp + timedelta(seconds=1),
            }
        ),
    )
    policy = VariationPolicy(families=("ordering",), order_independent=True)
    initial = case(original, tuple(reversed(original)), policy, "ordering")
    observations = harness(require_time_order=True)
    fixture = FixtureHarness(
        FixtureResults(
            cases=(
                FixtureCase(
                    case_id="baseline",
                    detections=observations.evaluate(
                        HarnessRequest(case_id="baseline", events=original)
                    ).detections,
                ),
                FixtureCase(case_id="initial", detections=()),
            )
        )
    )
    result = FailureShrinker(fixture).shrink(original, initial, policy, expectation())
    assert result.status == "unknown" and result.final.status == "missed"
    assert all(step.decision == "unknown" for step in result.trace)
    assert all(a.association == "unknown" for a in result.root_cause.ranked)


def test_identical_input_cannot_create_a_counterexample_from_case_lookup_alone():
    original = originals()
    policy = VariationPolicy(families=("ordering",), order_independent=True)
    initial = case(original, original, policy, "ordering")
    result = FailureShrinker(harness()).shrink(original, initial, policy, expectation())
    assert result.status == "invalid" and not result.root_cause.ranked


def test_nonessential_metadata_fields_are_restored():
    original = originals()
    policy = VariationPolicy(families=("metadata",), optional_fields=("sensor", "vendor"))
    changed = tuple(
        TelemetryEvent.model_validate(
            e.model_dump()
            | {
                "raw": RawSource.model_validate(
                    e.raw.model_dump()
                    | {
                        "sensor": "fixture-sensor-alias",
                        "vendor": "fixture-sensor-alias",
                    }
                ),
            }
        )
        for e in original
    )
    detector = harness(
        conditions=[{"field": "sensor", "operator": "eq", "value": "lab-sensor"}], min_count=2
    )
    result = FailureShrinker(detector).shrink(
        original, case(original, changed, policy, "metadata"), policy, expectation()
    )
    assert result.status == "minimized"
    assert all(e.raw.vendor == "synthetic" for e in result.events)
    assert sum(e.raw.sensor != "lab-sensor" for e in result.events) == 1
