import random
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dvi_sentinel.adapters import normalize
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.scenario_io import load_scenario
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.variation_models import EventLineage, VariationPlan
from dvi_sentinel.variations import plan_variations

EXAMPLES = Path(__file__).parents[1] / "examples"


def events() -> tuple[TelemetryEvent, ...]:
    return normalize((EXAMPLES / "telemetry" / "generic.jsonl").read_bytes(), "jsonl").events


def policy(**changes: object) -> VariationPolicy:
    return VariationPolicy.model_validate(
        {
            "families": ["timing", "ordering", "metadata", "noise", "volume", "dropout"],
            "max_variants": 40,
            "max_jitter_ms": 20,
            "max_noise_events": 3,
            "max_duplicates": 3,
            "order_independent": True,
            "optional_fields": ["sensor", "vendor", "tags", "labels", "correlation_id"],
        }
        | changes
    )


def lineage(original: tuple[TelemetryEvent, ...]) -> tuple[EventLineage, ...]:
    return tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in original
    )


def failures(result: object) -> set[str]:
    return {check.id for check in result.checks if not check.passed}


def test_all_families_have_real_valid_transformations() -> None:
    original = events()
    snapshot = canonical_json([e.model_dump(mode="json") for e in original])
    plan = plan_variations("example", original, policy(), 7)
    assert {case.family for case in plan.valid_cases} == {"baseline", *policy().families}
    assert len(plan.cases) <= policy().max_variants
    assert len({case.id for case in plan.cases}) == len(plan.cases)
    assert all(case.preservation.valid for case in plan.cases)
    assert all(
        strategy.allowed_changes and strategy.protected_invariants for strategy in plan.strategies
    )
    assert canonical_json([e.model_dump(mode="json") for e in original]) == snapshot
    for case in plan.cases:
        by_id = {e.event_id: e for e in original}
        for reference in case.lineage:
            if reference.original_event_id:
                changed = next(e for e in case.events if e.event_id == reference.event_id)
                assert changed.semantics == by_id[reference.original_event_id].semantics
                assert changed.raw.raw_digest == by_id[reference.original_event_id].raw.raw_digest


def test_determinism_roundtrip_and_no_global_rng_mutation() -> None:
    state = random.getstate()
    first = plan_variations("example", events(), policy(), 123)
    second = plan_variations("example", events(), policy(), 123)
    assert canonical_json(first) == canonical_json(second)
    assert VariationPlan.model_validate_json(canonical_json(first)) == first
    assert random.getstate() == state
    changed = plan_variations("example", events(), policy(), 124)
    assert first.input_digest == changed.input_digest
    assert first.cases[1:] != changed.cases[1:]


@settings(max_examples=20, deadline=None, derandomize=True)
@given(st.integers(min_value=0, max_value=2**32), st.integers(min_value=0, max_value=100))
def test_seeded_bounds_and_semantic_preservation(seed: int, bound: int) -> None:
    config = policy(max_variants=8, max_jitter_ms=bound)
    plan = plan_variations("example", events(), config, seed)
    assert all(case.preservation.valid for case in plan.cases)
    assert canonical_json(plan) == canonical_json(
        plan_variations("example", events(), config, seed)
    )
    assert all(len(case.events) <= len(events()) + 3 for case in plan.cases)


def test_baseline_only_and_noop_termination() -> None:
    baseline = plan_variations("x", events(), VariationPolicy(), 0)
    assert len(baseline.cases) == 1 and baseline.cases[0].preservation.valid
    noop = plan_variations("x", events(), policy(families=["timing"], max_jitter_ms=0), 0)
    assert len(noop.cases) == 1
    assert noop.attempted == noop.skipped_noop == 4 * policy().max_variants


@pytest.mark.parametrize("seed", [-1, True, 1.5, "1", 2**63])
def test_invalid_seeds(seed: object) -> None:
    with pytest.raises(ValueError, match="DVI-VAR-SEED"):
        plan_variations("x", events(), policy(), seed)


def test_invalid_baseline_rejected() -> None:
    with pytest.raises(ValueError, match="DVI-VAR-INPUT"):
        plan_variations("x", (), policy(), 0)
    with pytest.raises(ValueError, match="DVI-VAR-INPUT"):
        plan_variations("x", (events()[0], events()[0]), policy(), 0)
    unsafe = TelemetryEvent.model_validate(
        events()[0].model_dump()
        | {
            "raw": RawSource.from_payload({"command": "inert"}, adapter="jsonl"),
        }
    )
    with pytest.raises(PolicyError):
        plan_variations("x", (unsafe,), policy(), 0)


def test_independent_protected_semantics_and_policy_rejection() -> None:
    original = events()
    data = original[0].model_dump()
    data["semantics"]["source"]["address"] = "8.8.8.8"
    candidate = (TelemetryEvent.model_validate(data), *original[1:])
    result = check_candidate(original, candidate, lineage(original), policy(), "metadata")
    assert {"DVI-INV-PROTECTED", "DVI-INV-POLICY"} <= failures(result)


def test_independent_timing_and_observation_delay_checks() -> None:
    first = TelemetryEvent.model_validate(
        events()[0].model_dump()
        | {
            "observed_at": events()[0].timestamp + timedelta(milliseconds=20),
        }
    )
    original = (first,)
    candidate = (
        TelemetryEvent.model_validate(
            first.model_dump()
            | {
                "timestamp": first.timestamp + timedelta(milliseconds=21),
            }
        ),
    )
    assert "DVI-INV-TIMING" in failures(
        check_candidate(original, candidate, lineage(original), policy(), "timing")
    )
    plan = plan_variations("x", original, policy(families=["timing"]), 1)
    assert all(
        case.events[0].observed_at - case.events[0].timestamp == timedelta(milliseconds=20)
        for case in plan.cases
    )


def test_ordering_requires_explicit_permission() -> None:
    original = events()
    result = check_candidate(
        original,
        tuple(reversed(original)),
        lineage(original),
        policy(order_independent=False),
        "ordering",
    )
    assert "DVI-INV-ORDER" in failures(result)
    plan = plan_variations("x", original, policy(families=["ordering"], order_independent=False), 1)
    assert all(not c.preservation.valid for c in plan.cases[1:])
    assert [c.id for c in plan.valid_cases] == ["baseline"]


def test_dropout_cannot_change_or_drop_protected_fields() -> None:
    original = events()
    modified = TelemetryEvent.model_validate(original[0].model_dump() | {"labels": ["different"]})
    result = check_candidate(
        original, (modified, *original[1:]), lineage(original), policy(), "dropout"
    )
    assert "DVI-INV-TRANSFORM" in failures(result)
    removed = TelemetryEvent.model_validate(original[0].model_dump() | {"labels": []})
    result = check_candidate(
        original,
        (removed, *original[1:]),
        lineage(original),
        policy(optional_fields=["sensor"]),
        "dropout",
    )
    assert "DVI-INV-PROTECTED" in failures(result)


def test_lineage_and_noise_cannot_disguise_event_loss() -> None:
    original = events()
    result = check_candidate(original, original[1:], lineage(original)[1:], policy(), "noise")
    assert "DVI-INV-COVERAGE" in failures(result)
    forged = (
        *lineage(original)[:-1],
        EventLineage(event_id=original[-1].event_id, original_event_id=None, role="noise"),
    )
    result = check_candidate(original, original, forged, policy(), "noise")
    assert {"DVI-INV-NOISE", "DVI-INV-COVERAGE"} <= failures(result)


def test_planned_cases_execute_real_local_rule() -> None:
    scenario, _ = load_scenario(EXAMPLES / "foundation_scenario.yaml")
    assert scenario.harness.kind == "rule_logic"
    harness = RuleLogicHarness(scenario.harness)
    plan = plan_variations(scenario.metadata.id, events(), scenario.variations, 42)
    for case in plan.valid_cases:
        result = harness.evaluate(HarnessRequest(case_id=case.id, events=case.events))
        assert result.status == "complete" and result.detections


def test_timestamp_overflow_is_counted_and_bounded() -> None:
    far_future = TelemetryEvent.model_validate(
        events()[0].model_dump()
        | {
            "timestamp": "9999-12-31T23:59:59.999999Z",
        }
    )
    plan = plan_variations("x", (far_future,), policy(families=["timing"], max_variants=20), 1)
    assert plan.skipped_invalid > 0
    assert any(item.code == "DVI-VAR-OVERFLOW" for item in plan.omissions)
    assert all(case.preservation.valid for case in plan.cases)


def test_total_event_budget_is_enforced_and_part_of_configuration() -> None:
    small = plan_variations("x", events(), policy(families=["timing"]), 1, event_budget=6)
    larger = plan_variations("x", events(), policy(families=["timing"]), 1, event_budget=12)
    assert len(small.cases) == 1 and small.event_budget_exhausted
    assert small.omissions[-1].code == "DVI-VAR-EVENT-BUDGET"
    assert sum(len(c.events) for c in larger.cases) <= 12
    assert small.config_digest != larger.config_digest
    with pytest.raises(ValueError, match="DVI-VAR-BUDGET"):
        plan_variations("x", events(), policy(), 1, event_budget=1)
