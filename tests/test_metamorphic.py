"""Bounded interactions and transformations checked against real local detectors."""

from datetime import timedelta
from itertools import combinations, product
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dvi_sentinel.adapters import normalize
from dvi_sentinel.comparison import compare_snapshots, snapshot_from_plan
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import (
    FixtureResults,
    HarnessRequest,
    LocalRule,
    RuleCondition,
    RuleHarnessConfig,
)
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import evaluate_events
from dvi_sentinel.probes import run_probes
from dvi_sentinel.reductions import reductions, validate_reduction
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.scoring import summarize
from dvi_sentinel.serialization import canonical_json, digest
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.variation_models import EventLineage, VariationCase
from dvi_sentinel.variations import plan_variations

ROOT = Path(__file__).parents[1] / "examples"
EXPECTED = DetectionExpectation(detector="lab", signature="observation")


def original_events():
    return normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events


def detector(max_count=None):
    return RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic",
            rules=(
                LocalRule(
                    id="count",
                    detector="lab",
                    signature="observation",
                    title="Synthetic observation",
                    conditions=(RuleCondition(field="action", operator="eq", value="observed"),),
                    max_count=max_count,
                ),
            ),
        )
    )


def assessment(case, harness):
    result = harness.evaluate(HarnessRequest(case_id=case.id, events=case.events))
    return CaseAssessment(
        case_id=case.id,
        family=case.family,
        distance=case.distance,
        preservation=case.preservation,
        parser_success=True,
        match=match_detection(EXPECTED, result, case.events, preservation=case.preservation),
    )


# Eight fixed rows cover every pair of binary values across seven parameters.
# Columns: jitter, noise, duplicates, optional metadata, variants, budget, seed.
INTERACTIONS = (
    (0, 0, 0, 0, 0, 0, 0),
    (0, 0, 1, 0, 1, 1, 1),
    (0, 1, 0, 1, 0, 1, 1),
    (0, 1, 1, 1, 1, 0, 0),
    (1, 0, 0, 1, 1, 0, 1),
    (1, 0, 1, 1, 0, 1, 0),
    (1, 1, 0, 0, 1, 1, 0),
    (1, 1, 1, 0, 0, 0, 1),
)


def test_interaction_table_covers_each_pair_of_parameter_values():
    for left, right in combinations(range(7), 2):
        assert {(row[left], row[right]) for row in INTERACTIONS} == set(product((0, 1), repeat=2))


@pytest.mark.parametrize("row", INTERACTIONS)
def test_pairwise_limits_preserve_safe_robust_observations(row):
    jitter, noise, duplicates, optional, variants, budget, seed = row
    original = original_events()
    policy = VariationPolicy(
        families=("timing", "ordering", "metadata", "noise", "volume", "dropout"),
        max_jitter_ms=20 * jitter,
        max_noise_events=2 * noise,
        max_duplicates=2 * duplicates,
        optional_fields=("sensor", "vendor", "labels", "tags", "correlation_id")
        if optional
        else (),
        order_independent=True,
        max_variants=16 if variants else 1,
    )
    event_budget = 120 if budget else len(original)
    seed = 2**63 - 1 if seed else 0
    plan = plan_variations("interaction", original, policy, seed, event_budget=event_budget)
    assert canonical_json(plan) == canonical_json(
        plan_variations("interaction", original, policy, seed, event_budget=event_budget)
    )
    assert sum(len(c.events) for c in plan.cases) <= event_budget
    assert len(plan.cases) <= policy.max_variants
    harness = detector()
    rows = []
    for case in plan.cases:
        assert case.preservation == check_candidate(
            original, case.events, case.lineage, policy, case.family
        )
        assert case.preservation.valid and not evaluate_events(case.events)
        original_refs = [ref.original_event_id for ref in case.lineage if ref.role == "original"]
        assert sorted(original_refs) == sorted(e.event_id for e in original)
        assert sum(ref.role == "noise" for ref in case.lineage) <= policy.max_noise_events
        assert sum(ref.role == "duplicate" for ref in case.lineage) <= policy.max_duplicates
        rows.append(assessment(case, harness))
        assert rows[-1].match.status == "detected"
    score = summarize(tuple(rows))
    assert not score.findings and score.metrics.missed == score.metrics.unknown == 0
    assert score.metrics.detected == len(plan.cases) - 1


@settings(max_examples=16)
@given(st.integers(min_value=2, max_value=6), st.integers(min_value=0, max_value=5))
def test_duplicate_shrinker_reaches_threshold_and_no_further_safe_miss(limit, surplus):
    original = original_events()
    count = limit - len(original) + 1 + surplus
    additions = tuple(
        TelemetryEvent.model_validate(original[i % 2].model_dump() | {"event_id": f"copy:{i}"})
        for i in range(count)
    )
    refs = tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in original
    )
    refs += tuple(
        EventLineage(
            event_id=e.event_id, original_event_id=original[i % 2].event_id, role="duplicate"
        )
        for i, e in enumerate(additions)
    )
    policy = VariationPolicy(families=("volume",), max_duplicates=count)
    candidate = original + additions
    initial = VariationCase(
        id="initial",
        family="volume",
        parameters=(),
        events=candidate,
        lineage=refs,
        preservation=check_candidate(original, candidate, refs, policy, "volume"),
        distance=float(count),
    )
    harness = detector(limit)
    result = FailureShrinker(harness).shrink(original, initial, policy, EXPECTED)
    assert result.status == "minimized" and len(result.events) == limit + 1
    assert result.final.status == "missed" and result.final.reason == result.initial.reason
    assert result.preservation.valid and result.finding_class == "volume_sensitivity"
    assert all(
        t.preservation.valid and t.match.status == "missed"
        for t in result.trace
        if t.decision == "accepted"
    )
    assert canonical_json(result) == canonical_json(
        FailureShrinker(harness).shrink(original, initial, policy, EXPECTED)
    )
    for _, events, lineage in reductions(original, result.events, result.lineage, "volume", policy):
        assert validate_reduction(original, events, lineage, policy, "volume").valid
        match = match_detection(
            EXPECTED, harness.evaluate(HarnessRequest(case_id="ablation", events=events)), events
        )
        assert match.status == "detected"


@settings(max_examples=16)
@given(
    st.integers(min_value=0, max_value=999999),
    st.integers(min_value=0, max_value=65535),
    st.sampled_from(["192.0.2.10", "2001:db8::10"]),
)
def test_full_match_survives_cross_schema_endpoint_and_time_representations(
    microseconds, port, address
):
    base = normalize((ROOT / "telemetry/generic.jsonl").read_bytes(), "jsonl").events[-1]
    data = base.model_dump()
    data["semantics"]["source"] = {"address": address, "port": port}
    data["timestamp"] = base.timestamp.replace(microsecond=microseconds)
    original = (TelemetryEvent.model_validate(data),)
    report = run_differential(original, detector(), expected=EXPECTED)
    assert len(report.cases) == 3
    for case in report.cases:
        assert case.status == "agree" and not case.differences
        assert case.match.status == "detected"
        assert case.normalized.events[0].timestamp == original[0].timestamp
        assert case.normalized.events[0].semantics == original[0].semantics


@settings(max_examples=12)
@given(st.integers(min_value=0, max_value=2**63 - 1))
def test_real_regression_and_recovery_are_symmetric_across_planner_seeds(seed):
    original = original_events()
    plan = plan_variations(
        "regression",
        original,
        VariationPolicy(families=("volume",), max_duplicates=4, max_variants=6),
        seed,
    )
    snapshots = []
    for limit in (None, 2):
        harness = detector(limit)
        snapshots.append(
            snapshot_from_plan(
                plan,
                tuple(assessment(case, harness) for case in plan.cases),
                scenario_digest=digest("same scenario"),
                detector_digest=digest({"count_rule_limit": limit}),
            )
        )
    robust, fragile = snapshots
    loss = compare_snapshots(robust, fragile)
    recovery = compare_snapshots(fragile, robust)
    assert loss.status == "regressed" and recovery.status == "passed"
    assert len(loss.newly_missed) == len(plan.cases) - 1
    assert recovery.recovered == loss.newly_missed and not recovery.newly_missed
    assert (
        loss.new_fragility_classes == recovery.removed_fragility_classes == ("volume_sensitivity",)
    )


@settings(max_examples=12)
@given(st.integers(min_value=0, max_value=999999))
def test_full_match_probe_controls_separate_measured_and_missing_evidence(microseconds):
    original = tuple(
        TelemetryEvent.model_validate(
            e.model_dump() | {"timestamp": e.timestamp + timedelta(microseconds=microseconds)}
        )
        for e in original_events()
    )
    policy = VariationPolicy(
        families=("ordering", "dropout", "noise", "volume"),
        order_independent=True,
        max_noise_events=2,
        max_duplicates=2,
        optional_fields=("sensor", "correlation_id", "labels", "tags"),
    )
    robust = run_probes(original, policy, detector(), expected=EXPECTED)
    assert any(p.observed_result == "robust" for p in robust)
    assert all(p.observed_result in {"robust", "not_applicable"} for p in robust)
    missing = run_probes(
        original, policy, FixtureHarness(FixtureResults(cases=())), expected=EXPECTED
    )
    assert any(p.observed_result == "unknown" for p in missing)
    assert all(p.observed_result in {"unknown", "not_applicable"} for p in missing)
    assert not summarize((), probes=missing).findings
