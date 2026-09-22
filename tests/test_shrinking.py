import json
import runpy
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.adapters import normalize
from dvi_sentinel.consensus_shrinking import oracle_shrink_artifacts, shrink_with_oracles
from dvi_sentinel.consensus_shrinking_models import (
    OracleShrinkBudget,
    OracleShrinkInput,
    OracleShrinkReport,
    consensus_signature,
    event_digest,
)
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import (
    FixtureCase,
    FixtureResults,
    HarnessRequest,
    LocalRule,
    RuleCondition,
    RuleHarnessConfig,
)
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_models import OracleDecision, OracleResult
from dvi_sentinel.probe_transforms import specifications, transform
from dvi_sentinel.reductions import reduction_cost, scoped_reductions, validate_reduction
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


ORACLE_EXAMPLE = ROOT / "oracle_shrinking.py"
oracle_fixture = runpy.run_path(str(ORACLE_EXAMPLE))["fixture"]


def oracle_update(request, **changes):
    return OracleShrinkInput.model_validate(request.model_dump(mode="python") | changes)


def oracle_shrink(request=None):
    request = request or oracle_fixture()
    return shrink_with_oracles(request, expected_digest=request.stable_digest())


@pytest.mark.parametrize("mode", ["metadata", "timing", "alias", "correlation"])
def test_oracle_shrinker_minimizes_actual_changes_and_preserves_all_nine_checks(mode):
    request = oracle_fixture(mode)
    result = oracle_shrink(request)
    assert result.state == "minimized" and len(result.final.events) == 1
    assert result.final.events[0].event_id == request.protected_event_ids[0]
    assert result.baseline.match.status == "detected"
    assert result.initial.match.reason == result.final.match.reason == "DVI-MATCH-LATE"
    assert result.final.consensus.state == "confirmed"
    assert len(result.final.consensus.decisions) == 9
    assert consensus_signature(result.initial.consensus) == consensus_signature(
        result.final.consensus
    )
    if mode == "metadata":
        assert result.final.events[0].raw.sensor == "FIXTURE:SENSOR"
        assert result.final.events[0].raw.vendor == "FixtureLab"
    elif mode == "timing":
        assert result.final.events[0].timestamp - request.original[0].timestamp == timedelta(
            microseconds=10001
        )
    elif mode == "alias":
        assert "source_ip" in result.final.events[0].raw.payload
        assert "src_ip" not in result.final.events[0].raw.payload
    else:
        assert result.final.events[0].correlation_id is None
    parent = request.case.events
    refs = request.case.lineage
    for step in result.trace:
        assert step.parent_digest == event_digest(parent)
        if step.decision == "accepted":
            assert step.preservation.valid
            assert step.cost < reduction_cost(request.original, parent, refs)
            assert step.baseline.match.status == "detected"
            assert request.finding_class in step.changed_classes
            parent, refs = step.candidate.events, step.lineage
    assert parent == result.final.events


def test_oracle_shrinker_records_proposals_and_content_cache_exactly(monkeypatch):
    request = oracle_fixture(count=3)
    generated = []
    observed = []
    actual = RuleLogicHarness.evaluate

    def recording_proposals(*args, **kwargs):
        for row in scoped_reductions(*args, **kwargs):
            generated.append((row[0], event_digest(row[1])))
            yield row

    def recording_observation(self, request):
        observed.append(event_digest(request.events))
        return actual(self, request)

    monkeypatch.setattr("dvi_sentinel.consensus_shrinking.scoped_reductions", recording_proposals)
    monkeypatch.setattr(RuleLogicHarness, "evaluate", recording_observation)
    result = oracle_shrink(request)
    assert generated == [(s.reduction, s.candidate_digest) for s in result.trace]
    assert len(observed) == len(set(observed)) == result.evaluations
    assert len([s.baseline.evaluation for s in result.trace if s.baseline]) > len(
        {s.baseline.evaluation for s in result.trace if s.baseline}
    )


def test_oracle_event_deletion_requires_actual_surviving_baseline_detection():
    request = oracle_fixture(count=3)
    rules = tuple(rule.model_copy(update={"min_count": 2}) for rule in request.harness.rules)
    result = oracle_shrink(
        oracle_update(request, harness=request.harness.model_copy(update={"rules": rules}))
    )
    # A one-event control no longer alerts: timing becomes unknown, so stop immediately.
    assert result.state == "unknown" and len(result.trace) == 1
    assert result.trace[0].baseline.match.status == "missed"
    assert result.trace[0].candidate is None
    assert result.final == result.initial and len(result.final.events) == 3


def test_oracle_shrinker_never_removes_other_explicitly_protected_events():
    request = oracle_fixture(count=4)
    protected = (request.original[0].event_id, request.original[-1].event_id)
    result = oracle_shrink(oracle_update(request, protected_event_ids=protected))
    assert result.state == "minimized"
    assert {e.event_id for e in result.final.events} == set(protected)


def test_oracle_chunk_rejection_falls_back_to_smaller_event_reductions():
    request = oracle_fixture(count=4)
    rules = tuple(
        rule.model_copy(update={"min_count": 2}) if rule.id == "fixture:timely" else rule
        for rule in request.harness.rules
    )
    result = oracle_shrink(
        oracle_update(request, harness=request.harness.model_copy(update={"rules": rules}))
    )
    assert result.state == "minimized" and len(result.final.events) == 2
    first = result.trace[0]
    assert first.decision == "rejected" and first.baseline.match.status == "missed"
    assert first.baseline.consensus.state == "confirmed" and first.candidate is None
    assert any(
        s.decision == "accepted" and s.reduction.startswith("remove_events:") for s in result.trace
    )
    assert sum(e.raw.sensor != "fixture:sensor" for e in result.final.events) == 1


def test_oracle_protected_identity_guard_is_independent_of_proposal_generator(monkeypatch):
    request = oracle_fixture(count=2)

    def invalid_proposal(*args, **kwargs):
        yield "drop-protected", request.case.events[1:], request.case.lineage[1:]

    monkeypatch.setattr("dvi_sentinel.consensus_shrinking.scoped_reductions", invalid_proposal)
    result = oracle_shrink(request)
    assert result.evaluations == 2 and result.trace[0].decision == "invalid"
    assert not next(
        c for c in result.trace[0].preservation.checks if c.id == "DVI-SHRINK-PROTECTED"
    ).passed
    assert result.final == result.initial


def test_oracle_wrong_class_reduction_rejected_even_when_match_reason_would_survive():
    request = oracle_fixture("correlation", count=1)
    event = request.case.events[0]
    event = event.model_copy(update={"raw": event.raw.model_copy(update={"vendor": None})})
    rules = tuple(
        rule.model_copy(
            update={
                "conditions": (
                    *rule.conditions,
                    RuleCondition(field="vendor", operator="eq", value="FixtureLab"),
                )
            }
        )
        if rule.id == "fixture:timely"
        else rule
        for rule in request.harness.rules
    )
    request = oracle_update(
        request,
        case=request.case.model_copy(update={"events": (event,)}),
        harness=request.harness.model_copy(update={"rules": rules}),
    )
    result = oracle_shrink(request)
    wrong = next(s for s in result.trace if "class would disappear" in s.reason)
    assert wrong.decision == "rejected" and wrong.candidate is None
    assert wrong.changed_classes == ("optional_field_dependency",)
    assert result.final.events[0].correlation_id is None
    assert result.final.events[0].raw.vendor == "FixtureLab"
    assert result.final.match.reason == result.initial.match.reason == "DVI-MATCH-LATE"


def test_oracle_changed_match_reason_rejected_with_confirmed_consensus():
    request = oracle_fixture(count=1)
    timely = next(r for r in request.harness.rules if r.id == "fixture:timely")
    late = next(r for r in request.harness.rules if r.id == "fixture:late")
    wrong = late.model_copy(update={"signature": "different"})
    restored = late.model_copy(
        update={
            "id": "fixture:restored",
            "conditions": (RuleCondition(field="vendor", operator="eq", value="FixtureLab"),),
        }
    )
    request = oracle_update(
        request, harness=request.harness.model_copy(update={"rules": (timely, wrong, restored)})
    )
    result = oracle_shrink(request)
    assert result.initial.match.reason == "DVI-MATCH-SIGNATURE"
    rejected = next(s for s in result.trace if "class/reason changed" in s.reason)
    assert rejected.candidate.consensus.state == "confirmed"
    assert rejected.candidate.match.reason == "DVI-MATCH-LATE"
    assert result.final.events[0].raw.vendor == "FIXTURELAB"


def test_oracle_same_consensus_state_with_changed_confidence_is_not_preserved(monkeypatch):
    request = oracle_fixture(count=2)

    def lowered_resolution(evidence, **kwargs):
        rows = evaluate_oracles(evidence, **kwargs)
        if len(evidence.events) == 1:
            rows = tuple(
                OracleResult.from_decision(
                    OracleDecision.model_validate(
                        row.model_dump(exclude={"digest"}) | {"confidence": 0.9}
                    )
                )
                if row.oracle_id == "temporal"
                else row
                for row in rows
            )
        return rows

    monkeypatch.setattr("dvi_sentinel.consensus_shrinking.evaluate_oracles", lowered_resolution)
    result = oracle_shrink(request)
    rejected = next(s for s in result.trace if "confidence or reasons changed" in s.reason)
    assert rejected.decision == "rejected"
    assert rejected.candidate.consensus.state == result.initial.consensus.state == "confirmed"
    assert rejected.candidate.consensus.confidence == 0.9
    assert len(result.final.events) == 2


def test_oracle_nonsimplifying_proposal_is_recorded_without_reevaluation(monkeypatch):
    request = oracle_fixture(count=1)

    def repeated(*args, **kwargs):
        yield "unchanged", request.case.events, request.case.lineage

    monkeypatch.setattr("dvi_sentinel.consensus_shrinking.scoped_reductions", repeated)
    report = oracle_shrink(request)
    assert report.evaluations == 2
    assert len(report.trace) == 1 and report.trace[0].decision == "rejected"
    assert "does not strictly simplify" in report.trace[0].reason


def test_actual_oracle_disagreement_stops_initial_case():
    request = oracle_fixture(count=1)
    rules = tuple(
        rule.model_copy(update={"signature": "different", "delay_ms": 0})
        if rule.id == "fixture:late"
        else rule
        for rule in request.harness.rules
    )
    result = oracle_shrink(
        oracle_update(request, harness=request.harness.model_copy(update={"rules": rules}))
    )
    assert result.state == "unknown" and not result.trace
    assert result.initial.match.status == "missed"
    assert result.initial.consensus.state == "ambiguous"
    assert result.initial.consensus.disagreements == ("detection", "temporal")


def test_actual_oracle_disagreement_during_reduction_stops_and_retains_last_proof():
    request = oracle_fixture(count=1)
    wrong = request.harness.rules[0].model_copy(
        update={
            "id": "fixture:wrong",
            "signature": "different",
            "delay_ms": 0,
            "conditions": (RuleCondition(field="vendor", operator="eq", value="FixtureLab"),),
        }
    )
    request = oracle_update(
        request,
        harness=request.harness.model_copy(update={"rules": (*request.harness.rules, wrong)}),
    )
    result = oracle_shrink(request)
    assert result.initial.consensus.state == "confirmed"
    assert result.state == "unknown" and result.trace[-1].decision == "unknown"
    assert result.trace[-1].candidate.consensus.state == "ambiguous"
    assert result.final == result.initial


def test_unsafe_reduction_is_traced_without_consumption_or_reexport(monkeypatch):
    request = oracle_fixture(count=1)
    bad = request.case.events[0].model_copy(
        update={
            "raw": RawSource.from_payload({"command": "inert forbidden marker"}, adapter="jsonl")
        }
    )

    def proposals(*args, **kwargs):
        yield "unsafe-proposal", (bad,), request.case.lineage

    monkeypatch.setattr("dvi_sentinel.consensus_shrinking.scoped_reductions", proposals)
    artifacts = oracle_shrink_artifacts(request, expected_digest=request.stable_digest())
    result = OracleShrinkReport.model_validate_json(artifacts["shrunk_case.json"])
    assert result.evaluations == 2 and len(result.trace) == 1
    step = result.trace[0]
    assert step.decision == "invalid" and step.candidate is None and step.baseline is None
    assert not next(c for c in step.preservation.checks if c.id == "DVI-INV-POLICY").passed
    assert all(b"inert forbidden marker" not in content for content in artifacts.values())


@pytest.mark.parametrize("max_attempts", [0, 1, 2])
def test_oracle_attempt_budget_retains_last_measured_case(max_attempts):
    request = oracle_update(oracle_fixture(), budget=OracleShrinkBudget(max_attempts=max_attempts))
    result = oracle_shrink(request)
    assert result.state == "budget_exhausted" and result.pending_reduction
    assert len(result.trace) == max_attempts
    assert result.final.consensus.state == "confirmed"


@pytest.mark.parametrize("evaluations", [0, 1, 2, 3, 4])
def test_oracle_evaluation_budget_counts_baselines_candidates_and_cached_controls(
    evaluations, monkeypatch
):
    request = oracle_update(
        oracle_fixture(), budget=OracleShrinkBudget(max_evaluations=evaluations)
    )
    actual = RuleLogicHarness.evaluate
    calls = []

    def measured(self, request):
        calls.append(request)
        return actual(self, request)

    monkeypatch.setattr(RuleLogicHarness, "evaluate", measured)
    result = oracle_shrink(request)
    assert result.state == "budget_exhausted" and result.pending_reduction
    assert len(calls) == result.evaluations == evaluations
    assert result.evaluated_events == sum(len(row.events) for row in calls)


@pytest.mark.parametrize("events", [0, 5, 6, 12, 13])
def test_oracle_event_budget_never_creates_unobserved_failures(events):
    result = oracle_shrink(
        oracle_update(oracle_fixture(), budget=OracleShrinkBudget(max_events=events))
    )
    assert result.state == "budget_exhausted" and result.evaluated_events <= events
    if events < 12:
        assert result.initial is None
    else:
        assert result.final == result.initial


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_oracle_pin_failure_blocks_all_consumers(pin, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("blocked input reached a detector")

    monkeypatch.setattr(RuleLogicHarness, "evaluate", forbidden)
    request = oracle_fixture()
    report = shrink_with_oracles(request, expected_digest=pin)
    assert report.input is None and report.evaluations == 0
    assert report.state == ("unknown" if pin is None else "unsafe_rejected")


def test_oracle_unsafe_input_blocks_original_baseline_and_omits_content(monkeypatch):
    request = oracle_fixture(count=1)
    bad = request.original[0].model_copy(
        update={
            "raw": RawSource.from_payload({"command": "inert forbidden marker"}, adapter="jsonl")
        }
    )
    request = oracle_update(request, original=(bad,))

    def forbidden(*args, **kwargs):
        pytest.fail("unsafe source reached the baseline detector")

    monkeypatch.setattr(RuleLogicHarness, "evaluate", forbidden)
    report = oracle_shrink(request)
    assert report.state == "unsafe_rejected" and report.input is None and report.evaluations == 0


def test_oracle_unresolved_meaning_and_precision_stop_conservatively():
    request = oracle_fixture(count=1)
    unknown = oracle_shrink(oracle_update(request, precision_digits=1))
    assert unknown.state == "unknown" and unknown.evaluations == 1 and unknown.initial is None
    original = request.original[0].model_copy(
        update={"semantics": request.original[0].semantics.model_copy(update={"category": "alert"})}
    )
    candidate = request.case.events[0].model_copy(update={"semantics": original.semantics})
    unknown = oracle_shrink(
        oracle_update(
            request,
            original=(original,),
            case=request.case.model_copy(update={"events": (candidate,)}),
        )
    )
    assert unknown.state == "unknown" and unknown.evaluations == 0


def test_oracle_robust_missed_baseline_and_invalid_initial_have_no_minimum():
    request = oracle_fixture(count=1)
    rules = tuple(rule.model_copy(update={"delay_ms": 0}) for rule in request.harness.rules)
    robust = oracle_shrink(
        oracle_update(request, harness=request.harness.model_copy(update={"rules": rules}))
    )
    assert robust.state == "not_a_failure" and not robust.trace
    missed = oracle_shrink(
        oracle_update(
            request, expected=request.expected.model_copy(update={"signature": "unmatched"})
        )
    )
    assert missed.state == "not_a_failure" and missed.initial is None
    invalid = oracle_shrink(
        oracle_update(request, policy=request.policy.model_copy(update={"families": ()}))
    )
    assert invalid.state == "invalid" and invalid.evaluations == 0
    no_change = oracle_shrink(
        oracle_update(request, case=request.case.model_copy(update={"events": request.original}))
    )
    assert no_change.state == "invalid" and no_change.evaluations == 0


def test_oracle_artifacts_are_repeatable_and_all_views_link_actual_evidence():
    request = oracle_fixture()
    left = oracle_shrink_artifacts(request, expected_digest=request.stable_digest())
    permuted = oracle_update(
        request,
        harness=request.harness.model_copy(
            update={"rules": tuple(reversed(request.harness.rules))}
        ),
        policy=request.policy.model_copy(
            update={"optional_fields": tuple(reversed(request.policy.optional_fields))}
        ),
    )
    assert request.stable_digest() == permuted.stable_digest()
    assert left == oracle_shrink_artifacts(permuted, expected_digest=permuted.stable_digest())
    result = OracleShrinkReport.model_validate_json(left["shrunk_case.json"])
    assert [
        json.loads(row) for row in left["shrinking_trace.jsonl"].splitlines()
    ] == result.model_dump(mode="json")["trace"]
    preservation = json.loads(left["oracle_preservation.json"])
    assert preservation["initial"] == result.initial.consensus.model_dump(mode="json")
    assert preservation["final"] == result.final.consensus.model_dump(mode="json")
    for row, step in zip(preservation["attempts"], result.trace, strict=True):
        assert row["candidate_digest"] == step.candidate_digest
        if step.decision == "accepted":
            assert row["preserved"] is True
    assert b"only in the minimized state" in left["shrunk_case.md"]


@settings(max_examples=5, deadline=None)
@given(st.integers(min_value=11, max_value=30))
def test_oracle_timing_reductions_find_the_measured_boundary_without_monotonic_assumptions(ms):
    request = oracle_fixture("timing", count=1)
    event = request.case.events[0].model_copy(
        update={"timestamp": request.original[0].timestamp + timedelta(milliseconds=ms)}
    )
    report = oracle_shrink(
        oracle_update(request, case=request.case.model_copy(update={"events": (event,)}))
    )
    assert report.state == "minimized"
    assert report.final.events[0].timestamp - request.original[0].timestamp == timedelta(
        microseconds=10001
    )


@pytest.mark.parametrize(
    "target",
    ["input", "cost", "class", "chain", "lineage", "match", "consensus", "count", "final", "state"],
)
def test_oracle_report_rejects_tampered_claims(target):
    report = oracle_shrink(oracle_fixture())
    data = report.model_dump(mode="json")
    step = next(s for s in data["trace"] if s["decision"] == "accepted")
    if target == "input":
        data["input"]["precision_digits"] = 1
    elif target == "cost":
        step["cost"][0] += 1
    elif target == "class":
        step["changed_classes"] = ["schema"]
    elif target == "chain":
        step["parent_digest"] = "0" * 64
    elif target == "lineage":
        step["lineage"] = []
    elif target == "match":
        step["candidate"]["match"]["reason"] = "DVI-MATCH-DETECTED"
    elif target == "consensus":
        step["candidate"]["consensus"]["state"] = "probable"
    elif target == "count":
        data["evaluations"] -= 1
    elif target == "final":
        data["final"] = data["initial"]
    else:
        data = oracle_shrink(
            oracle_update(oracle_fixture(), budget=OracleShrinkBudget(max_attempts=0))
        ).model_dump(mode="json")
        data["state"] = "minimized"
    with pytest.raises(ValidationError, match="DVI-SHRINK"):
        OracleShrinkReport.model_validate(data)


def test_oracle_bounds_and_copied_invalid_values_fail_before_detector():
    request = oracle_fixture(count=1)
    for changes in (
        {"original": request.original * 2},
        {"protected_event_ids": ("absent",)},
        {"protected_event_ids": request.protected_event_ids * 2},
        {"precision_digits": True},
        {"expected": request.expected.model_copy(update={"event_ids": ("absent",)})},
        {"case": request.case.model_copy(update={"events": request.case.events * 65})},
    ):
        with pytest.raises(ValidationError):
            oracle_shrink(request.model_copy(update=changes))
    for value in (True, -1, 129):
        with pytest.raises(ValidationError):
            OracleShrinkBudget(max_attempts=value)
    huge = request.original[0].model_copy(
        update={"raw": RawSource.from_payload({"note": "x" * 262144}, adapter="jsonl")}
    )
    with pytest.raises(ValidationError, match="256 KiB"):
        oracle_update(request, original=(huge,))


def test_oracle_artifact_size_cap_and_unexpected_engine_errors_propagate(monkeypatch):
    request = oracle_fixture(count=1)
    monkeypatch.setattr("dvi_sentinel.consensus_shrinking.MAX_ARTIFACT_BYTES", 1)
    with pytest.raises(ValueError, match="OUTPUT"):
        oracle_shrink_artifacts(request, expected_digest=request.stable_digest())

    def broken(*args, **kwargs):
        raise RuntimeError("unexpected local defect")

    monkeypatch.setattr(RuleLogicHarness, "evaluate", broken)
    with pytest.raises(RuntimeError, match="unexpected local defect"):
        oracle_shrink(request)


def test_oracle_example_executes_four_controls_and_refuses_existing_output(tmp_path):
    destination = tmp_path / "proof"
    command = [sys.executable, str(ORACLE_EXAMPLE), "--out", str(destination)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert len(list(destination.rglob("*.json"))) == 8
    assert len(list(destination.rglob("*.jsonl"))) == 4
    assert len(list(destination.rglob("*.md"))) == 4
    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode != 0 and "new local directory" in second.stderr
