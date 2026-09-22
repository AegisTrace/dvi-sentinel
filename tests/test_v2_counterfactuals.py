"""Observed local failures, complete subset controls and honest paired effects."""

import json
import runpy
import subprocess
import sys
from itertools import product
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.consensus_shrinking import shrink_with_oracles
from dvi_sentinel.consensus_shrinking_models import OracleShrinkInput
from dvi_sentinel.counterfactual_models import (
    CounterfactualBudget,
    CounterfactualDimension,
    CounterfactualInput,
    CounterfactualSummary,
)
from dvi_sentinel.counterfactuals import counterfactual_artifacts, mine_counterfactuals
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import (
    HarnessIssue,
    HarnessResult,
    LocalRule,
    RuleCondition,
    RuleHarnessConfig,
)
from dvi_sentinel.models import RawSource
from dvi_sentinel.reductions import validate_reduction
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.variation_models import EventLineage, VariationCase

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/counterfactuals.py"
fixture = runpy.run_path(str(EXAMPLE))["fixture"]


def changed(request, **updates):
    return CounterfactualInput.model_validate(request.model_dump(mode="python") | updates)


def mine(request=None):
    request = request or fixture()
    return mine_counterfactuals(request, expected_digest=request.stable_digest())


def minimal(report):
    return tuple(f.necessary_dimensions for f in report.findings)


def by_active(report):
    return {c.active: c for c in report.cases}


def test_single_safe_change_produces_actual_local_failure():
    report = mine(fixture("single"))
    cases = by_active(report)
    assert cases[()].match.status == "detected"
    assert cases[("sensor",)].match.status == "missed"
    assert cases[("sensor",)].observation.detections == ()
    assert cases[("sensor",)].events[0].raw.sensor is None
    assert cases[("sensor",)].steps[0].preservation.valid
    assert minimal(report) == (("sensor",),)


def test_combination_requires_both_dimensions_and_excludes_irrelevant_tags():
    report = mine()
    cases = by_active(report)
    assert cases[("sensor",)].outcome == cases[("vendor",)].outcome == "detected"
    assert cases[("sensor", "vendor")].outcome == "missed"
    assert minimal(report) == (("sensor", "vendor"),)
    assert report.rankings[-1].dimension.name == "tags"
    assert report.rankings[-1].effect.mean_miss_delta == 0
    assert not report.rankings[-1].minimal_failure_cases
    assert report.covering_plan.state == "complete"
    assert report.executed_interactions == report.covering_plan.feasible_interactions


def test_robust_control_claims_only_no_failure_in_tested_cases():
    report = mine(fixture("robust"))
    assert report.state == "no_failure_observed"
    assert not report.findings and not report.failure_sets
    assert all(c.outcome in {"detected", "not_evaluated"} for c in report.cases)
    assert "not_selected" in {c.stage for c in report.cases}
    assert "does not imply exhaustive" in report.limitations


def test_effect_counts_match_independent_paired_outcomes_and_keep_missing_pairs():
    report = mine()
    cases = by_active(report)
    for ranked in report.rankings:
        name = ranked.dimension.name
        deltas = []
        for active, absent in cases.items():
            if name in active:
                continue
            present = cases[tuple(sorted((*active, name)))]
            if (
                absent.match is not None
                and present.match is not None
                and absent.match.status != "unknown"
                and present.match.status != "unknown"
            ):
                deltas.append(
                    int(present.match.status == "missed") - int(absent.match.status == "missed")
                )
        assert ranked.effect.possible_pairs == 4
        assert ranked.effect.unavailable_pairs == 4 - len(deltas)
        assert ranked.effect.mean_miss_delta == sum(deltas) / len(deltas)
    assert all(r.effect.unavailable_pairs == 1 for r in report.rankings)


@settings(max_examples=8, deadline=None)
@given(st.integers(min_value=0, max_value=10000))
def test_minimal_dimensions_are_stable_across_seeded_covering_choices(seed):
    request = changed(fixture(), seed=seed)
    first = mine(request)
    assert minimal(first) == (("sensor", "vendor"),)
    assert canonical_json(first) == canonical_json(mine(request))
    assert tuple(r.dimension.name for r in first.rankings[:2]) == ("sensor", "vendor")


def test_declaration_order_does_not_change_inputs_or_artifacts():
    request = fixture()
    reversed_request = changed(
        request,
        dimensions=tuple(reversed(request.dimensions)),
        policy=request.policy.model_copy(
            update={"optional_fields": tuple(reversed(request.policy.optional_fields))}
        ),
        harness=request.harness.model_copy(
            update={"rules": tuple(reversed(request.harness.rules))}
        ),
    )
    assert request.stable_digest() == reversed_request.stable_digest()
    assert counterfactual_artifacts(
        request, expected_digest=request.stable_digest()
    ) == counterfactual_artifacts(
        reversed_request, expected_digest=reversed_request.stable_digest()
    )


@pytest.mark.parametrize("unknown", [False, True])
def test_unproven_baseline_stops_before_transformation_search(monkeypatch, unknown):
    import dvi_sentinel.counterfactuals as engine

    original = engine._materialize

    def guarded(events, assignment, policy):
        assert all(t.option == "none" for t in assignment)
        return original(events, assignment, policy)

    monkeypatch.setattr(engine, "_materialize", guarded)
    request = fixture()
    expected = request.expected.model_copy(
        update={"signature_contains": "fixture"} if unknown else {"detector": "fixture:missing"}
    )
    report = mine(changed(request, expected=expected))
    assert report.state == ("unknown" if unknown else "baseline_not_detected")
    assert report.evaluations == len(report.cases) == 1
    assert not report.findings and not report.rankings and report.covering_plan is None


def test_one_dimension_needs_only_baseline_and_single_control():
    request = fixture("single")
    report = mine(changed(request, dimensions=(request.dimensions[0],)))
    assert report.covering_plan is None and report.evaluations == 2
    assert minimal(report) == (("sensor",),)
    assert report.rankings[0].effect.mean_miss_delta == 1


@pytest.mark.parametrize("limit", [1, 2, 4, 5])
def test_global_case_budget_counts_actual_harness_calls(monkeypatch, limit):
    original = RuleLogicHarness.evaluate
    calls = []

    def counted(self, request):
        calls.append(request.case_id)
        return original(self, request)

    monkeypatch.setattr(RuleLogicHarness, "evaluate", counted)
    report = mine(changed(fixture(), budget=CounterfactualBudget(max_cases=limit)))
    assert report.evaluations == len(calls) == limit
    assert report.state == "incomplete"
    assert len(calls) == len(set(calls))
    assert report.unexecuted_cover_cases
    assert any(r.effect.unavailable_pairs for r in report.rankings)


@pytest.mark.parametrize("limit", [0, 1, 3])
def test_event_budget_never_becomes_a_measured_miss(limit):
    report = mine(changed(fixture(), budget=CounterfactualBudget(max_events=limit)))
    assert report.evaluated_events <= limit
    assert report.state == ("unknown" if limit == 0 else "incomplete")
    assert not report.findings
    assert any(c.outcome == "not_evaluated" and "Event budget" in c.reason for c in report.cases)


def test_noop_dimension_does_not_invent_an_effect_denominator():
    request = fixture("robust")
    event = request.events[0]
    event = event.model_copy(update={"raw": event.raw.model_copy(update={"sensor": None})})
    report = mine(changed(request, events=(event,), dimensions=(request.dimensions[0],)))
    effect = report.rankings[0].effect
    assert effect.unchanged_input_pairs == 1 and effect.mean_miss_delta is None
    assert effect.loss_pairs == effect.recovery_pairs == 0
    assert report.rankings[0].confidence == "insufficient_evidence" and not report.findings


def test_unpermitted_changes_have_rejection_evidence_and_never_execute():
    request = fixture()
    report = mine(changed(request, policy=VariationPolicy()))
    assert report.state == "incomplete"
    assert report.evaluations == 1
    assert all(c.outcome == "invalid" for c in report.cases[1:])
    assert all(c.rejections[0].reason_code == "operation_not_permitted" for c in report.cases[1:])
    assert not report.findings


def test_semantically_invalid_correlation_removal_is_excluded():
    request = fixture()
    report = mine(
        changed(
            request,
            dimensions=(
                CounterfactualDimension(name="correlation", operation="drop:correlation_id"),
            ),
            policy=VariationPolicy(families=("dropout",), optional_fields=("correlation_id",)),
        )
    )
    assert report.evaluations == 1 and report.cases[1].outcome == "invalid"
    assert report.cases[1].rejections[0].reason_code == "semantic_different"
    assert not report.findings


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_missing_or_wrong_input_pin_blocks_consumers(monkeypatch, pin):
    def forbidden(*args, **kwargs):
        pytest.fail("consumed unpinned input")

    monkeypatch.setattr("dvi_sentinel.counterfactuals._materialize", forbidden)
    report = mine_counterfactuals(fixture(), expected_digest=pin)
    assert report.state == ("unknown" if pin is None else "unsafe_rejected")
    assert report.input is None and not report.cases


def test_unsafe_source_blocks_harness_and_is_not_reexported(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("consumed unsafe input")

    monkeypatch.setattr(RuleLogicHarness, "evaluate", forbidden)
    request = fixture()
    event = request.events[0].model_copy(
        update={"raw": RawSource.from_payload({"command": "fixture"}, adapter="jsonl")}
    )
    report = mine(changed(request, events=(event,)))
    assert report.state == "unsafe_rejected" and report.input is None
    assert '"command"' not in canonical_json(report)


def test_unsafe_transformed_candidate_never_reaches_harness(monkeypatch):
    import dvi_sentinel.exploration as exploration

    original = exploration.transform

    def unsafe(spec, events, policy):
        candidate, lineage, preservation = original(spec, events, policy)
        event = candidate[0].model_copy(
            update={"raw": RawSource.from_payload({"command": "fixture"}, adapter="jsonl")}
        )
        return (event, *candidate[1:]), lineage, preservation

    monkeypatch.setattr(exploration, "transform", unsafe)
    report = mine()
    assert report.evaluations == 1 and not report.findings
    assert all(
        c.outcome == "invalid" and c.rejections[0].category == "safety" for c in report.cases[1:]
    )
    assert '"command"' not in canonical_json(report)


def test_replay_drift_fails_before_observation(monkeypatch):
    import dvi_sentinel.counterfactuals as engine

    original = engine._materialize
    calls = {}

    def drifting(events, assignment, policy):
        key = tuple((t.parameter, t.option) for t in assignment)
        calls[key] = calls.get(key, 0) + 1
        candidate, steps, failures = original(events, assignment, policy)
        if any(t.option != "none" for t in assignment) and calls[key] == 2:
            candidate = (candidate[0].model_copy(update={"labels": ("changed",)}), *candidate[1:])
        return candidate, steps, failures

    monkeypatch.setattr(engine, "_materialize", drifting)
    with pytest.raises(ValueError, match="REPLAY"):
        mine()


def test_unknown_subset_control_prevents_minimality_claim(monkeypatch):
    original = RuleLogicHarness.evaluate

    def missing(self, request):
        event = request.events[0]
        if event.raw.vendor is None and event.raw.sensor is not None:
            return HarnessResult(
                case_id=request.case_id,
                status="unknown",
                issues=(
                    HarnessIssue(
                        code="DVI-HARNESS-NO-FIXTURE", explanation="Missing control observation"
                    ),
                ),
            )
        return original(self, request)

    monkeypatch.setattr(RuleLogicHarness, "evaluate", missing)
    report = mine()
    assert report.state == "incomplete" and not report.findings
    failure = next(f for f in report.failure_sets if f.dimensions == ("sensor", "vendor"))
    assert failure.status == "unresolved" and failure.unresolved_cases
    assert all(r.confidence != "verified_local_subset_controls" for r in report.rankings)


def test_every_proper_subset_is_checked_without_monotonicity_assumption():
    request = fixture()
    dimensions = (
        CounterfactualDimension(name="a_spelling", operation="severity_normalization"),
        CounterfactualDimension(name="b_sensor", operation="name:sensor"),
        CounterfactualDimension(name="c_vendor", operation="name:vendor"),
    )
    rules = []
    for bits in product((0, 1), repeat=3):
        if bits in {(1, 0, 0), (1, 1, 1)}:
            continue
        values = (
            "unknown" if bits[0] else 0,
            "fixture-sensor-alias" if bits[1] else "fixture:sensor",
            "fixture-sensor-alias" if bits[2] else "FixtureLab",
        )
        rules.append(
            LocalRule(
                id="fixture:" + "".join(map(str, bits)),
                detector="fixture:detector",
                signature="fixture:signal",
                title="Non-monotonic local control",
                conditions=tuple(
                    RuleCondition(field=field, operator="eq", value=value)
                    for field, value in zip(
                        ("raw.severity", "sensor", "vendor"), values, strict=True
                    )
                ),
            )
        )
    report = mine(
        changed(
            request,
            dimensions=dimensions,
            strength=3,
            policy=VariationPolicy(families=("metadata",), optional_fields=("sensor", "vendor")),
            harness=RuleHarnessConfig(kind="rule_logic", rules=tuple(rules)),
        )
    )
    largest = next(f for f in report.failure_sets if len(f.dimensions) == 3)
    cases = by_active(report)
    assert all(c.outcome == "detected" for a, c in cases.items() if len(a) == 2)
    assert largest.status == "nonminimal" and len(largest.proper_subset_cases) == 7
    assert cases[("a_spelling",)].case_id in largest.smaller_missed_cases
    assert minimal(report) == (("a_spelling",),)
    assert any(r.effect.recovery_pairs for r in report.rankings)


def test_findings_use_conditional_language_and_no_population_confidence():
    report = mine()
    for phrase in (
        "associated with this local fixture",
        "necessary under this tested scenario",
        "likely contributor",
    ):
        assert phrase in report.findings[0].statement
    text = canonical_json(report)
    for phrase in ("proves universal cause", "guaranteed bypass", "always evades detection"):
        assert phrase not in text
    assert "not independent samples" in report.limitations
    assert all(r.effect.scope == "descriptive_local_pairs" for r in report.rankings)


def triple_request(max_cases=64):
    request = fixture()
    rules = (
        *request.harness.rules,
        LocalRule(
            id="fixture:tags",
            detector="fixture:detector",
            signature="fixture:signal",
            title="Three-field local control",
            conditions=(RuleCondition(field="tags", operator="contains", value="synthetic"),),
        ),
    )
    return changed(
        request,
        harness=RuleHarnessConfig(kind="rule_logic", rules=rules),
        seed=0,
        budget=CounterfactualBudget(max_cases=max_cases),
    )


def test_minimization_observes_subset_controls_not_selected_by_covering_array():
    report = mine(triple_request())
    assert minimal(report) == (("sensor", "tags", "vendor"),)
    assert report.evaluations == 8 and len(report.findings[0].control_cases) == 7
    assert any(c.stage == "minimization" for c in report.cases)
    assert report.state == "findings"


def test_exhausted_minimization_keeps_sufficient_miss_but_withholds_minimality():
    report = mine(triple_request(5))
    assert report.evaluations == 5 and report.state == "incomplete"
    failure = report.failure_sets[0]
    assert failure.dimensions == ("sensor", "tags", "vendor")
    assert failure.status == "unresolved" and len(failure.unresolved_cases) == 3
    assert not report.findings


def test_maximum_six_dimensions_remain_a_finite_accounted_space():
    request = fixture("robust")
    dimensions = (
        *request.dimensions,
        CounterfactualDimension(name="confidence", operation="drop:confidence"),
        CounterfactualDimension(name="labels", operation="drop:labels"),
        CounterfactualDimension(name="ordering", operation="ordering"),
    )
    policy = VariationPolicy(
        families=("dropout", "ordering"),
        order_independent=True,
        optional_fields=("sensor", "vendor", "tags", "labels", "confidence"),
    )
    report = mine(changed(request, dimensions=dimensions, policy=policy, strength=4))
    assert len(report.cases) == 64 and report.evaluations <= 64
    assert report.covering_plan.feasible_interactions == 15 * 16
    assert report.executed_interactions == 240
    assert report.state == "no_failure_observed" and not report.findings


def test_unexpected_engine_error_is_not_silently_classified(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("unexpected engine defect")

    monkeypatch.setattr(RuleLogicHarness, "evaluate", broken)
    with pytest.raises(RuntimeError, match="unexpected engine defect"):
        mine()


def test_unresolved_baseline_meaning_blocks_detector_consumption(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unresolved baseline was observed")

    monkeypatch.setattr(RuleLogicHarness, "evaluate", forbidden)
    request = fixture()
    event = request.events[0]
    event = event.model_copy(
        update={"semantics": event.semantics.model_copy(update={"category": "alert"})}
    )
    report = mine(changed(request, events=(event,)))
    assert report.state == "unknown" and report.evaluations == 0
    assert report.cases[0].outcome == "invalid"
    assert report.cases[0].rejections[0].reason_code == "semantic_unknown"


@pytest.mark.parametrize(
    "target", ["input", "minimality", "effect", "coverage", "observation", "state"]
)
def test_artifact_tampering_cannot_change_measured_claims(target):
    data = mine().model_dump(mode="json")
    if target == "input":
        data["input"]["seed"] += 1
    elif target == "minimality":
        data["failure_sets"][0]["proper_subset_cases"].pop()
    elif target == "effect":
        data["rankings"][0]["effect"]["mean_miss_delta"] = 1
    elif target == "coverage":
        data["executed_interactions"] += 1
    elif target == "observation":
        data["cases"][0]["observation"]["case_id"] = "foreign"
    else:
        data["state"] = "no_failure_observed"
    with pytest.raises(ValidationError, match="DVI-COUNTERFACTUAL"):
        CounterfactualSummary.model_validate(data)


def test_bounds_and_copied_invalid_inputs_fail_before_evaluation():
    request = fixture()
    for updates in (
        {"seed": True},
        {"events": request.events * 2},
        {"dimensions": request.dimensions * 2},
        {"strength": 5},
    ):
        with pytest.raises(ValidationError):
            mine(request.model_copy(update=updates))
    with pytest.raises(ValidationError, match="non-identity"):
        CounterfactualDimension(name="empty", operation="none")
    for value in (0, 65, True):
        with pytest.raises(ValidationError):
            CounterfactualBudget(max_cases=value)
    event = request.events[0].model_copy(
        update={"raw": RawSource.from_payload({"note": "x" * 262_144}, adapter="jsonl")}
    )
    with pytest.raises(ValidationError, match="256 KiB"):
        changed(request, events=(event,))


def test_combined_output_bound_is_enforced(monkeypatch):
    monkeypatch.setattr("dvi_sentinel.counterfactuals.MAX_ARTIFACT_BYTES", 1)
    request = fixture()
    with pytest.raises(ValueError, match="OUTPUT"):
        counterfactual_artifacts(request, expected_digest=request.stable_digest())


def test_artifacts_retain_actual_controls_and_consistent_views():
    request = fixture()
    artifacts = counterfactual_artifacts(request, expected_digest=request.stable_digest())
    report = json.loads(artifacts["counterfactual_summary.json"])
    assert [json.loads(line) for line in artifacts["counterfactuals.jsonl"].splitlines()] == report[
        "cases"
    ]
    assert json.loads(artifacts["minimal_failure_set.json"])["findings"] == report["findings"]
    assert json.loads(artifacts["causal_rankings.json"])["rankings"] == report["rankings"]
    cases = {c["case_id"]: c for c in report["cases"]}
    for finding in report["findings"]:
        assert cases[finding["case_id"]]["outcome"] == "missed"
        assert all(cases[c]["outcome"] == "detected" for c in finding["control_cases"])


def test_example_executes_three_controls_and_refuses_existing_output(tmp_path):
    destination = tmp_path / "proof"
    command = [sys.executable, str(EXAMPLE), "--out", str(destination)]
    result = subprocess.run(command, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert len(list(destination.rglob("*.json"))) == 9
    assert len(list(destination.rglob("*.jsonl"))) == 3
    robust = CounterfactualSummary.model_validate_json(
        (destination / "robust/counterfactual_summary.json").read_text()
    )
    assert robust.state == "no_failure_observed" and not robust.findings
    second = subprocess.run(command, text=True, capture_output=True)
    assert second.returncode != 0 and "new local directory" in second.stderr


def test_mined_missing_alert_does_not_become_oracle_confirmed_by_shrinking():
    source = fixture("single")
    mined = mine(source)
    finding = mined.findings[0]
    case = next(c for c in mined.cases if c.case_id == finding.case_id)
    refs = tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in source.events
    )
    request = OracleShrinkInput(
        original=source.events,
        case=VariationCase(
            id=case.case_id,
            family="dropout",
            parameters=(),
            events=case.events,
            lineage=refs,
            preservation=validate_reduction(
                source.events, case.events, refs, source.policy, "dropout"
            ),
            distance=1.0,
        ),
        policy=source.policy,
        expected=source.expected,
        harness=source.harness,
        protected_event_ids=tuple(e.event_id for e in source.events),
    )
    report = shrink_with_oracles(request, expected_digest=request.stable_digest())
    assert report.initial.match.status == "missed"
    assert report.initial.consensus.state == "not_enough_evidence"
    assert report.state == "unknown" and not report.trace
    assert report.final == report.initial
    temporal = next(d for d in report.initial.consensus.decisions if d.oracle_id == "temporal")
    assert temporal.decision == "unknown" and temporal.reason_codes == ("alert_evidence_missing",)
