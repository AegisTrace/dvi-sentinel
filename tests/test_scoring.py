from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest, RuleHarnessConfig
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.matching import match_detection
from dvi_sentinel.probes import run_probes
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.score_models import CaseAssessment, Ratio, ResilienceFrontier
from dvi_sentinel.scoring import percentile, summarize
from dvi_sentinel.serialization import canonical_json, parse_json
from dvi_sentinel.variation_models import MetamorphicInvariant, SemanticPreservationResult
from dvi_sentinel.variations import plan_variations

ROOT = Path(__file__).parents[1] / "examples"


def assessment(
    case_id, status="detected", family="timing", distance=1.0, valid=True, parser=True, delay=10.0
):
    return CaseAssessment(
        case_id=case_id,
        family=family,
        distance=distance,
        parser_success=parser,
        preservation=SemanticPreservationResult(
            checks=(
                MetamorphicInvariant(
                    id="semantic", passed=valid, explanation="test protected meaning"
                ),
                MetamorphicInvariant(id="safety", passed=True, explanation="test safe fixture"),
            )
        ),
        match=MatchResult(
            case_id=case_id,
            status=status,
            reason={
                "detected": "DVI-MATCH-DETECTED",
                "missed": "DVI-MATCH-LATE",
                "unknown": "DVI-MATCH-HARNESS",
            }[status],
            explanation="explicit formula fixture",
            alert_delay_ms=delay,
        )
        if status
        else None,
    )


def test_formulas_have_explicit_denominators_and_invalids_do_not_improve_rates():
    rows = (
        assessment("baseline", family="baseline"),
        assessment("hit", distance=2.0),
        assessment("miss", status="missed", distance=1.0),
        assessment("unknown", status="unknown"),
        assessment("unparsed", parser=False),
        assessment("invalid", valid=False),
    )
    result = summarize(rows)
    m = result.metrics
    assert (m.total, m.tested, m.semantically_valid, m.invalid) == (5, 5, 4, 1)
    assert (m.detected, m.missed, m.unknown) == (1, 1, 2)
    assert m.detection_rate == Ratio(numerator=1, denominator=4, value=0.25)
    assert m.miss_rate.value == 0.25 and m.unknown_rate.value == 0.5
    assert m.measured_detection_rate.value == 0.5
    assert m.semantic_preservation_rate.value == 0.8
    assert m.invariant_pass_rate.value == 0.9
    assert m.parser_success_rate.value == 0.8
    assert m.latency_samples == 1 and m.latency_p50_ms == m.latency_p95_ms == 10
    assert len(result.findings) == 1 and result.findings[0].case_id == "miss"
    assert result.families[0].minimal_miss_distance == 1
    assert result.families[0].hardest_safe_detected.case_id == "hit"


def test_empty_baseline_only_and_all_unknown_are_not_success():
    for rows in ((), (assessment("baseline", family="baseline"),)):
        result = summarize(rows)
        assert result.metrics.total == 0 and not result.families
        assert result.metrics.detection_rate.value is None
        assert result.metrics.parser_success_rate.value is None
        assert result.metrics.evidence_completeness.value is None
        assert result.metrics.latency_p95_ms is None
        assert result.adapter_disagreement_rate.value is None
    unknown = summarize((assessment("x", status=None, parser=None),)).metrics
    assert unknown.tested == 0 and unknown.unknown == unknown.parser_unknown == 1
    assert unknown.detection_rate.value == 0 and unknown.measured_detection_rate.value is None


def test_frontiers_are_per_family_with_stable_ties_and_no_invalid_boundaries():
    rows = (
        assessment("z", distance=4),
        assessment("a", distance=4),
        assessment("bad", distance=100, valid=False),
        assessment("miss", status="missed", family="volume", distance=2),
    )
    result = summarize(rows)
    assert [f.family for f in result.families] == ["timing", "volume"]
    assert result.families[0].hardest_safe_detected.case_id == "a"
    assert result.families[0].minimal_miss_distance is None
    assert result.families[1].easiest_safe_missed.case_id == "miss"
    assert not result.findings  # A miss alone does not establish baseline-relative fragility.
    assert canonical_json(result) == canonical_json(summarize(tuple(reversed(rows))))
    assert ResilienceFrontier.model_validate_json(canonical_json(result)) == result


def test_latency_interpolation_is_documented_not_rounded_to_sample():
    assert percentile([10, 20, 30, 40], 0.5) == 25
    assert percentile([10, 20, 30, 40], 0.95) == pytest.approx(38.5)
    assert percentile([4], 0.95) == 4 and percentile([], 0.5) is None
    with pytest.raises(ValueError):
        percentile([float("nan")], 0.5)


def test_inconsistent_ratios_duplicate_assessments_and_misaligned_matches_rejected():
    with pytest.raises(ValidationError):
        Ratio(numerator=1, denominator=2, value=1)
    with pytest.raises(ValueError, match="DUPLICATE"):
        summarize((assessment("x"), assessment("x")))
    with pytest.raises(ValueError, match="BASELINE"):
        summarize((assessment("a", family="baseline"), assessment("b", family="baseline")))
    with pytest.raises(ValidationError):
        CaseAssessment.model_validate(assessment("x").model_dump() | {"case_id": "y"})


@settings(max_examples=25, deadline=None, derandomize=True)
@given(st.lists(st.sampled_from(["detected", "missed", "unknown"]), max_size=30))
def test_outcome_partition_and_rate_bounds(statuses):
    result = summarize(
        tuple(assessment(f"case:{i}", status=status) for i, status in enumerate(statuses))
    )
    m = result.metrics
    assert m.detected + m.missed + m.unknown == m.semantically_valid == len(statuses)
    if statuses:
        assert m.detection_rate.value + m.miss_rate.value + m.unknown_rate.value == pytest.approx(1)
    assert not result.findings


@given(
    st.lists(
        st.tuples(
            st.sampled_from(["detected", "missed", "unknown"]),
            st.booleans(),
            st.sampled_from([True, False, None]),
        ),
        max_size=20,
    )
)
def test_mixed_invalid_and_unparsed_cases_keep_honest_denominators(cases):
    rows = tuple(
        assessment(f"case:{i}", status=status, valid=valid, parser=parsed)
        for i, (status, valid, parsed) in enumerate(cases)
    )
    score = summarize(rows)
    valid_count = sum(valid for _, valid, _ in cases)
    hits = sum(status == "detected" and valid and parsed is True for status, valid, parsed in cases)
    misses = sum(status == "missed" and valid and parsed is True for status, valid, parsed in cases)
    assert score.metrics.invalid == len(cases) - valid_count
    assert score.metrics.detected == hits and score.metrics.missed == misses
    assert score.metrics.unknown == valid_count - hits - misses
    assert (
        score.metrics.detection_rate.denominator
        == score.metrics.unknown_rate.denominator
        == valid_count
    )
    assert score.metrics.measured_detection_rate.denominator == hits + misses
    assert score.metrics.latency_samples == hits
    assert summarize((assessment("baseline", family="baseline"), *rows)).metrics == score.metrics
    assert canonical_json(summarize(tuple(reversed(rows)))) == canonical_json(score)


@pytest.mark.parametrize("rule_id", ["duplicates", "robust"])
def test_real_variation_benchmark_has_expected_frontier_and_evidence(rule_id):
    events = normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events
    config = RuleHarnessConfig.model_validate(parse_json((ROOT / "probes/rules.json").read_bytes()))
    harness = RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic", rules=tuple(r for r in config.rules if r.id == rule_id)
        )
    )
    expected = DetectionExpectation(detector="lab", signature=rule_id)
    policy = VariationPolicy(families=("volume",), max_duplicates=3, max_variants=10)
    plan = plan_variations("score-proof", events, policy, 42)
    rows = tuple(
        CaseAssessment(
            case_id=case.id,
            family=case.family,
            distance=case.distance,
            preservation=case.preservation,
            parser_success=True,
            match=match_detection(
                expected,
                harness.evaluate(
                    HarnessRequest(
                        case_id=case.id,
                        events=case.events,
                    )
                ),
                case.events,
                preservation=case.preservation,
            ),
        )
        for case in plan.cases
    )
    result = summarize(rows)
    assert result.baseline.match.status == "detected"
    if rule_id == "duplicates":
        assert result.metrics.miss_rate.value == 1 and result.metrics.detection_rate.value == 0
        assert result.families[0].minimal_miss_distance == 1
        assert {f.finding_class for f in result.findings} == {"volume_sensitivity"}
        assert (
            result.metrics.evidence_completeness.value is None
            and result.metrics.latency_samples == 0
        )
    else:
        assert result.metrics.detection_rate.value == 1 and result.metrics.miss_rate.value == 0
        assert result.metrics.evidence_completeness.value == 1
        assert result.families[0].minimal_miss_distance is None and not result.findings


def test_real_probe_taxonomy_and_adapter_disagreement_rates():
    events = normalize((ROOT / "telemetry/generic.jsonl").read_bytes(), "jsonl").events
    config = RuleHarnessConfig.model_validate(parse_json((ROOT / "probes/rules.json").read_bytes()))
    harness = RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic", rules=tuple(r for r in config.rules if r.id == "alias")
        )
    )
    policy = VariationPolicy(families=("metadata",))
    probes = run_probes(events, policy, harness)
    differential = run_differential(events, harness)
    result = summarize((), probes=probes + probes, differential=differential)
    assert {f.finding_class for f in result.findings} == {"schema"}
    assert len({f.id for f in result.findings}) == len(result.findings)
    assert result.adapter_disagreement_rate.value == pytest.approx(1 / 3)
    assert result.adapter_unknown == 0


def test_completeness_aggregates_available_comparisons_even_when_failed():
    events = normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events
    config = RuleHarnessConfig.model_validate(parse_json((ROOT / "probes/rules.json").read_bytes()))
    observation = RuleLogicHarness(config).evaluate(HarnessRequest(case_id="x", events=events))
    match = match_detection(
        DetectionExpectation(detector="lab", min_severity=5), observation, events
    )
    row = CaseAssessment.model_validate(assessment("x").model_dump() | {"match": match})
    result = summarize((row,))
    assert result.metrics.missed == 1 and result.metrics.evidence_cases == 1
    assert result.metrics.evidence_completeness.value == 1
