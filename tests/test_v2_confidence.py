"""Mathematical controls and evidence-boundary regressions for V2 statistics."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

import dvi_sentinel.confidence as engine
from dvi_sentinel.confidence import analyze_confidence, confidence_artifacts
from dvi_sentinel.confidence_math import (
    bootstrap_latency,
    latency_points,
    paired_difference_bounds,
    wilson_bounds,
)
from dvi_sentinel.confidence_models import (
    ConfidenceInput,
    ConfidenceReport,
    ConfidenceRun,
    ConfidenceSettings,
    RateInterval,
)
from dvi_sentinel.harness import FixtureHarness
from dvi_sentinel.harness_models import FixtureCase, FixtureResults, HarnessRequest
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import RawSource
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.serialization import canonical_json, digest
from examples.statistical_confidence import fixture_run


def analyze(current, previous=(), **settings):
    request = ConfidenceInput(
        current=tuple(current),
        previous=tuple(previous),
        settings=ConfidenceSettings(bootstrap_resamples=100, **settings),
    )
    return analyze_confidence(request, expected_digest=request.stable_digest())


def group(report, *, seed=1, side="current", scope="run"):
    return next(g for g in report.groups if (g.side, g.seed, g.scope) == (side, seed, scope))


def changed_run(run, *, statuses=None, invalid=(), parser_unknown=(), drop=(), **snapshot):
    """Measure a declared fixture schedule; never assign a synthetic matcher outcome."""
    data = run.model_dump(mode="python")
    if drop:
        data["snapshot"]["assessments"] = [
            r for r in data["snapshot"]["assessments"] if r["case_id"] not in drop
        ]
        data["snapshot"]["case_input_digests"] = {
            k: v for k, v in data["snapshot"]["case_input_digests"].items() if k not in drop
        }
        data["evidence"] = [p for p in data["evidence"] if p["evidence"]["subject_id"] not in drop]
    if statuses is not None:
        cases = []
        for proof in run.evidence:
            e = proof.evidence
            index = int(e.subject_id.rsplit(":", 1)[1]) - 1
            status = "detected" if index < 0 else statuses[index]
            if status != "unknown":
                cases.append(
                    FixtureCase(
                        case_id=e.subject_id,
                        detections=e.observation.detections if status == "detected" else (),
                    )
                )
        fixture = FixtureResults(cases=tuple(cases))
        harness = FixtureHarness(fixture)
        # Fixed schedule identity across seeds: fixture case IDs differ, the protocol does not.
        data["snapshot"]["detector_digest"] = digest({"fixture": "declared-seed-schedule"})
        for row, proof in zip(data["snapshot"]["assessments"], data["evidence"], strict=True):
            e = next(p.evidence for p in run.evidence if p.evidence.subject_id == row["case_id"])
            observation = harness.evaluate(HarnessRequest(case_id=e.subject_id, events=e.events))
            index = int(e.subject_id.rsplit(":", 1)[1]) - 1
            if index in invalid:
                row["preservation"] = row["preservation"] | {
                    "checks": tuple(c | {"passed": False} for c in row["preservation"]["checks"])
                }
                # Preservation model derives valid from checks; use its validated result below.
                from dvi_sentinel.variation_models import SemanticPreservationResult

                preservation = SemanticPreservationResult.model_validate(row["preservation"])
            else:
                preservation = next(
                    r.preservation for r in run.snapshot.assessments if r.case_id == e.subject_id
                )
            if index in parser_unknown:
                row["parser_success"] = None
            proof["evidence"]["observation"] = observation.model_dump(mode="python")
            proof["expected_digest"] = OracleEvidence.model_validate(
                proof["evidence"]
            ).stable_digest()
            row["match"] = match_detection(
                e.expected,
                observation,
                e.events,
                parser_success=row["parser_success"] is True,
                preservation=preservation,
            ).model_dump(mode="python")
    data["snapshot"].update(snapshot)
    return ConfidenceRun.model_validate(data)


@pytest.mark.parametrize(
    "k,n,expected",
    [
        (0, 0, (None, None)),
        (0, 10, (0, 0.2775327998628892)),
        (10, 10, (0.7224672001371107, 1)),
        (50, 100, (0.4038315303659956, 0.5961684696340044)),
        (10, 20, (0.2992980081982123, 0.7007019918017877)),
    ],
)
def test_wilson_known_values(k, n, expected):
    assert wilson_bounds(k, n) == pytest.approx(expected)


@given(st.integers(1, 10000), st.floats(0, 1, allow_nan=False))
def test_wilson_contains_estimate_and_has_complementary_miss_bounds(n, fraction):
    k = min(n, int(n * fraction))
    lo, hi = wilson_bounds(k, n)
    ml, mh = wilson_bounds(n - k, n)
    assert 0 <= lo <= k / n <= hi <= 1
    assert (lo, hi) == pytest.approx((1 - mh, 1 - ml))


@pytest.mark.parametrize(
    "args",
    [
        (True, 2),
        (1, True),
        (-1, 3),
        (4, 3),
        (1, 10**9 + 1),
        (1, 3, 0),
        (1, 3, 1),
        (1, 3, float("nan")),
        (1, 3, True),
    ],
)
def test_invalid_wilson_inputs(args):
    with pytest.raises(ValueError):
        wilson_bounds(*args)


@pytest.mark.parametrize(
    "args", [(0, 0, 1, -0.1), (0, 0, 1, True), (-1, 0, 2), (1, 2, 2), (True, 0, 2), (0, 0, True)]
)
def test_invalid_paired_inputs(args):
    with pytest.raises(ValueError):
        paired_difference_bounds(*args)


def test_bootstrap_seed_order_and_observation_budget():
    data = (1.0, 2.0, 4.0, 9.0, 20.0)
    first = bootstrap_latency(data, seed=9, resamples=100)
    assert first == bootstrap_latency(tuple(reversed(data)), seed=9, resamples=100)
    assert first != bootstrap_latency(data, seed=10, resamples=100)
    assert all(len(row) == 100 and min(row) >= 1 and max(row) <= 20 for row in first)
    assert latency_points(data) == pytest.approx((7.2, 4, 17.8))
    assert bootstrap_latency((), seed=1, resamples=100) == ((), (), ())
    assert bootstrap_latency((7.0,), seed=1, resamples=100) == ((), (), ())
    assert latency_points((7.0,)) == (7, 7, 7)
    assert bootstrap_latency((7.0, 7.0), seed=1, resamples=100) == ((7.0,) * 100,) * 3


@pytest.mark.parametrize(
    "values,seed,resamples",
    [
        ((float("inf"),), 1, 100),
        ((-1.0,), 1, 100),
        ((True,), 1, 100),
        ((1.0,) * 129, 1, 100),
        ((86400001.0,), 1, 100),
        ((1.0,), -1, 100),
        ((1.0,), True, 100),
        ((1.0,), 1, 99),
        ((1.0,), 1, 1001),
        ((1.0,), 1, True),
    ],
)
def test_bootstrap_bounds(values, seed, resamples):
    with pytest.raises(ValueError):
        bootstrap_latency(values, seed=seed, resamples=resamples)


def test_empty_and_baseline_only_never_gain_confidence():
    baseline = fixture_run(1, count=0)
    for run in (baseline, changed_run(baseline, drop=(baseline.snapshot.assessments[0].case_id,))):
        report = analyze((run,))
        g = group(report)
        assert g.metrics.total == 0 and g.confidence_class == "unknown"
        assert g.detection_interval.lower is None and g.miss_interval.upper is None
        assert g.detection_identification_bounds == (None, None)
        assert {"small_sample", "empty_denominator", "latency_small_sample"} <= set(g.warnings)


def test_unknown_invalid_and_parser_evidence_preserve_honest_denominators():
    run = changed_run(
        fixture_run(1, count=5),
        statuses=("detected", "missed", "unknown", "detected", "detected"),
        invalid=(3,),
        parser_unknown=(4,),
    )
    g = group(analyze((run,)))
    assert (
        g.metrics.total,
        g.metrics.detected,
        g.metrics.missed,
        g.metrics.unknown,
        g.metrics.invalid,
    ) == (5, 1, 1, 2, 1)
    assert g.detection_interval.denominator == g.miss_interval.denominator == 2
    assert g.metrics.detection_rate.value == 0.25  # Existing V1 valid denominator remains intact.
    assert g.detection_identification_bounds == (0.25, 0.75)
    assert g.confidence_class == "insufficient_sample" and len(g.latency.samples_ms) == 1
    assert {"missing_outcomes", "invalid_cases", "latency_selection"} <= set(g.warnings)


def test_actual_findings_get_single_case_confidence_not_family_sample_counts():
    report = analyze((fixture_run(1, fragile=True, count=4),))
    assert {g.scope for g in report.groups} == {"run", "family", "finding"}
    findings = [g for g in report.groups if g.scope == "finding"]
    assert len(findings) == 2
    assert all(
        g.metrics.total == g.miss_interval.denominator == 1
        and g.confidence_class == "insufficient_sample"
        for g in findings
    )
    assert group(report).metrics.total == 4


def test_same_aggregate_rates_with_opposite_outcomes_are_unstable():
    runs = (
        changed_run(fixture_run(1, count=4), statuses=("detected", "missed") * 2),
        changed_run(fixture_run(2, count=4), statuses=("missed", "detected") * 2),
    )
    report = analyze(runs)
    g = group(report)
    stability = next(s for s in report.seed_stability if s.key == g.stability_key)
    assert all(r.detection_rate == 0.5 for r in stability.rates)
    assert (stability.possible_pairs, stability.resolved_pairs, stability.agreeing_pairs) == (
        4,
        4,
        0,
    )
    assert stability.score == 0 and g.confidence_class == "unstable_across_seeds"
    assert "small_sample" in g.warnings
    assert all(g.confidence_class == "unstable_across_seeds" for g in report.groups)


def test_partial_and_unavailable_seed_pairs_stay_explicit():
    runs = (
        changed_run(fixture_run(1, count=2), statuses=("detected", "unknown")),
        changed_run(fixture_run(2, count=2), statuses=("detected", "unknown")),
    )
    report = analyze(runs)
    s = next(s for s in report.seed_stability if s.key == group(report).stability_key)
    assert (s.possible_pairs, s.resolved_pairs, s.unavailable_pairs, s.score) == (2, 1, 1, 1)
    assert s.state == "partial" and "seed_stability_unknown" in group(report).warnings
    unknown = analyze(
        tuple(changed_run(fixture_run(seed, count=1), statuses=("unknown",)) for seed in (1, 2))
    )
    assert group(unknown).confidence_class == "unknown"
    assert all(s.score is None for s in unknown.seed_stability)


@pytest.mark.parametrize("mismatch", ["detector", "cohort", "one_seed"])
def test_seed_incompatibility_never_looks_stable(mismatch):
    left, right = fixture_run(1, count=2), fixture_run(2, count=2)
    if mismatch == "detector":
        right = changed_run(right, detector_digest="0" * 64)
    if mismatch == "cohort":
        right = changed_run(right, drop=(right.snapshot.assessments[-1].case_id,))
    report = analyze((left,) if mismatch == "one_seed" else (left, right))
    assert all(s.score is None and s.state == "unknown" for s in report.seed_stability)


@pytest.mark.parametrize(
    "n,iid,seeds,expected",
    [
        (19, True, 3, "insufficient_sample"),
        (20, True, 3, "low_confidence"),
        (30, True, 2, "moderate_confidence"),
        (100, True, 3, "high_confidence"),
        (100, False, 3, "low_confidence"),
        (100, True, 1, "low_confidence"),
    ],
)
def test_precision_classes_require_explicit_assumptions_and_seed_evidence(n, iid, seeds, expected):
    report = analyze(
        tuple(fixture_run(seed, count=n) for seed in range(1, seeds + 1)),
        independent_trials_assumed=iid,
    )
    assert group(report).confidence_class == expected
    assert (
        group(report).detection_interval.denominator == n
    )  # Neither seeds nor resamples add trials.
    assert (
        "unverified" in report.calibration_note
        and "No empirical coverage" in report.calibration_note
    )


def test_regression_is_preserved_even_when_effect_interval_includes_zero():
    previous = fixture_run(1, count=1)
    current = fixture_run(1, fragile=True, count=1)
    comparison = analyze((current,), (previous,)).comparisons[0]
    assert comparison.legacy.status == "regressed" and comparison.legacy.exit_status == 1
    effect = comparison.effects[0]
    assert effect.delta == -1 and effect.lost == 1 and effect.direction == "includes_zero"
    assert effect.lower < 0 < effect.upper


def test_large_regression_recovery_and_no_change_have_uncertainty():
    previous, current = fixture_run(1, count=32), fixture_run(1, fragile=True, count=32)
    report = analyze((current,), (previous,))
    effect = report.comparisons[0].effects[0]
    assert effect.delta == -0.5 and effect.direction == "negative_interval"
    recovery = analyze((previous,), (current,)).comparisons[0].effects[0]
    assert recovery.direction == "positive_interval"
    assert (recovery.lower, recovery.upper) == pytest.approx((-effect.upper, -effect.lower))
    unchanged = analyze((previous,), (previous,)).comparisons[0].effects[0]
    assert unchanged.delta == 0 and unchanged.lower < 0 < unchanged.upper


def test_comparison_unknowns_are_not_counted_as_losses():
    previous = changed_run(fixture_run(1, count=2), statuses=("detected", "detected"))
    current = changed_run(fixture_run(1, count=2), statuses=("unknown", "missed"))
    result = analyze((current,), (previous,)).comparisons[0]
    assert result.legacy.status == "regressed"
    assert (
        result.effects[0].paired_cases,
        result.effects[0].lost,
        result.effects[0].unavailable,
    ) == (2, 1, 1)


def test_incompatible_snapshots_and_seed_sets_have_no_effects():
    run = fixture_run(1, count=2)
    report = analyze((changed_run(run, config_digest="0" * 64),), (run,))
    assert report.comparisons[0].legacy.status == "incompatible"
    assert not report.comparisons[0].effects and report.comparisons[0].effect_reasons
    mismatch = analyze((fixture_run(2, count=2),), (run,))
    assert not mismatch.comparisons and mismatch.comparison_reasons


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_top_pin_gate_precedes_all_consumption(monkeypatch, pin):
    request = ConfidenceInput(current=(fixture_run(1, count=1),))

    def forbidden(*args, **kwargs):
        pytest.fail("unverified input reached an analyzer")

    monkeypatch.setattr(engine, "_gates", forbidden)
    monkeypatch.setattr(engine, "_derive", forbidden)
    report = analyze_confidence(request, expected_digest=pin)
    assert report.input is None and not report.groups
    assert report.state == ("unknown" if pin is None else "unsafe_rejected")


@pytest.mark.parametrize("gate", ["safety", "provenance"])
def test_per_record_authoritative_gates_precede_matching(monkeypatch, gate):
    data = ConfidenceInput(current=(fixture_run(1, count=1),)).model_dump(mode="python")
    proof = data["current"][0]["evidence"][0]
    if gate == "provenance":
        proof["expected_digest"] = "0" * 64
    else:
        event = proof["evidence"]["events"][0]
        event["raw"] = RawSource.from_payload({"src_ip": "8.8.8.8"}, adapter="jsonl").model_dump()
        proof["expected_digest"] = OracleEvidence.model_validate(proof["evidence"]).stable_digest()
    request = ConfidenceInput.model_validate(data)

    def forbidden(*args, **kwargs):
        pytest.fail("authoritative failure reached matching")

    monkeypatch.setattr(engine, "match_detection", forbidden)
    report = analyze_confidence(request, expected_digest=request.stable_digest())
    assert report.state == "unsafe_rejected" and report.input is None and not report.groups
    assert any(g.oracle_id == gate and g.blocking for g in report.gates)
    assert "8.8.8.8" not in canonical_json(report)


@pytest.mark.parametrize(
    "mismatch", ["input", "match", "missing_observation", "missing_expectation"]
)
def test_assessments_must_match_pinned_actual_observations(mismatch):
    data = ConfidenceInput(current=(fixture_run(1, count=1),)).model_dump(mode="python")
    run = data["current"][0]
    row, proof = run["snapshot"]["assessments"][0], run["evidence"][0]
    if mismatch == "input":
        run["snapshot"]["case_input_digests"][row["case_id"]] = "0" * 64
    elif mismatch == "match":
        row["match"] = None
    else:
        proof["evidence"]["observation" if mismatch == "missing_observation" else "expected"] = None
        proof["expected_digest"] = OracleEvidence.model_validate(proof["evidence"]).stable_digest()
    request = ConfidenceInput.model_validate(data)
    with pytest.raises(ValueError, match="DVI-CONFIDENCE-(INPUT|MATCH)"):
        analyze_confidence(request, expected_digest=request.stable_digest())


def test_canonical_order_and_artifact_views_roundtrip():
    request = ConfidenceInput(
        current=(fixture_run(2, count=3), fixture_run(1, fragile=True, count=3))
    )
    data = request.model_dump(mode="python")
    data["current"] = tuple(reversed(data["current"]))
    for run in data["current"]:
        run["evidence"] = tuple(reversed(run["evidence"]))
        run["snapshot"]["assessments"] = tuple(reversed(run["snapshot"]["assessments"]))
    reordered = ConfidenceInput.model_validate(data)
    assert reordered.stable_digest() == request.stable_digest()
    first = confidence_artifacts(request, expected_digest=request.stable_digest())
    assert first == confidence_artifacts(reordered, expected_digest=reordered.stable_digest())
    report = ConfidenceReport.model_validate_json(first["confidence.json"])
    assert (
        json.loads(first["seed_stability.json"])["records"]
        == report.model_dump(mode="json")["seed_stability"]
    )
    assert (
        json.loads(first["score_distribution.json"])["groups"]
        == report.model_dump(mode="json")["groups"]
    )
    assert (
        json.loads(first["statistical_warnings.json"])["warnings"]
        == report.model_dump(mode="json")["warnings"]
    )
    assert all(blob.endswith(b"\n") for blob in first.values())


@pytest.mark.parametrize(
    "tamper",
    ["class", "gates", "group", "stability", "warnings", "calibration", "bootstrap", "comparison"],
)
def test_report_validation_rederives_decisions_and_numerical_evidence(tamper):
    run = fixture_run(1, count=3)
    data = analyze((run,), (run,)).model_dump(mode="json")
    if tamper == "class":
        data["groups"][0]["confidence_class"] = "high_confidence"
    elif tamper == "bootstrap":
        estimate = data["groups"][0]["latency"]["estimates"][0]
        estimate["resampled_estimates"] = [99.0] * 100
        estimate["lower"] = estimate["upper"] = 99.0
    elif tamper == "comparison":
        data["comparisons"][0]["legacy"]["status"] = "regressed"
    elif tamper == "calibration":
        data["calibration_note"] = "Certain"
    else:
        key = {"group": "groups", "stability": "seed_stability"}.get(tamper, tamper)
        data[key] = []
    with pytest.raises(ValidationError):
        ConfidenceReport.model_validate(data)


def test_models_reject_duplicate_seeds_evidence_and_invalid_denominators():
    run = fixture_run(1, count=1)
    with pytest.raises(ValidationError, match="SEEDS"):
        ConfidenceInput(current=(run, run))
    data = run.model_dump(mode="python")
    data["evidence"] = data["evidence"][:-1]
    with pytest.raises(ValidationError, match="EVIDENCE"):
        ConfidenceRun.model_validate(data)
    with pytest.raises(ValidationError):
        RateInterval(numerator=0, denominator=0, confidence_level=0.95, lower=0.0, upper=1.0)


def test_runnable_example_and_existing_destination_protection(tmp_path):
    root = Path(__file__).parents[1]
    destination = tmp_path / "proof"
    command = [
        sys.executable,
        str(root / "examples/statistical_confidence.py"),
        "--out",
        str(destination),
    ]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr
    assert len(list(destination.iterdir())) == 4
    data = json.loads((destination / "confidence.json").read_text())
    assert len(data["comparisons"]) == 3 and all(
        c["legacy"]["status"] == "regressed" for c in data["comparisons"]
    )
    before = {p.name: p.read_bytes() for p in destination.iterdir()}
    repeat = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=90)
    assert repeat.returncode != 0 and "new local directory" in repeat.stderr
    assert before == {p.name: p.read_bytes() for p in destination.iterdir()}


def test_duplicate_inputs_cannot_establish_seed_stability():
    def duplicate(seed):
        data = fixture_run(seed, count=2).model_dump(mode="python")
        source = data["evidence"][1]["evidence"]
        target_id = data["evidence"][2]["evidence"]["subject_id"]
        replacement = OracleEvidence.model_validate(source).model_dump(mode="python")
        replacement["subject_id"] = target_id
        replacement["observation"]["case_id"] = target_id
        proof = OracleEvidence.model_validate(replacement)
        data["evidence"] = list(data["evidence"])
        data["evidence"][2] = {
            "evidence": proof.model_dump(mode="python"),
            "expected_digest": proof.stable_digest(),
        }
        row = data["snapshot"]["assessments"][2]
        row["distance"] = data["snapshot"]["assessments"][1]["distance"]
        row["preservation"] = data["snapshot"]["assessments"][1]["preservation"]
        row["match"] = match_detection(proof.expected, proof.observation, proof.events).model_dump()
        data["snapshot"]["case_input_digests"][target_id] = digest(
            [e.model_dump(mode="json") for e in proof.events]
        )
        return ConfidenceRun.model_validate(data)

    report = analyze((duplicate(1), duplicate(2)))
    assert "duplicate_inputs" in group(report).warnings
    assert all(s.score is None and "duplicate_units" in s.reasons for s in report.seed_stability)
    assert "latency_degenerate" in group(report).warnings


def test_changed_expectations_prevent_effects_and_seed_agreement():
    before = fixture_run(1, count=2)

    def change(run):
        data = run.model_dump(mode="python")
        for row, p in zip(data["snapshot"]["assessments"], data["evidence"], strict=True):
            p["evidence"]["expected"]["max_delay_ms"] = 20
            e = OracleEvidence.model_validate(p["evidence"])
            p["expected_digest"] = e.stable_digest()
            row["match"] = match_detection(e.expected, e.observation, e.events).model_dump()
        return ConfidenceRun.model_validate(data)

    after = change(before)
    comparison = analyze((after,), (before,)).comparisons[0]
    assert comparison.legacy.status == "passed"
    assert not comparison.effects and "expectations differ" in comparison.effect_reasons[0]
    report = analyze((before, change(fixture_run(2, count=2))))
    assert all(
        s.score is None and "seed_configuration_mismatch" in s.reasons
        for s in report.seed_stability
    )


def test_absent_observation_and_match_remain_unknown():
    data = fixture_run(1, count=1).model_dump(mode="python")
    p = data["evidence"][1]
    p["evidence"]["observation"] = None
    p["expected_digest"] = OracleEvidence.model_validate(p["evidence"]).stable_digest()
    data["snapshot"]["assessments"][1]["match"] = None
    g = group(analyze((ConfidenceRun.model_validate(data),)))
    assert g.metrics.unknown == 1 and g.confidence_class == "unknown"


@pytest.mark.parametrize(
    "field,value",
    [
        ("bootstrap_resamples", True),
        ("bootstrap_resamples", 1001),
        ("bootstrap_seed", -1),
        ("bootstrap_seed", 2**63),
        ("confidence_level", 0.79),
        ("confidence_level", 1.0),
        ("confidence_level", float("inf")),
        ("independent_trials_assumed", 1),
    ],
)
def test_settings_bounds(field, value):
    with pytest.raises(ValidationError):
        ConfidenceSettings.model_validate({field: value})


def test_total_record_bound_and_unchecked_copy_are_revalidated():
    run = fixture_run(1, count=100)
    copies = tuple(changed_run(run, seed=seed) for seed in range(6))
    with pytest.raises(ValidationError, match="512"):
        ConfidenceInput(current=copies)
    request = ConfidenceInput(current=(run,))
    request = request.model_copy(update={"current": copies})
    with pytest.raises(ValidationError, match="512"):
        analyze_confidence(request)


def test_input_byte_bound_is_enforced():
    data = fixture_run(1, count=0).model_dump(mode="python")
    # Eight individually bounded safe metadata records exceed the combined 4 MiB cap.
    raw = RawSource.from_payload({"description": "x" * 600000}, adapter="jsonl")
    data["evidence"][0]["evidence"]["events"][0]["raw"] = raw.model_dump()
    run = ConfidenceRun.model_validate(data)
    with pytest.raises(ValidationError, match="4 MiB"):
        ConfidenceInput(current=tuple(changed_run(run, seed=seed) for seed in range(8)))
