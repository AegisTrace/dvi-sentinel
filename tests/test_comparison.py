from pathlib import Path

import pytest
from typer.testing import CliRunner

from dvi_sentinel.adapters import normalize
from dvi_sentinel.cli.main import app
from dvi_sentinel.comparison import compare_snapshots, snapshot_from_plan
from dvi_sentinel.comparison_models import (
    ComparisonResult,
    ComparisonSnapshot,
    ComparisonThresholds,
)
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest, LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.matching import match_detection
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.serialization import canonical_json, digest, parse_json
from dvi_sentinel.variations import plan_variations

ROOT = Path(__file__).parents[1] / "examples"
runner = CliRunner()


def snapshot(fragile=False):
    events = normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events
    config = RuleHarnessConfig(
        kind="rule_logic",
        rules=(
            LocalRule(
                id="rule",
                detector="lab",
                signature="same-identity",
                title="Count observation",
                conditions=(RuleCondition(field="action", operator="eq", value="observed"),),
                max_count=2 if fragile else None,
            ),
        ),
    )
    harness = RuleLogicHarness(config)
    plan = plan_variations(
        "comparison-proof",
        events,
        VariationPolicy(
            families=("volume",),
            max_duplicates=3,
            max_variants=8,
        ),
        42,
    )
    expected = DetectionExpectation(detector="lab", signature="same-identity")
    assessments = tuple(
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
    return snapshot_from_plan(
        plan,
        assessments,
        scenario_digest=digest({"scenario": "fixed"}),
        detector_digest=config.stable_digest(),
    )


def replace(old, **changes):
    return ComparisonSnapshot.model_validate(old.model_dump() | changes)


def test_real_regression_recovery_unchanged_and_roundtrip():
    robust, fragile = snapshot(), snapshot(True)
    regression = compare_snapshots(robust, fragile)
    assert regression.status == "regressed" and regression.exit_status == 1
    assert len(regression.newly_missed) == len(robust.assessments) - 1
    assert regression.new_fragility_classes == ("volume_sensitivity",)
    assert regression.previous.metrics.detection_rate.value == 1
    assert regression.current.metrics.detection_rate.value == 0
    assert (
        next(d for d in regression.families[0].metrics if d.metric == "detection_rate").delta == -1
    )
    recovery = compare_snapshots(fragile, robust)
    assert recovery.status == "passed" and recovery.recovered == regression.newly_missed
    assert recovery.removed_fragility_classes == ("volume_sensitivity",)
    unchanged = compare_snapshots(fragile, fragile)
    assert unchanged.status == "passed" and unchanged.unchanged_misses == regression.newly_missed
    assert not unchanged.newly_missed
    assert ComparisonResult.model_validate_json(canonical_json(regression)) == regression


@pytest.mark.parametrize(
    "field",
    [
        "scenario_id",
        "scenario_digest",
        "input_digest",
        "config_digest",
        "tool_version",
        "seed",
        "schema_version",
    ],
)
def test_incompatible_metadata_never_produces_numeric_comparison(field):
    old = snapshot()
    value = (
        digest({"changed": True}) if "digest" in field else 43 if field == "seed" else "different"
    )
    result = compare_snapshots(old, replace(old, **{field: value}))
    assert result.status == "incompatible" and result.exit_status == 2
    assert result.previous is result.current is None and not result.metrics


def test_missing_case_and_changed_candidate_content_are_incompatible():
    old = snapshot()
    missing_id = old.assessments[-1].case_id
    missing = replace(
        old,
        assessments=old.assessments[:-1],
        case_input_digests={
            key: value for key, value in old.case_input_digests.items() if key != missing_id
        },
    )
    assert compare_snapshots(old, missing).status == "incompatible"
    changed = replace(
        old, case_input_digests=old.case_input_digests | {missing_id: digest("changed")}
    )
    assert compare_snapshots(old, changed).status == "incompatible"


def test_threshold_boundary_is_inclusive_and_all_gates_remain_visible():
    old, new = snapshot(), snapshot(True)
    count = len(old.assessments) - 1
    limits = ComparisonThresholds(max_detection_rate_drop=1, max_new_misses=count)
    result = compare_snapshots(old, new, limits)
    assert result.status == "passed" and all(t.status == "pass" for t in result.thresholds)
    assert (
        compare_snapshots(
            old, new, ComparisonThresholds(max_detection_rate_drop=0.999, max_new_misses=count)
        ).status
        == "regressed"
    )
    assert (
        compare_snapshots(
            old, new, ComparisonThresholds(max_detection_rate_drop=1, max_new_misses=count - 1)
        ).status
        == "regressed"
    )


def test_empty_measurements_are_unknown_and_detector_change_is_allowed():
    old = snapshot()
    empty = replace(old, assessments=[], case_input_digests={})
    result = compare_snapshots(empty, empty)
    assert result.status == "unknown" and result.exit_status == 2
    assert (
        compare_snapshots(old, replace(old, detector_digest=digest("new detector"))).status
        == "passed"
    )


def test_determinism_independent_of_input_assessment_order():
    old, new = snapshot(), snapshot(True)
    assert canonical_json(compare_snapshots(old, new)) == canonical_json(
        compare_snapshots(
            replace(old, assessments=tuple(reversed(old.assessments))),
            replace(new, assessments=tuple(reversed(new.assessments))),
        )
    )


def test_cli_actual_snapshots_json_human_thresholds_and_exit_codes(tmp_path):
    previous, current = tmp_path / "old.json", tmp_path / "new.json"
    previous.write_text(canonical_json(snapshot()), encoding="utf-8")
    current.write_text(canonical_json(snapshot(True)), encoding="utf-8")
    result = runner.invoke(app, ["compare", str(previous), str(current), "--json"])
    assert result.exit_code == 1
    report = parse_json(result.stdout)
    assert report["status"] == "regressed" and report["newly_missed"]
    human = runner.invoke(app, ["compare", str(previous), str(current)])
    assert human.exit_code == 1 and "Newly missed:" in human.stdout and "Family" in human.stdout
    accepted = runner.invoke(
        app,
        [
            "compare",
            str(previous),
            str(current),
            "--max-detection-drop",
            "1",
            "--max-new-misses",
            "100",
        ],
    )
    assert accepted.exit_code == 0
    same = runner.invoke(app, ["compare", str(previous), str(previous), "--json"])
    assert same.exit_code == 0


def test_cli_malformed_duplicate_key_and_missing_inputs_are_exit_two(tmp_path):
    path = tmp_path / "bad.json"
    for content in ("{bad}", '{"schema_version":"1","schema_version":"2"}'):
        path.write_text(content, encoding="utf-8")
        result = runner.invoke(app, ["compare", str(path), str(path), "--json"])
        assert result.exit_code == 2 and parse_json(result.stdout)["status"] == "invalid_input"
    result = runner.invoke(app, ["compare", str(tmp_path / "missing.json"), str(path), "--json"])
    assert result.exit_code == 2


def test_adapter_disagreement_change_and_coverage_guard():
    events = normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events
    reports = []
    for field in ("category", "raw.category"):
        detector = RuleLogicHarness(
            RuleHarnessConfig(
                kind="rule_logic",
                rules=(
                    LocalRule(
                        id="schema",
                        detector="lab",
                        signature="same",
                        title="Schema observation",
                        conditions=(RuleCondition(field=field, operator="exists"),),
                    ),
                ),
            )
        )
        reports.append(run_differential(events, detector))
    old = replace(snapshot(), differential=reports[0])
    new = replace(snapshot(), differential=reports[1])
    result = compare_snapshots(old, new)
    change = next(d for d in result.metrics if d.metric == "adapter_disagreement_rate")
    assert change.previous == 0 and change.current == change.delta == 0.5
    assert result.status == "regressed" and result.new_fragility_classes == ("schema",)
    assert (
        compare_snapshots(
            old, new, ComparisonThresholds(max_adapter_disagreement_increase=0.5)
        ).status
        == "passed"
    )
    assert compare_snapshots(old, snapshot()).status == "incompatible"


@pytest.mark.parametrize("failure", ["parser", "invariant"])
def test_lost_validity_or_parsing_cannot_hide_a_regression(failure):
    old = snapshot()
    row = old.assessments[-1].model_dump()
    if failure == "parser":
        row["parser_success"] = False
    else:
        row["preservation"]["checks"][0]["passed"] = False
    new = replace(old, assessments=(*old.assessments[:-1], CaseAssessment.model_validate(row)))
    result = compare_snapshots(old, new)
    assert result.status == "regressed"
    metric = "unknown_rate" if failure == "parser" else "semantic_preservation_rate"
    assert next(t for t in result.thresholds if t.metric == metric).status == "fail"
