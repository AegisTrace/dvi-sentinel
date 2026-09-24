"""Observed history transitions, conservative gates and persisted baseline integrity."""

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

import dvi_sentinel.confidence as confidence_engine
import dvi_sentinel.regression_memory as engine
from dvi_sentinel.confidence_models import ConfidenceInput, ConfidenceSettings
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import RawSource
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.regression_memory import (
    analyze_drift,
    append_record,
    register_baseline,
    regression_memory_artifacts,
)
from dvi_sentinel.regression_memory_io import load_regression_memory
from dvi_sentinel.regression_memory_models import (
    BaselineEntry,
    DriftInput,
    DriftMemory,
    DriftPolicy,
    DriftRecord,
    DriftReport,
    PinnedRecord,
    ProfileStamp,
)
from dvi_sentinel.schema_profiles import schema_profile
from dvi_sentinel.serialization import canonical_json
from examples.regression_memory import fixture_record
from tests.test_v2_confidence import changed_run

FIXTURE_POLICY = DriftPolicy(minimum_confidence="low_confidence", max_plausible_detection_drop=0.15)


def record(sequence, fragile=False, count=4, seeds=(1, 2)):
    return fixture_record(sequence, fragile=fragile, count=count, seeds=seeds)


def memory(*records, baseline=None):
    entries = (
        ()
        if baseline is None
        else (
            BaselineEntry(
                name=baseline[0],
                record_id=baseline[1].id,
                record_digest=baseline[1].stable_digest(),
            ),
        )
    )
    return DriftMemory(
        records=tuple(PinnedRecord(record=r, expected_digest=r.stable_digest()) for r in records),
        baselines=entries,
    )


def request(*records, current_id=None, baseline=None, policy=None):
    return DriftInput(
        memory=memory(*records, baseline=baseline),
        current_id=current_id or records[-1].id,
        named_baseline=baseline[0] if baseline else None,
        policy=policy or DriftPolicy(),
    )


def analyze(value):
    return analyze_drift(value, expected_digest=value.stable_digest())


def replace(value, **changes):
    return type(value).model_validate(value.model_dump(mode="python") | changes)


def scheduled(sequence, statuses):
    source = record(sequence, count=len(statuses[0]), seeds=tuple(range(1, len(statuses) + 1)))
    runs = tuple(
        changed_run(run, statuses=schedule)
        for run, schedule in zip(source.measurement.current, statuses, strict=True)
    )
    return replace(
        source,
        detector=replace(
            source.detector,
            version="fixture-schedule-v1",
            definition_digest=runs[0].snapshot.detector_digest,
        ),
        measurement=ConfidenceInput(current=runs, settings=source.measurement.settings),
    )


@pytest.mark.parametrize(
    "before,after,classification,gate",
    [
        (False, False, "stable_strong", "unknown"),
        (True, True, "still_fragile", "unknown"),
        (False, True, "newly_fragile", "fail"),
        (True, False, "recovered", "unknown"),
    ],
)
def test_measured_local_transitions_keep_class_separate_from_precision(
    before, after, classification, gate
):
    report = analyze(request(record(0, before), record(1, after)))
    assert report.classification == classification and report.gate.status == gate
    assert len(report.trend) == 1 and len(report.trend[0].seed_results) == 2
    assert "confidence_below_floor" in report.gate.reasons
    if gate == "fail":
        assert "legacy_regression" in report.gate.reasons
    assert all(
        c.legacy.status == ("regressed" if gate == "fail" else "passed")
        for c in report.trend[0].seed_results
    )


def test_small_regression_with_interval_including_zero_still_fails():
    report = analyze(request(record(0, count=1), record(1, True, count=1)))
    assert report.gate.status == "fail" and report.gate.exit_status == 1
    assert report.trend[0].seed_results[0].effects[0].direction == "includes_zero"


def test_current_previous_baseline_and_older_trend_decisions_are_distinct():
    rows = (
        record(0, count=32),
        record(1, True, count=32),
        record(2, True, count=32),
        record(3, count=32),
    )
    report = analyze(request(*rows, baseline=("release", rows[0]), policy=FIXTURE_POLICY))
    assert [c.classification for c in report.trend] == [
        "newly_fragile",
        "still_fragile",
        "recovered",
    ]
    assert [c.gate.status for c in report.trend] == ["fail", "pass", "pass"]
    assert report.classification == "recovered" and report.gate.status == "pass"
    assert report.baseline_comparison.classification == "stable_strong"
    assert report.baseline_comparison.previous_id == rows[0].id
    assert report.trend[-1].previous_id == rows[2].id
    assert report.input.memory.baselines[0].record_id == rows[0].id


def test_baseline_regression_vetoes_unchanged_predecessor():
    rows = (record(0, count=32), record(1, True, count=32), record(2, True, count=32))
    report = analyze(request(*rows, baseline=("release", rows[0]), policy=FIXTURE_POLICY))
    assert report.trend[-1].gate.status == "pass"
    assert report.baseline_comparison.classification == "newly_fragile"
    assert report.gate.status == "fail"


def test_partial_recovery_keeps_remaining_fragility_visible():
    after = scheduled(1, (("detected", "detected", "missed", "detected"),) * 2)
    report = analyze(request(record(0, True), after))
    assert report.classification == "still_fragile"
    effect = report.trend[0].seed_results[0].effects[0]
    assert effect.recovered == 1 and effect.lost == 0
    assert report.trend[0].seed_results[0].legacy.current.metrics.missed == 1


def test_churn_and_seed_disagreement_are_unstable():
    left = scheduled(0, (("detected", "missed"),) * 2)
    right = scheduled(1, (("missed", "detected"),) * 2)
    report = analyze(request(left, right))
    assert report.classification == "unstable" and report.gate.status == "fail"
    differing = scheduled(1, (("detected", "missed"), ("missed", "detected")))
    unstable = analyze(request(record(0, count=2), differing))
    assert (
        unstable.classification == "unstable" and "unstable_observations" in unstable.gate.reasons
    )


def test_different_transition_classes_across_seeds_are_unstable():
    after = scheduled(1, (("detected",) * 4, ("detected", "missed", "detected", "detected")))
    report = analyze(request(record(0), after))
    assert report.classification == "unstable"


def test_unknown_current_case_never_passes_even_with_permissive_drop_limit():
    after = scheduled(1, (("unknown", "detected"),) * 2)
    policy = DriftPolicy(minimum_confidence="low_confidence", max_plausible_detection_drop=1)
    report = analyze(request(record(0, count=2), after, policy=policy))
    assert report.classification == "unknown" and report.gate.status != "pass"
    assert "case_outcomes_unresolved" in report.gate.reasons


@pytest.mark.parametrize("kind", ["missing_control", "empty_variants", "one_seed"])
def test_incomplete_controls_and_seed_evidence_do_not_pass(kind):
    count = 0 if kind == "empty_variants" else 32
    seeds = (1,) if kind == "one_seed" else (1, 2)
    rows = [record(i, count=count, seeds=seeds) for i in (0, 1)]
    if kind == "missing_control":
        rows = [
            replace(
                r,
                measurement=replace(
                    r.measurement,
                    current=tuple(
                        changed_run(
                            run,
                            drop=tuple(
                                a.case_id
                                for a in run.snapshot.assessments
                                if a.family == "baseline"
                            ),
                        )
                        for run in r.measurement.current
                    ),
                ),
            )
            for r in rows
        ]
    report = analyze(request(*rows, policy=FIXTURE_POLICY))
    assert report.gate.status == "unknown"
    assert report.classification == ("stable_strong" if kind == "one_seed" else "unknown")


def test_effect_limit_is_inclusive_and_independent_of_confidence_floor():
    value = request(record(0, count=32), record(1, count=32), policy=FIXTURE_POLICY)
    report = analyze(value)
    effect = report.trend[0].seed_results[0].effects[0]
    limit = -effect.lower
    exact = replace(value, policy=replace(FIXTURE_POLICY, max_plausible_detection_drop=limit))
    assert analyze(exact).gate.status == "pass"
    narrower = replace(
        exact, policy=replace(exact.policy, max_plausible_detection_drop=math.nextafter(limit, 0))
    )
    assert analyze(narrower).gate.status == "unknown"
    stricter = replace(
        value, policy=replace(FIXTURE_POLICY, minimum_confidence="moderate_confidence")
    )
    assert analyze(stricter).gate.status == "unknown"


def test_default_gate_can_pass_sufficient_declared_sampling_evidence():
    rows = tuple(
        replace(
            r,
            measurement=replace(
                r.measurement,
                settings=ConfidenceSettings(
                    bootstrap_resamples=100, independent_trials_assumed=True
                ),
            ),
        )
        for r in (record(0, count=100), record(1, count=100))
    )
    report = analyze(request(*rows))
    assert report.classification == "stable_strong" and report.gate.status == "pass"
    assert all(
        g.confidence_class == "moderate_confidence"
        for p in report.points
        for g in p.confidence.groups
    )


@pytest.mark.parametrize(
    "kind,reason",
    [
        ("contract", "detector_contract_changed"),
        ("reused_version", "detector_version_reused"),
        ("profile", "schema_profiles_changed"),
        ("profile_revision", "schema_profile_unsupported"),
        ("profile_digest", "schema_profile_unsupported"),
        ("settings", "statistical_settings_changed"),
        ("seeds", "seed_sets_changed"),
    ],
)
def test_metadata_compatibility_precedes_paired_arithmetic(monkeypatch, kind, reason):
    left, right = record(0), record(1, True)
    if kind == "contract":
        right = replace(right, detector=replace(right.detector, comparison_contract="changed"))
    elif kind == "reused_version":
        right = replace(right, detector=replace(right.detector, version=left.detector.version))
    elif kind == "profile":
        right = replace(right, profiles=(ProfileStamp.from_profile(schema_profile("ecs_like")),))
    elif kind in {"profile_revision", "profile_digest"}:
        right = replace(
            right,
            profiles=(
                replace(
                    right.profiles[0],
                    **(
                        {"revision": "2"}
                        if kind == "profile_revision"
                        else {"definition_digest": "0" * 64}
                    ),
                ),
            ),
        )
    elif kind == "settings":
        right = replace(
            right,
            measurement=replace(
                right.measurement, settings=ConfidenceSettings(bootstrap_resamples=200)
            ),
        )
    else:
        right = record(1, True, seeds=(3, 4))

    def forbidden(*args, **kwargs):
        pytest.fail("incompatible metadata reached paired arithmetic")

    monkeypatch.setattr(engine, "_comparisons", forbidden)
    report = analyze(request(left, right))
    assert report.classification == "incompatible" and report.gate.status == "unknown"
    assert reason in report.trend[0].reasons and not report.trend[0].seed_results


@pytest.mark.parametrize(
    "field", ["tool_version", "scenario_id", "scenario_digest", "input_digest", "config_digest"]
)
def test_existing_v1_compatibility_and_reasons_survive(field):
    left, right = record(0), record(1)
    value = "changed" if field in {"tool_version", "scenario_id"} else "0" * 64
    right = replace(
        right,
        measurement=replace(
            right.measurement,
            current=tuple(changed_run(run, **{field: value}) for run in right.measurement.current),
        ),
    )
    report = analyze(request(left, right))
    assert report.classification == "incompatible" and not report.trend[0].seed_results
    assert any(field in detail for detail in report.trend[0].compatibility_details)


def test_version_reuse_is_detected_across_nonadjacent_history():
    first, second, third = record(0), record(1, True), record(2, True)
    third = replace(third, detector=replace(third.detector, version=first.detector.version))
    report = analyze(request(first, second, third))
    assert all(c.classification == "incompatible" for c in report.trend)
    assert "detector_version_reused" in report.trend[-1].reasons


def test_missing_current_previous_and_named_baselines_remain_unknown():
    first, second = record(0), record(1)
    for value, reason in (
        (DriftInput(memory=DriftMemory(), current_id="absent"), "current_record_missing"),
        (request(first), "previous_record_missing"),
        (replace(request(first, second), named_baseline="absent"), "named_baseline_missing"),
    ):
        result = analyze(value)
        assert result.classification == "unknown" and result.gate.status == "unknown"
        assert reason in result.gate.reasons
    regression = replace(request(first, record(1, True)), named_baseline="absent")
    assert analyze(regression).gate.status == "fail"


def test_selected_historical_record_never_compares_to_a_future_or_self_baseline():
    rows = (record(0), record(1), record(2))
    for baseline in (rows[1], rows[2]):
        report = analyze(request(*rows, current_id=rows[1].id, baseline=("release", baseline)))
        assert len(report.points) == 2 and len(report.trend) == 1
        assert report.classification == "incompatible" and report.gate.status == "unknown"
        assert "reference_not_earlier" in report.baseline_comparison.reasons


def test_append_and_baseline_registration_are_immutable_and_idempotent():
    first, second = record(0), record(1)
    empty = DriftMemory()
    state = append_record(
        empty,
        first,
        expected_digest=empty.stable_digest(),
        expected_record_digest=first.stable_digest(),
    )
    assert empty.records == ()
    assert (
        append_record(
            state,
            first,
            expected_digest=state.stable_digest(),
            expected_record_digest=first.stable_digest(),
        )
        == state
    )
    state = register_baseline(state, "release", first.id, expected_digest=state.stable_digest())
    assert (
        register_baseline(state, "release", first.id, expected_digest=state.stable_digest())
        == state
    )
    state = append_record(
        state,
        second,
        expected_digest=state.stable_digest(),
        expected_record_digest=second.stable_digest(),
    )
    assert state.baselines[0].record_id == first.id
    with pytest.raises(ValueError, match="cannot be replaced"):
        register_baseline(state, "release", second.id, expected_digest=state.stable_digest())
    with pytest.raises(ValueError, match="absent"):
        register_baseline(state, "missing", "absent", expected_digest=state.stable_digest())
    altered = replace(first, sequence=10)
    with pytest.raises(ValueError, match="cannot be replaced"):
        append_record(
            state,
            altered,
            expected_digest=state.stable_digest(),
            expected_record_digest=altered.stable_digest(),
        )
    old = replace(first, id="old")
    with pytest.raises(ValueError, match="last sequence"):
        append_record(
            state,
            old,
            expected_digest=state.stable_digest(),
            expected_record_digest=old.stable_digest(),
        )


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_request_pin_blocks_before_consumption(monkeypatch, pin):
    value = request(record(0), record(1))

    def forbidden(*args, **kwargs):
        pytest.fail("unpinned history was consumed")

    monkeypatch.setattr(engine, "_verify_memory", forbidden)
    result = analyze_drift(value, expected_digest=pin)
    assert result.input is None and not result.points and not result.trend
    assert result.gate.status == ("unknown" if pin is None else "fail")


@pytest.mark.parametrize(
    "kind", ["record_pin", "baseline_pin", "missing_baseline_target", "evidence_pin", "safety"]
)
def test_all_history_integrity_failures_block_before_any_matching(monkeypatch, kind):
    first, second = record(0), record(1)
    data = request(first, second, baseline=("release", first)).model_dump(mode="python")
    ledger = data["memory"]
    if kind == "record_pin":
        ledger["records"][0]["expected_digest"] = "0" * 64
    elif kind == "baseline_pin":
        ledger["baselines"][0]["record_digest"] = "0" * 64
    elif kind == "missing_baseline_target":
        ledger["baselines"][0]["record_id"] = "absent"
    else:
        row = ledger["records"][1]
        proof = row["record"]["measurement"]["current"][0]["evidence"][0]
        if kind == "evidence_pin":
            proof["expected_digest"] = "0" * 64
        else:
            proof["evidence"]["events"][0]["raw"] = RawSource.from_payload(
                {"src_ip": "8.8.8.8"}, adapter="jsonl"
            ).model_dump()
            proof["expected_digest"] = OracleEvidence.model_validate(
                proof["evidence"]
            ).stable_digest()
        row["expected_digest"] = DriftRecord.model_validate(row["record"]).stable_digest()
    value = DriftInput.model_validate(data)

    def forbidden(*args, **kwargs):
        pytest.fail("rejected history reached a matcher")

    monkeypatch.setattr(confidence_engine, "match_detection", forbidden)
    report = analyze(value)
    assert (
        report.state == "unsafe_rejected" and report.gate.status == "fail" and report.input is None
    )
    assert not report.points and "8.8.8.8" not in canonical_json(report)


def test_record_metadata_must_link_and_snapshots_are_verified_again():
    row = record(0)
    for changes in ({"detector_id": "different"}, {"definition_digest": "0" * 64}):
        with pytest.raises(ValidationError, match="DETECTOR"):
            replace(row, detector=replace(row.detector, **changes))
    data = row.model_dump(mode="python")
    data["measurement"]["current"][0]["snapshot"]["assessments"][0]["match"] = None
    invalid = DriftRecord.model_validate(data)
    with pytest.raises(ValueError, match="MATCH"):
        analyze(request(invalid, record(1)))


def test_canonical_history_order_and_report_tamper_rejection():
    first, second = record(0), record(1, True)
    value = request(second, first, current_id=second.id, baseline=("release", first))
    assert [p.record.sequence for p in value.memory.records] == [0, 1]
    report = analyze(value)
    assert DriftReport.model_validate_json(canonical_json(report)) == report
    for kind in (
        "classification",
        "gate",
        "trend",
        "point",
        "baseline",
        "interpretation",
        "confidence",
    ):
        data = report.model_dump(mode="json")
        if kind == "classification":
            data["classification"] = "stable_strong"
        elif kind == "gate":
            data["gate"] = {"status": "pass", "exit_status": 0, "reasons": ["forged"]}
        elif kind == "trend":
            data["trend"][0]["current_id"] = "forged"
        elif kind == "point":
            data["points"][0]["record_digest"] = "0" * 64
        elif kind == "baseline":
            data["baseline_comparison"] = None
        elif kind == "interpretation":
            data["interpretation"] = "Guaranteed"
        else:
            data["points"][0]["confidence"]["groups"][0]["confidence_class"] = "high_confidence"
        with pytest.raises(ValidationError):
            DriftReport.model_validate(data)


def test_artifacts_reload_and_resume_keep_the_original_baseline(tmp_path):
    first, second, third = record(0), record(1, True), record(2)
    value = request(first, second, baseline=("release", first))
    artifacts = regression_memory_artifacts(value, expected_digest=value.stable_digest())
    for name, data in artifacts.items():
        (tmp_path / name).write_bytes(data)
    restored = load_regression_memory(
        tmp_path, "regression_memory.json", expected_digest=value.memory.stable_digest()
    )
    resumed = append_record(
        restored,
        third,
        expected_digest=restored.stable_digest(),
        expected_record_digest=third.stable_digest(),
    )
    assert resumed.baselines == value.memory.baselines and len(resumed.records) == 3
    assert artifacts == regression_memory_artifacts(value, expected_digest=value.stable_digest())
    assert (
        json.loads(artifacts["baseline_registry.json"])["entries"]
        == value.memory.model_dump(mode="json")["baselines"]
    )
    report = DriftReport.model_validate_json(artifacts["trend_report.json"])
    assert (
        json.loads(artifacts["comparison_with_uncertainty.json"])["trend"]
        == report.model_dump(mode="json")["trend"]
    )
    with pytest.raises(ValueError, match="digest differs"):
        load_regression_memory(tmp_path, "regression_memory.json", expected_digest="0" * 64)
    blocked = regression_memory_artifacts(value)
    (tmp_path / "blocked.json").write_bytes(blocked["regression_memory.json"])
    with pytest.raises(ValueError, match="blocked artifact"):
        load_regression_memory(
            tmp_path, "blocked.json", expected_digest=value.memory.stable_digest()
        )


@pytest.mark.parametrize(
    "path",
    [
        "../memory.json",
        "/memory.json",
        "C:/memory.json",
        "a%2fmemory.json",
        "con.json",
        "a\\memory.json",
        "a//memory.json",
    ],
)
def test_reader_rejects_unsafe_paths_without_reading(tmp_path, path):
    with pytest.raises(ValueError):
        load_regression_memory(tmp_path, path, expected_digest="0" * 64)


def test_reader_rejects_duplicate_keys_and_byte_overflow(tmp_path):
    (tmp_path / "duplicate.json").write_text('{"schema_version":"1","schema_version":"1"}')
    with pytest.raises(ValueError, match="duplicate"):
        load_regression_memory(tmp_path, "duplicate.json", expected_digest="0" * 64)
    (tmp_path / "large.json").write_bytes(b" " * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="exceeds"):
        load_regression_memory(tmp_path, "large.json", expected_digest="0" * 64)


def test_reader_rejects_linked_roots_and_children(tmp_path, monkeypatch):
    (tmp_path / "memory.json").write_text("{}")
    original = Path.is_junction
    monkeypatch.setattr(Path, "is_junction", lambda p: p == tmp_path or original(p))
    with pytest.raises(ValueError, match="plain local root"):
        load_regression_memory(tmp_path, "memory.json", expected_digest="0" * 64)
    monkeypatch.setattr(Path, "is_junction", lambda p: p.name == "memory.json" or original(p))
    with pytest.raises(ValueError, match="linked paths"):
        load_regression_memory(tmp_path, "memory.json", expected_digest="0" * 64)


def test_identity_size_and_append_pin_bounds():
    first = record(0, count=0)
    with pytest.raises(ValidationError, match="unique"):
        memory(first, replace(first, sequence=1))
    with pytest.raises(ValidationError, match="unique"):
        memory(first, replace(first, id="other"))
    with pytest.raises(ValidationError):
        memory(*(replace(first, id=f"run:{i}", sequence=i) for i in range(9)))
    with pytest.raises(ValueError, match="memory digest"):
        append_record(
            DriftMemory(),
            first,
            expected_digest="0" * 64,
            expected_record_digest=first.stable_digest(),
        )
    with pytest.raises(ValueError, match="new record digest"):
        append_record(
            DriftMemory(),
            first,
            expected_digest=DriftMemory().stable_digest(),
            expected_record_digest="0" * 64,
        )
    larger = record(0, count=100, seeds=(1, 2, 3))
    with pytest.raises(ValidationError, match="512"):
        memory(larger, replace(larger, id="later", sequence=1))


def test_runnable_example_persists_real_history_and_refuses_overwrite(tmp_path):
    root = Path(__file__).parents[1]
    destination = tmp_path / "proof"
    command = [
        sys.executable,
        str(root / "examples/regression_memory.py"),
        "--out",
        str(destination),
    ]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    report = json.loads((destination / "trend_report.json").read_bytes())
    assert report["classification"] == "recovered" and report["gate"]["status"] == "pass"
    assert len(list(destination.iterdir())) == 4
    before = (destination / "regression_memory.json").read_bytes()
    repeat = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
    assert repeat.returncode != 0 and "new local directory" in repeat.stderr
    assert (destination / "regression_memory.json").read_bytes() == before


@pytest.mark.parametrize("change", ["detector_identity", "expectation"])
def test_changed_detector_identity_and_expectation_are_explicitly_incompatible(change):
    left, right = record(0), record(1)
    data = right.model_dump(mode="python")
    if change == "detector_identity":
        data["detector"]["detector_id"] = "fixture:other-detector"
    for run in data["measurement"]["current"]:
        proofs = {p["evidence"]["subject_id"]: p for p in run["evidence"]}
        for row in run["snapshot"]["assessments"]:
            proof = proofs[row["case_id"]]
            if change == "detector_identity":
                proof["evidence"]["expected"]["detector"] = "fixture:other-detector"
                for event in proof["evidence"]["observation"]["detections"]:
                    event["detector"] = "fixture:other-detector"
            else:
                proof["evidence"]["expected"]["max_delay_ms"] = 20
            evidence = OracleEvidence.model_validate(proof["evidence"])
            proof["expected_digest"] = evidence.stable_digest()
            row["match"] = match_detection(
                evidence.expected, evidence.observation, evidence.events
            ).model_dump()
    report = analyze(request(left, DriftRecord.model_validate(data)))
    assert report.classification == "incompatible" and report.gate.status == "unknown"
    code = (
        "detector_identity_changed"
        if change == "detector_identity"
        else "case_expectations_changed"
    )
    assert code in report.trend[0].reasons and not report.trend[0].seed_results


def test_combined_history_byte_limit_is_checked_before_consumption():
    data = record(0, count=0, seeds=(1,)).model_dump(mode="python")
    proof = data["measurement"]["current"][0]["evidence"][0]
    proof["evidence"]["events"][0]["raw"] = RawSource.from_payload(
        {"description": "x" * 600000}, adapter="jsonl"
    ).model_dump()
    large = DriftRecord.model_validate(data)
    with pytest.raises(ValidationError, match="4 MiB"):
        memory(*(replace(large, id=f"large:{i}", sequence=i) for i in range(8)))


def test_combined_artifact_limit_rejects_oversized_serialization(monkeypatch):
    value = request(record(0, count=0))
    monkeypatch.setattr(engine, "canonical_json", lambda _: "x" * (8 * 1024 * 1024))
    with pytest.raises(ValueError, match="32 MiB"):
        regression_memory_artifacts(value, expected_digest=value.stable_digest())
