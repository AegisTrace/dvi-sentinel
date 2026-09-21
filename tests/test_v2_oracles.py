"""Actual local fixtures exercise consensus, uncertainty and integrity boundaries."""

import importlib.util
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.harness_models import HarnessResult
from dvi_sentinel.models import RawSource
from dvi_sentinel.oracle import (
    DetectionOracle,
    DifferentialOracle,
    EvidenceOracle,
    ProvenanceOracle,
    SchemaOracle,
    SemanticOracle,
    StatisticalOracle,
    TemporalOracle,
    evaluate_oracles,
)
from dvi_sentinel.oracle_consensus import build_consensus, oracle_artifacts
from dvi_sentinel.oracle_models import ORACLE_IDS, OracleDecision, OracleEvidence, OracleResult
from dvi_sentinel.serialization import canonical_json, digest, parse_json

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "oracle_consensus.py"
spec = importlib.util.spec_from_file_location("oracle_example", EXAMPLE)
assert spec and spec.loader
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


def fixture(delay=2000, repetitions=3):
    return example.fixture(delay, repetitions=repetitions)


def update(evidence, **changes):
    return OracleEvidence.model_validate(evidence.model_dump(mode="json") | changes)


def evaluate(evidence):
    return evaluate_oracles(evidence, expected_digest=evidence.stable_digest())


def test_real_late_alerts_confirm_gap_and_safety_pass_does_not_vote_against_it():
    evidence = fixture()
    rows = evaluate(evidence)
    result = build_consensus(rows)
    assert result.state == "confirmed" and result.confidence == 1.0
    assert result.supporting_oracles == ("detection", "statistical", "temporal")
    assert result.opposing_oracles == ()
    assert next(row for row in rows if row.oracle_id == "detection").reason_codes == (
        "DVI-MATCH-LATE",
    )
    assert all(row.input_digest == evidence.stable_digest() for row in rows)


def test_real_timely_alerts_suppress_proposed_gap():
    result = build_consensus(evaluate(fixture(500)))
    assert result.state == "suppressed_false_positive"
    assert result.opposing_oracles == ("detection", "statistical", "temporal")
    assert result.supporting_oracles == ()


def test_timing_and_metadata_disagreement_preserves_both_sides():
    evidence = fixture(500, repetitions=0)
    evidence = update(
        evidence,
        expected=evidence.expected.model_dump(mode="json") | {"signature": "fixture:other"},
    )
    result = build_consensus(evaluate(evidence))
    assert result.state == "ambiguous"
    assert result.disagreements == ("detection", "temporal")
    assert result.confidence == 0.5


@pytest.mark.parametrize("where", ["events", "observation", "repetitions", "representations"])
def test_unsafe_evidence_blocks_consumption_everywhere(where, monkeypatch):
    evidence = fixture()
    bad_raw = RawSource.from_payload({"command": "inert text"}, adapter="jsonl")
    data = evidence.model_dump(mode="json")
    if where == "events":
        data[where][0]["raw"] = bad_raw.model_dump(mode="json")
    elif where == "representations":
        data[where][0]["content"] = '{"command":"inert text"}'
    else:
        row = data[where][0] if where == "repetitions" else data[where]
        row["detections"][0]["raw"] = bad_raw.model_dump(mode="json")
    unsafe = OracleEvidence.model_validate(data)

    def must_not_run(_):
        pytest.fail("blocked inputs reached detection analysis")

    monkeypatch.setattr(DetectionOracle, "evaluate", must_not_run)
    rows = evaluate(unsafe)
    result = build_consensus(rows)
    assert result.state == "unsafe_rejected" and result.blocking_oracles == ("safety",)
    assert all(
        row.decision == "not_applicable"
        for row in rows
        if row.oracle_id not in {"safety", "provenance"}
    )
    artifact = parse_json(
        oracle_artifacts(unsafe, expected_digest=unsafe.stable_digest())["oracle_consensus.json"]
    )
    assert artifact["evidence"] is None


def test_provenance_recomputes_digest_and_blocks_changed_content(monkeypatch):
    evidence = fixture()
    pinned = evidence.stable_digest()
    changed = update(evidence, precision_digits=1)

    def must_not_run(_):
        pytest.fail("tampered evidence reached temporal analysis")

    monkeypatch.setattr(TemporalOracle, "evaluate", must_not_run)
    result = build_consensus(evaluate_oracles(changed, expected_digest=pinned))
    assert result.state == "unsafe_rejected" and result.blocking_oracles == ("provenance",)
    assert ProvenanceOracle.evaluate(evidence).decision == "unknown"
    with pytest.raises(ValidationError):
        ProvenanceOracle.evaluate(evidence, "not-a-sha256")


def test_missing_provenance_cannot_confirm_even_with_aligned_diagnostics():
    result = build_consensus(evaluate_oracles(fixture()))
    assert result.state == "not_enough_evidence" and result.confidence == 0.0


@pytest.mark.parametrize(
    "change",
    [
        {"events": []},
        {"expected": None},
        {"observation": None},
        {"required_paths": ["/events/0/observed_at"]},
    ],
)
def test_missing_evidence_blocks_confidence(change):
    evidence = update(fixture(), **change)
    result = build_consensus(evaluate(evidence))
    assert result.state == "not_enough_evidence" and result.confidence == 0.0
    assert EvidenceOracle.evaluate(evidence).decision == "unknown"


def test_core_required_evidence_cannot_be_removed():
    evidence = update(fixture(), required_paths=[], expected=None)
    assert EvidenceOracle.evaluate(evidence).decision == "unknown"


def test_complete_empty_detection_fixture_is_a_miss_but_unknown_alert_timing():
    evidence = fixture(repetitions=0)
    evidence = update(
        evidence, observation=HarnessResult(case_id=evidence.subject_id, status="complete")
    )
    rows = {row.oracle_id: row for row in evaluate(evidence)}
    assert rows["detection"].decision == "fail"
    assert rows["temporal"].decision == "unknown"
    assert build_consensus(tuple(rows.values())).state == "not_enough_evidence"


def test_incomplete_observation_is_unknown_in_both_diagnostics():
    evidence = fixture(repetitions=0)
    evidence = update(
        evidence, observation=HarnessResult(case_id=evidence.subject_id, status="unknown")
    )
    assert DetectionOracle.evaluate(evidence).decision == "unknown"
    assert TemporalOracle.evaluate(evidence).decision == "unknown"
    assert build_consensus(evaluate(evidence)).state == "unknown"


def test_statistical_warning_lowers_consensus_confidence_and_has_measured_counts():
    evidence = fixture(repetitions=1)
    stats = StatisticalOracle.evaluate(evidence)
    assert stats.decision == "warn" and "n=1" in stats.explanation
    assert stats.reason_codes == ("statistical_small_sample",)
    result = build_consensus(evaluate(evidence))
    assert result.state == "probable" and result.confidence == 0.5


def test_mixed_and_unknown_repeats_cannot_confirm():
    evidence = fixture()
    early = fixture(500).repetitions[0]
    mixed = update(evidence, repetitions=(early, *evidence.repetitions[1:]))
    assert StatisticalOracle.evaluate(mixed).decision == "warn"
    unknown = update(
        evidence,
        repetitions=(
            HarnessResult(case_id="repeat:0", status="unknown"),
            *evidence.repetitions[1:],
        ),
    )
    assert "statistical_unknown_samples" in StatisticalOracle.evaluate(unknown).reason_codes
    assert build_consensus(evaluate(unknown)).confidence <= 0.5


def test_benign_context_suppresses_gap_but_not_integrity_failure():
    evidence = fixture()
    event = evidence.events[0].model_dump(mode="json") | {"labels": ["benign"]}
    evidence = update(evidence, events=[event], representations=[])
    assert SemanticOracle.evaluate(evidence).reason_codes == ("contradictory_benign_context",)
    assert TemporalOracle.evaluate(evidence).reason_codes == ("contradictory_benign_context",)
    assert build_consensus(evaluate(evidence)).state == "suppressed_false_positive"
    assert (
        build_consensus(evaluate_oracles(evidence, expected_digest="0" * 64)).state
        == "unsafe_rejected"
    )


def test_differential_reparses_actual_representation_and_retains_changes():
    evidence = fixture()
    original = evidence.representations[0]
    payload = parse_json(original.content)
    payload["correlation_id"] = "flow:changed"
    changed = update(
        evidence,
        representations=[
            FixtureRepresentation(representation="canonical_jsonl", content=canonical_json(payload))
        ],
    )
    result = DifferentialOracle.evaluate(changed)
    assert result.decision == "warn" and "correlation_key_loss" in result.reason_codes
    assert build_consensus(evaluate(changed)).state == "probable"
    malformed = update(
        evidence,
        representations=[FixtureRepresentation(representation="canonical_jsonl", content="{")],
    )
    assert DifferentialOracle.evaluate(malformed).decision == "unknown"
    assert build_consensus(evaluate(malformed)).state == "not_enough_evidence"


def test_ontology_loss_is_an_eligibility_failure_not_an_extra_finding_vote():
    evidence = fixture()
    event = evidence.events[0].model_dump(mode="json")
    event["semantics"] = {"category": "dns", "action": "query"}
    evidence = update(evidence, events=[event], representations=[])
    assert SemanticOracle.evaluate(evidence).decision == "unknown"
    assert build_consensus(evaluate(evidence)).state == "not_enough_evidence"


def test_temporal_precision_rejects_missing_and_mismatched_source_text():
    evidence = update(fixture(), precision_digits=3)
    assert "timestamp_precision_loss" in TemporalOracle.evaluate(evidence).reason_codes
    data = evidence.model_dump(mode="json")
    data["events"][0]["raw"]["original_timestamp"] = "2026-01-01T00:00:00.000Z"
    data["observation"]["detections"][0]["raw"]["original_timestamp"] = "2026-01-01T00:00:02.000Z"
    precise = OracleEvidence.model_validate(data)
    assert TemporalOracle.evaluate(precise).decision == "fail"
    data["observation"]["detections"][0]["raw"]["original_timestamp"] = "2026-01-01T00:00:03.000Z"
    assert TemporalOracle.evaluate(OracleEvidence.model_validate(data)).decision == "unknown"


def test_temporal_keys_explicit_reference_and_unattributed_events():
    evidence = fixture()
    explicit = update(
        evidence,
        expected=evidence.expected.model_dump(mode="json")
        | {"reference_time": "2026-01-01T00:00:00Z", "correlation_id": None},
    )
    assert TemporalOracle.evaluate(explicit).decision == "fail"
    events = [evidence.events[0].model_dump(mode="json") | {"event_id": "different"}]
    unlinked = update(evidence, events=events, representations=[])
    assert "time_reference_missing" in TemporalOracle.evaluate(unlinked).reason_codes
    events = [evidence.events[0].model_dump(mode="json") | {"correlation_id": None}]
    missing = update(evidence, events=events, representations=[])
    assert "correlation_key_missing" in TemporalOracle.evaluate(missing).reason_codes
    events[0]["correlation_id"] = "flow:different"
    mismatch = update(evidence, events=events, representations=[])
    assert "correlation_key_mismatch" in TemporalOracle.evaluate(mismatch).reason_codes


def test_duplicate_or_cross_subject_or_cross_input_decisions_are_rejected():
    rows = evaluate(fixture())
    with pytest.raises(ValueError, match="duplicate"):
        build_consensus((rows[0], rows[0]))
    other = evaluate(fixture(500))
    with pytest.raises(ValueError, match="different"):
        build_consensus((rows[0], other[1]))
    with pytest.raises(ValueError, match="require"):
        build_consensus(())
    result = build_consensus((rows[0],))
    assert result.state == "not_enough_evidence"
    assert "safety" in result.missing_oracles


def test_copied_model_cannot_skip_schema_or_result_digest_validation():
    evidence = fixture()
    with pytest.raises(ValidationError):
        SchemaOracle.evaluate(evidence.model_copy(update={"precision_digits": True}))
    rows = evaluate(evidence)
    with pytest.raises(ValidationError, match="content changed"):
        build_consensus((rows[0].model_copy(update={"confidence": 0.1}), *rows[1:]))
    with pytest.raises(ValidationError):
        OracleResult.model_validate(rows[0].model_dump(mode="json") | {"oracle_id": "extra"})


@pytest.mark.parametrize(
    "change",
    [
        {"minimum_repetitions": 1},
        {"precision_digits": 7},
        {"required_paths": ["/events", "/events"]},
    ],
)
def test_configuration_bounds_are_enforced(change):
    with pytest.raises(ValidationError):
        update(fixture(), **change)


def test_event_count_duplicate_ids_and_input_bytes_are_bounded():
    evidence = fixture()
    with pytest.raises(ValidationError, match="128"):
        update(evidence, events=evidence.events * 129)
    with pytest.raises(ValidationError, match="unique"):
        update(evidence, events=evidence.events * 2)
    with pytest.raises(ValidationError, match="2 MiB"):
        update(
            evidence,
            events=[
                evidence.events[0].model_dump(mode="json")
                | {"raw": RawSource.from_payload({"inert": "x" * 2_097_152}, adapter="jsonl")}
            ],
        )


def test_primary_or_duplicate_repetitions_cannot_inflate_sample_count():
    evidence = fixture()
    with pytest.raises(ValidationError, match="primary observation"):
        update(evidence, repetitions=(evidence.observation,))
    with pytest.raises(ValidationError, match="unique"):
        update(evidence, repetitions=(evidence.repetitions[0],) * 3)


def test_standalone_analyzers_reject_unsafe_copied_evidence():
    evidence = fixture()
    raw = RawSource.from_payload({"target": "production.invalid"}, adapter="jsonl")
    evidence = update(evidence, events=[evidence.events[0].model_dump() | {"raw": raw}])
    with pytest.raises(ValueError, match="DVI-ORACLE-SAFETY"):
        DetectionOracle.evaluate(evidence)


def test_inert_evidence_paths_do_not_treat_false_or_zero_as_missing():
    evidence = update(fixture(), required_paths=("/precision_digits",))
    assert EvidenceOracle.evaluate(evidence).decision == "pass"
    unknown = update(evidence, required_paths=("/events/999/timestamp", "/events/0/timestamp/x"))
    assert EvidenceOracle.evaluate(unknown).decision == "unknown"


@given(st.permutations(ORACLE_IDS))
def test_consensus_is_invariant_to_oracle_order(order):
    # Vary the combination order of real fixture decisions.
    by_id = {row.oracle_id: row for row in evaluate(fixture())}
    assert build_consensus(tuple(by_id[name] for name in order)) == build_consensus(
        tuple(by_id.values())
    )


def test_low_confidence_gate_cannot_be_hidden_by_decisive_diagnostics():
    rows = evaluate(fixture())
    lowered = tuple(
        OracleResult.from_decision(
            OracleDecision.model_validate(row.model_dump(exclude={"digest"}) | {"confidence": 0.0})
        )
        if row.oracle_id == "evidence"
        else row
        for row in rows
    )
    result = build_consensus(lowered)
    assert result.state == "not_enough_evidence" and result.confidence == 0.0


def test_same_subject_different_input_fingerprints_cannot_be_combined():
    evidence = fixture()
    original = evaluate(evidence)
    changed = evaluate(update(evidence, precision_digits=2))
    with pytest.raises(ValueError, match="different subjects or evidence"):
        build_consensus((original[0], *changed[1:]))


@pytest.mark.parametrize(
    "delay,expected", [(0, "pass"), (1000, "pass"), (1001, "fail"), (86_400_000, "fail")]
)
def test_exact_temporal_window_boundaries(delay, expected):
    evidence = fixture(delay, repetitions=0)
    assert TemporalOracle.evaluate(evidence).decision == expected
    assert DetectionOracle.evaluate(evidence).decision == expected


def test_artifacts_recompute_and_embed_traceable_evidence_and_decision_digests():
    evidence = fixture()
    artifacts = oracle_artifacts(evidence, expected_digest=evidence.stable_digest())
    assert artifacts == oracle_artifacts(evidence, expected_digest=evidence.stable_digest())
    assert set(artifacts) == {
        "oracle_decisions.jsonl",
        "oracle_consensus.json",
        "uncertainty_report.json",
        "oracle_matrix.json",
    }
    summary = parse_json(artifacts["oracle_consensus.json"])
    assert digest(summary["evidence"]) == summary["input_digest"]
    lines = [parse_json(line) for line in artifacts["oracle_decisions.jsonl"].splitlines()]
    assert [row["oracle_id"] for row in lines] == list(ORACLE_IDS)
    for row in lines:
        expected = row.pop("digest")
        assert digest(row) == expected
        assert row["input_digest"] == summary["input_digest"]


def test_example_emits_confirmed_gap_and_protected_negative_control(tmp_path, monkeypatch):
    out = tmp_path / "oracle-proof"
    monkeypatch.setattr("sys.argv", [str(EXAMPLE), "--out", str(out)])
    example.main()
    assert (
        parse_json((out / "delayed" / "oracle_consensus.json").read_bytes())["state"] == "confirmed"
    )
    assert (
        parse_json((out / "timely" / "oracle_consensus.json").read_bytes())["state"]
        == "suppressed_false_positive"
    )
    with pytest.raises(SystemExit):
        example.main()
