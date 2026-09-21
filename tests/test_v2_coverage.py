"""Evidence-derived novelty, conservative unknowns and deterministic retention."""

import importlib.util
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

import dvi_sentinel.semantic_coverage as engine
from dvi_sentinel.coverage_models import DIMENSIONS, CoverageCaseInput, SemanticCoverage
from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.fixture_encoding import encode_fixture
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.semantic_coverage import (
    analyze_coverage,
    coverage_artifacts,
    coverage_evidence_gate,
    measure_case,
)
from dvi_sentinel.serialization import digest, parse_json

EXAMPLE = Path(__file__).parents[1] / "examples" / "semantic_coverage.py"
spec = importlib.util.spec_from_file_location("coverage_example", EXAMPLE)
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


def fixture(case_id="case:timely", delay=500):
    return example.fixture(case_id, delay)


def replace_evidence(case, **changes):
    evidence = OracleEvidence.model_validate(case.evidence.model_dump(mode="python") | changes)
    return CoverageCaseInput.model_validate(
        case.model_dump(mode="python")
        | {"evidence": evidence, "expected_digest": evidence.stable_digest()}
    )


def values(report, dimension):
    return {t.value for t in report.tokens if t.dimension == dimension}


def observations(case):
    return {row.dimension: row for row in case.observations}


def test_new_measured_matcher_branch_and_timing_state_increase_coverage():
    timely = fixture()
    late = fixture("case:late", 2000)
    baseline = analyze_coverage((timely,))
    result = analyze_coverage((timely, late))
    assert result.evidence_gate.passed
    assert len(result.tokens) > len(baseline.tokens)
    assert "DVI-MATCH-LATE" in values(result, "matcher_branch")
    assert "DVI-MATCH-LATE" not in values(baseline, "matcher_branch")
    assert "timestamp_timezone" in values(result, "fragility_class")
    assert values(result, "semantic_signal") == values(baseline, "semantic_signal")
    assert sum(row.retained for row in result.retention) == 2


def test_duplicate_observation_with_a_new_case_id_does_not_inflate_coverage():
    baseline = analyze_coverage((fixture(),))
    result = analyze_coverage((fixture(), fixture("case:duplicate")))
    assert result.tokens == baseline.tokens
    assert sum(row.retained for row in result.retention) == 1
    assert {row.reason for row in result.retention} == {"new_coverage", "duplicate_coverage"}
    assert result.growth[-1].added == 0
    assert all(row.explanation for row in result.retention)


def test_new_semantic_meaning_and_different_invariant_state_add_distinct_tokens():
    baseline = fixture()
    changed = fixture("case:action")
    event = changed.evidence.events[0]
    candidate = TelemetryEvent.model_validate(
        event.model_dump()
        | {
            "semantics": event.semantics.model_dump() | {"action": "different_observation"},
        }
    )
    changed = replace_evidence(
        changed,
        events=(candidate,),
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl",
                content=encode_fixture((candidate,), "canonical_jsonl"),
            ),
        ),
    )
    report = analyze_coverage((baseline, changed))
    assert len(values(report, "semantic_signal")) == 2
    assert values(report, "invariant_state") == {"equivalent", "different"}


def test_executed_adapter_and_profile_paths_add_coverage():
    baseline = fixture()
    expanded = fixture("case:paths")
    expanded = replace_evidence(
        expanded,
        representations=(
            *expanded.evidence.representations,
            FixtureRepresentation(
                representation="suricata_eve",
                content=encode_fixture(expanded.evidence.events, "suricata_eve"),
            ),
        ),
    )
    expanded = expanded.model_copy(update={"profiles": ("ecs_like", "dvi")})
    report = analyze_coverage((baseline, expanded))
    original = analyze_coverage((baseline,))
    assert "suricata_eve->suricata_eve:parsed" in values(report, "adapter_path")
    assert len(values(report, "field_mapping_path")) > len(values(original, "field_mapping_path"))
    assert any(value.startswith("ecs_like:") for value in values(report, "schema_profile_path"))


def test_unbound_raw_metadata_digests_do_not_create_semantic_novelty():
    case = fixture()
    copy = fixture("case:metadata")
    event = copy.evidence.events[0]
    raw = RawSource.from_payload(
        event.raw.payload | {"fixture_note": "an additional inert note"},
        adapter="jsonl",
        original_timestamp=event.raw.original_timestamp,
    )
    changed = TelemetryEvent.model_validate(event.model_dump() | {"raw": raw})
    copy = replace_evidence(
        copy,
        events=(changed,),
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl",
                content=encode_fixture((changed,), "canonical_jsonl"),
            ),
        ),
    )
    result = analyze_coverage((case, copy))
    assert result.tokens == analyze_coverage((case,)).tokens
    assert sum(row.retained for row in result.retention) == 1


@given(st.integers(min_value=0, max_value=2**63 - 1))
@settings(max_examples=12, deadline=None)
def test_seed_and_input_order_determinism(seed):
    inputs = (fixture(), fixture("case:late", 2000), fixture("case:duplicate"))
    a = analyze_coverage(inputs, seed=seed)
    b = analyze_coverage(tuple(reversed(inputs)), seed=seed)
    assert a == b
    assert sum(row.retained for row in a.retention) == 2
    assert tuple(row.dimension for row in a.cases[0].observations) == DIMENSIONS


def test_growth_is_an_exact_union_with_canonical_dimension_value_tokens():
    result = analyze_coverage(
        (fixture(), fixture("case:late", 2000), fixture("case:copy")), seed=42
    )
    accumulated = set()
    for case, decision, point in zip(result.cases, result.retention, result.growth, strict=True):
        current = {
            (row.dimension, value)
            for row in case.observations
            if row.state == "known"
            for value in row.values
        }
        assert {
            (token.dimension, token.value) for token in decision.new_tokens
        } == current - accumulated
        accumulated |= current
        assert point.cumulative == len(accumulated)
    assert tuple((token.dimension, token.value) for token in result.tokens) == tuple(
        sorted(accumulated)
    )


@pytest.mark.parametrize("missing", ["expected_digest", "reference_digest"])
def test_skipped_unknown_cases_cannot_make_the_evidence_gate_pass(missing):
    incomplete = fixture("case:missing").model_copy(update={missing: None})
    result = analyze_coverage((fixture(), incomplete))
    decision = next(row for row in result.retention if row.case_id == "case:missing")
    assert not decision.retained and decision.reason == "unknown_coverage"
    assert result.evidence_gate.state == "unknown" and not result.evidence_gate.passed
    assert result.evidence_gate.unresolved_cases == ("case:missing",)
    assert not coverage_evidence_gate((incomplete,)).passed
    assert not coverage_evidence_gate(()).passed


@pytest.mark.parametrize(
    "missing,dimension",
    [
        ("representations", "adapter_path"),
        ("profiles", "schema_profile_path"),
        ("reference_events", "invariant_state"),
        ("observation", "matcher_branch"),
        ("expected", "evidence_quality_state"),
    ],
)
def test_absent_required_measurements_remain_unknown(missing, dimension):
    case = fixture()
    if missing == "profiles":
        case = case.model_copy(update={missing: ()})
    elif missing == "reference_events":
        case = case.model_copy(update={missing: (), "reference_digest": digest([])})
    else:
        case = replace_evidence(case, **{missing: () if missing == "representations" else None})
    measured = measure_case(case)
    assert observations(measured)[dimension].state == "unknown"
    result = analyze_coverage((case,))
    assert not values(result, dimension)
    assert not result.evidence_gate.passed


@pytest.mark.parametrize(
    "source", ["input_digest", "reference_digest", "input_policy", "reference_policy"]
)
def test_integrity_and_safety_block_all_coverage_consumers(monkeypatch, source):
    case = fixture()
    bad = TelemetryEvent.model_validate(
        case.evidence.events[0].model_dump()
        | {"raw": RawSource.from_payload({"target": "production.invalid"}, adapter="jsonl")}
    )
    if source == "input_digest":
        case = case.model_copy(update={"expected_digest": "0" * 64})
    elif source == "reference_digest":
        case = case.model_copy(update={"reference_digest": "0" * 64})
    elif source == "input_policy":
        case = replace_evidence(case, events=(bad,))
    else:
        case = case.model_copy(
            update={
                "reference_events": (bad,),
                "reference_digest": digest([bad.model_dump(mode="json")]),
            }
        )
    monkeypatch.setattr(
        engine, "roundtrip_profile", lambda *args: pytest.fail("blocked content reached mappings")
    )
    result = analyze_coverage((case,))
    assert not result.tokens
    assert result.evidence_gate.state == "unsafe_rejected"
    assert result.retention[0].reason == "unsafe_rejected"
    assert result.cases[0].input is None and result.cases[0].measurements is None
    assert "production.invalid" not in result.model_dump_json()


def test_actual_mapping_loss_adds_a_path_without_claiming_a_lossless_roundtrip():
    case = fixture()
    event = case.evidence.events[0]
    timestamp = "2026-01-01T00:00:00.000001Z"
    changed = TelemetryEvent.model_validate(
        event.model_dump()
        | {
            "timestamp": timestamp,
            "raw": RawSource.from_payload(
                event.raw.payload | {"timestamp": timestamp},
                adapter="jsonl",
                original_timestamp=timestamp,
            ),
        }
    )
    case = replace_evidence(
        case,
        events=(changed,),
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl",
                content=encode_fixture((changed,), "canonical_jsonl"),
            ),
        ),
    )
    case = case.model_copy(
        update={
            "reference_events": (changed,),
            "reference_digest": digest([changed.model_dump(mode="json")]),
            "profiles": ("ocsf_like",),
        }
    )
    result = analyze_coverage((case,))
    assert any(
        "timestamp_precision_loss" in value for value in values(result, "normalization_loss_path")
    )
    assert any(":lossy:" in value for value in values(result, "schema_profile_path"))
    # A resolved loss is an observation, not a successful lossless mapping.
    assert result.cases[0].measurements.mappings[0].decision == "lossy"


def test_unsupported_metadata_profile_remains_unknown():
    case = fixture().model_copy(update={"profiles": ("sigma_metadata",)})
    result = analyze_coverage((case,))
    assert observations(result.cases[0])["schema_profile_path"].state == "unknown"
    assert not result.evidence_gate.passed


def test_adapter_disagreement_records_real_loss_paths_and_existing_fragility_class():
    case = fixture()
    representation_event = TelemetryEvent.model_validate(
        case.evidence.events[0].model_dump() | {"correlation_id": None}
    )
    case = replace_evidence(
        case,
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl",
                content=encode_fixture((representation_event,), "canonical_jsonl"),
            ),
        ),
    )
    result = analyze_coverage((case,))
    assert any(
        "correlation_key_loss" in value for value in values(result, "normalization_loss_path")
    )
    assert "correlation_key_dependency" in values(result, "fragility_class")


def test_unparseable_representation_is_unknown_and_does_not_claim_no_loss():
    case = replace_evidence(
        fixture(),
        representations=(
            FixtureRepresentation(representation="canonical_jsonl", content="{broken"),
        ),
    )
    result = analyze_coverage((case,))
    assert not values(result, "adapter_path")
    assert "no_observed_loss" not in values(result, "normalization_loss_path")
    assert not result.evidence_gate.passed


def test_correlation_not_requested_is_distinct_from_missing_requested_key():
    case = fixture()
    no_request = replace_evidence(
        case, expected=case.evidence.expected.model_dump() | {"correlation_id": None}
    )
    assert values(analyze_coverage((no_request,)), "correlation_path") == {"not_requested"}
    observation = case.evidence.observation
    missing = replace_evidence(
        case,
        observation=observation.model_dump()
        | {
            "detections": [
                d.model_dump() | {"correlation_id": None} for d in observation.detections
            ]
        },
    )
    measured = measure_case(missing)
    assert observations(measured)["correlation_path"].state == "unknown"
    assert not coverage_evidence_gate((missing,)).passed


def test_disagreement_is_covered_without_claiming_a_confirmed_cause():
    case = fixture()
    case = replace_evidence(
        case, expected=case.evidence.expected.model_dump() | {"signature": "different"}
    )
    result = analyze_coverage((case,))
    assert any(
        "detection:fail" in value and "temporal:pass" in value
        for value in values(result, "oracle_disagreement_class")
    )
    assert not values(result, "fragility_class")
    assert not result.evidence_gate.passed


@pytest.mark.parametrize("seed", [True, -1, 2**63, 0.5])
def test_seed_validation(seed):
    with pytest.raises(ValueError, match="DVI-COVERAGE-SEED"):
        analyze_coverage((fixture(),), seed=seed)


def test_input_counts_copied_models_and_identity_are_bounded():
    case = fixture()
    with pytest.raises(ValueError, match="1..16"):
        analyze_coverage(())
    with pytest.raises(ValueError, match="1..16"):
        analyze_coverage((case,) * 17)
    with pytest.raises(ValueError, match="IDs must be unique"):
        analyze_coverage((case, case))
    with pytest.raises(ValidationError, match="duplicate profile"):
        measure_case(case.model_copy(update={"profiles": ("dvi", "dvi")}))
    copied = case.evidence.model_copy(update={"precision_digits": True})
    with pytest.raises(ValidationError):
        measure_case(case.model_copy(update={"evidence": copied}))
    too_many = tuple(
        TelemetryEvent.model_validate(case.evidence.events[0].model_dump() | {"event_id": f"e:{i}"})
        for i in range(9)
    )
    with pytest.raises(ValidationError, match="eight"):
        replace_evidence(case, events=too_many)


def test_serialized_growth_gate_and_source_tampering_are_rejected():
    report = analyze_coverage((fixture(), fixture("case:late", 2000)))
    for update, error in (
        ({"growth": [point.model_dump() | {"cumulative": 0} for point in report.growth]}, "GROWTH"),
        ({"tokens": []}, "TOTAL"),
        ({"evidence_gate": report.evidence_gate.model_dump() | {"passed": False}}, "GATE"),
    ):
        with pytest.raises(ValidationError, match=error):
            SemanticCoverage.model_validate(report.model_dump() | update)
    data = report.model_dump(mode="json")
    data["cases"][0]["input"]["profiles"] = ["ecs_like"]
    with pytest.raises(ValidationError, match="retained input changed"):
        SemanticCoverage.model_validate(data)


def test_artifacts_link_dimension_paths_to_actual_measurements():
    inputs = (fixture(), fixture("case:late", 2000), fixture("case:duplicate"))
    artifacts = coverage_artifacts(inputs, seed=42)
    assert artifacts == coverage_artifacts(tuple(reversed(inputs)), seed=42)
    assert set(artifacts) == {
        "semantic_coverage.json",
        "coverage_growth.json",
        "discovery_queue.jsonl",
        "coverage_retention.json",
    }
    parsed = parse_json(artifacts["semantic_coverage.json"])
    queue = [parse_json(line) for line in artifacts["discovery_queue.jsonl"].splitlines()]
    assert queue == parsed["retention"]
    assert parse_json(artifacts["coverage_growth.json"])["final_count"] == len(parsed["tokens"])
    for case in parsed["cases"]:
        for observation in case["observations"]:
            for path in observation["evidence_refs"]:
                current = case
                for part in path.split("/")[1:]:
                    current = current[part]
                assert current is not None


def test_example_emits_real_coverage_and_refuses_existing_output(tmp_path, monkeypatch):
    out = tmp_path / "proof"
    monkeypatch.setattr(sys, "argv", [str(EXAMPLE), "--out", str(out)])
    example.main()
    assert len(list(out.iterdir())) == 4
    report = SemanticCoverage.model_validate(
        parse_json((out / "semantic_coverage.json").read_bytes())
    )
    assert report.evidence_gate.passed and len(report.tokens) == 34
    assert sum(row.retained for row in report.retention) == 2
    with pytest.raises(SystemExit):
        example.main()
