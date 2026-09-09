from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import (
    FixtureCase,
    FixtureResults,
    HarnessRequest,
    HarnessResult,
    RuleHarnessConfig,
)
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import DetectionEvent
from dvi_sentinel.probes import run_probes
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json, parse_json
from dvi_sentinel.variation_models import MetamorphicInvariant, SemanticPreservationResult

ROOT = Path(__file__).parents[1] / "examples"


def inputs():
    return normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events


def observed(**changes):
    rules = RuleHarnessConfig.model_validate(parse_json((ROOT / "probes/rules.json").read_bytes()))
    detection = (
        RuleLogicHarness(rules)
        .evaluate(HarnessRequest(case_id="baseline", events=inputs()))
        .detections[0]
    )
    return DetectionEvent.model_validate(
        detection.model_dump()
        | {
            "event_id": "alert:1",
            "signature": "lab.example",
            "title": "Synthetic example observation",
            "labels": ["lab"],
            "tags": ["fixture"],
            "techniques": ["T0000"],
            "correlation_id": "123",
        }
        | changes
    )


def expectation(**changes):
    return DetectionExpectation.model_validate(
        {
            "detector": "lab",
            "signature": "lab.example",
            "min_severity": 3,
            "labels": ["lab"],
            "tags": ["fixture"],
            "techniques": ["T0000"],
            "correlation_id": "123",
            "event_ids": [e.event_id for e in inputs()],
            "reference_time": "2026-01-01T00:00:01Z",
            "max_delay_ms": 1000,
        }
        | changes
    )


def evaluate(expected=None, detections=None, **kwargs):
    return match_detection(
        expected or expectation(),
        HarnessResult(
            case_id="variant:1",
            status="complete",
            detections=detections if detections is not None else (observed(),),
        ),
        inputs(),
        **kwargs,
    )


def test_true_match_contains_normalized_evidence_and_roundtrips():
    result = evaluate(expectation(title_contains="example", source_adapter=observed().raw.adapter))
    assert result.status == "detected" and result.matching_event_ids == ("alert:1",)
    assert result.alert_delay_ms == 0 and result.evidence_completeness == 1
    assert not result.missing_evidence and not result.contradictory_evidence
    assert all(c.outcome == "pass" for c in result.candidates[0].comparisons)
    assert MatchResult.model_validate_json(canonical_json(result)) == result


@pytest.mark.parametrize(
    ("changes", "code", "field"),
    [
        ({"signature": "other"}, "DVI-MATCH-SIGNATURE", "signature"),
        ({"severity": 2}, "DVI-MATCH-SEVERITY", "severity"),
        ({"labels": []}, "DVI-MATCH-LABEL", "labels"),
        ({"tags": []}, "DVI-MATCH-TAG", "tags"),
        ({"techniques": []}, "DVI-MATCH-TECHNIQUE", "techniques"),
        ({"correlation_id": "456"}, "DVI-MATCH-CORRELATION", "correlation_id"),
        ({"related_event_ids": ["different"]}, "DVI-MATCH-EVENT-ID", "event_ids"),
        ({"timestamp": "2026-01-01T00:00:02.000001Z"}, "DVI-MATCH-LATE", "alert_delay_ms"),
        ({"timestamp": "2026-01-01T00:00:00.999999Z"}, "DVI-MATCH-EARLY", "alert_delay_ms"),
    ],
)
def test_hard_contradictions_are_explained(changes, code, field):
    result = evaluate(detections=(observed(**changes),))
    assert result.status == "missed" and result.reason == code
    assert field in result.contradictory_evidence
    assert not result.matching_event_ids
    assert result.evidence_completeness == 1  # Complete evidence can prove failure.


def test_required_absence_and_no_candidate_have_distinct_reasons():
    result = evaluate(
        expectation(required_fields=["correlation_id"]), (observed(correlation_id=None),)
    )
    assert result.reason == "DVI-MATCH-MISSING-FIELD" and result.status == "missed"
    assert "required/correlation_id" in result.missing_evidence and result.evidence_completeness < 1
    for detections in ((), (observed(detector="other"),)):
        result = evaluate(detections=detections)
        assert result.status == "missed" and result.reason == "DVI-MATCH-NO-CANDIDATE"


def test_explicit_containment_is_case_sensitive_and_no_regex():
    assert evaluate(expectation(signature=None, signature_contains="example")).status == "detected"
    assert (
        evaluate(expectation(signature=None, signature_contains=".*")).reason
        == "DVI-MATCH-SIGNATURE"
    )
    assert evaluate(expectation(title_contains="EXAMPLE")).reason == "DVI-MATCH-TITLE"
    assert evaluate(expectation(source_adapter="other")).reason == "DVI-MATCH-SOURCE"


def test_guard_failures_cannot_be_overridden_by_matching_candidates():
    failed = SemanticPreservationResult(
        checks=(
            MetamorphicInvariant(
                id="test",
                passed=False,
                explanation="protected semantic field changed",
            ),
        )
    )
    assert evaluate(preservation=failed).reason == "DVI-MATCH-INVARIANT"
    assert evaluate(parser_success=False).reason == "DVI-MATCH-NORMALIZATION"
    unavailable = HarnessResult(case_id="x", status="unknown", detections=(observed(),))
    assert match_detection(expectation(), unavailable, inputs()).reason == "DVI-MATCH-HARNESS"
    assert (
        evaluate(expectation(signature_contains="example")).reason
        == "DVI-MATCH-AMBIGUOUS-EXPECTATION"
    )
    assert evaluate(expectation(tags=["fixture", "fixture"])).status == "unknown"
    result = evaluate(detections=(observed(), observed(severity=2)))
    assert result.reason == "DVI-MATCH-AMBIGUOUS-OBSERVATION" and result.status == "unknown"


def test_conflicting_distinct_candidates_do_not_hide_a_true_match():
    good, bad = observed(), observed(event_id="alert:2", severity=2)
    first = evaluate(detections=(bad, good))
    assert first.status == "detected" and first.matching_event_ids == ("alert:1",)
    assert [c.status for c in first.candidates] == ["detected", "missed"]
    assert canonical_json(first) == canonical_json(evaluate(detections=(good, bad)))


def test_time_reference_inference_and_unknown_without_attribution():
    assert evaluate(expectation(reference_time=None)).alert_delay_ms == 0
    ambiguous = expectation(reference_time=None, event_ids=[])
    result = evaluate(ambiguous, (observed(related_event_ids=[]),))
    assert result.status == "unknown" and result.reason == "DVI-MATCH-TIME-REFERENCE"
    assert "alert_delay_ms" in result.missing_evidence
    linked = evaluate(ambiguous, (observed(related_event_ids=["unknown:input"]),))
    assert linked.status == "unknown"


@settings(max_examples=20, deadline=None, derandomize=True)
@given(st.integers(min_value=-100, max_value=2000))
def test_inclusive_time_window(delay_ms):
    detection = observed(timestamp=inputs()[-1].timestamp + timedelta(milliseconds=delay_ms))
    result = evaluate(detections=(detection,))
    assert (result.status == "detected") == (0 <= delay_ms <= 1000)
    assert result.alert_delay_ms == delay_ms


def test_probe_uses_full_match_when_identity_survives_but_title_changes():
    rules = RuleHarnessConfig.model_validate(parse_json((ROOT / "probes/rules.json").read_bytes()))
    policy = VariationPolicy(families=("ordering",), order_independent=True)
    expected = expectation(title_contains="example")
    # Probe case IDs are fixed by input/spec/config, independent of harness observations.
    planned = run_probes(inputs(), policy, RuleLogicHarness(rules), expected=expected)
    probe_id = next(p.id for p in planned if p.spec.name == "ordering")
    fixture = FixtureHarness(
        FixtureResults(
            cases=(
                FixtureCase(case_id="baseline", detections=(observed(),)),
                FixtureCase(
                    case_id=probe_id, detections=(observed(title="Different observation"),)
                ),
            )
        )
    )
    result = next(
        p
        for p in run_probes(inputs(), policy, fixture, expected=expected)
        if p.spec.name == "ordering"
    )
    assert result.observed_result == "fragile"
    assert result.baseline_match.status == "detected"
    assert result.candidate_match.reason == "DVI-MATCH-TITLE"
    assert not result.missing_identities


def test_differential_uses_full_match_when_identity_survives_but_severity_drops():
    canonical = normalize((ROOT / "telemetry/generic.jsonl").read_bytes(), "jsonl").events
    expected = expectation(event_ids=[], reference_time="2026-01-01T00:00:01Z")
    fixture = FixtureHarness(
        FixtureResults(
            cases=(
                FixtureCase(case_id="baseline", detections=(observed(),)),
                FixtureCase(case_id="schema:canonical_jsonl", detections=(observed(),)),
                FixtureCase(case_id="schema:csv", detections=(observed(severity=2),)),
                FixtureCase(case_id="schema:suricata_eve", detections=(observed(),)),
            )
        )
    )
    result = run_differential(canonical, fixture, expected=expected)
    assert [c.status for c in result.cases] == ["agree", "disagree", "agree"]
    assert result.cases[1].match.reason == "DVI-MATCH-SEVERITY"
    assert result.cases[1].differences[0].finding_class == "schema_fragility"
