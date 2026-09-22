"""Measured cross-representation behavior, field evidence and conservative unknowns."""

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.adapters import normalize
from dvi_sentinel.fixture_encoding import encode_fixture
from dvi_sentinel.metamorphic import analyze_representations, metamorphic_artifacts
from dvi_sentinel.metamorphic_models import (
    REPRESENTATION_IDS,
    MetamorphicInput,
    MetamorphicReport,
    RepresentationInput,
)
from dvi_sentinel.models import RawSource
from dvi_sentinel.schema_mapping import project_profile
from dvi_sentinel.serialization import canonical_json, parse_json


def source(**changes):
    record = {
        "event_id": "fixture:flow",
        "timestamp": "2026-01-01T00:00:00Z",
        "category": "flow",
        "severity": 0,
        "action": "observed",
        "protocol": "tcp",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.2",
        "correlation_id": "flow:1",
    } | changes
    result = normalize(canonical_json(record).encode(), "jsonl")
    assert result.parser_success, result.errors
    return result.events[0]


def analyze(event=None, names=REPRESENTATION_IDS, supplied=()):
    request = MetamorphicInput(source=event or source(), representations=names, supplied=supplied)
    return analyze_representations(request, expected_digest=request.stable_digest())


def supplied(name, value):
    return RepresentationInput(representation=name, content=canonical_json(value))


def row(report, name):
    return next(r for r in report.results if r.representation == name)


def classes(report):
    return {f.finding_class for f in report.findings}


def test_equivalent_common_subset_agrees_through_all_seven_event_representations():
    event = source()
    # An absent optional vendor column is supported by the V1 parser; an empty cell is not.
    stream = io.StringIO(encode_fixture((event,), "csv"))
    reader = csv.DictReader(stream)
    record = next(reader)
    record.pop("vendor")
    record.pop("sensor")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(record), lineterminator="\n")
    writer.writeheader()
    writer.writerow(record)
    result = analyze(
        event,
        tuple(n for n in REPRESENTATION_IDS if n != "sigma_metadata"),
        (RepresentationInput(representation="csv", content=output.getvalue()),),
    )
    assert result.state == "agree"
    assert len(result.results) == 7 and len(result.matrix) == 49
    assert all(p.state == "agree" for p in result.matrix)
    assert all(r.semantic.decision == "equivalent" for r in result.results)
    assert not result.findings


def test_actual_ocsf_precision_loss_is_field_linked_and_keeps_semantic_verdict():
    result = analyze(
        source(timestamp="2026-01-01T00:00:00.123456Z"), ("canonical_jsonl", "ocsf_like")
    )
    changed = row(result, "ocsf_like")
    assert changed.profile.event.timestamp.microsecond == 123000
    assert changed.state == "disagree"
    assert any(
        f.finding_class == "timestamp_precision_loss" and f.field_path == "/timestamp"
        for f in result.findings
    )
    assert any(
        d.expected.endswith("123456Z") and d.observed.endswith("123000Z")
        for d in changed.differences
        if d.path == "/timestamp"
    )
    assert (
        changed.semantic is not None
    )  # Meaning and exact field preservation are distinct measurements.


def test_metadata_loss_is_visible_even_when_ontology_meaning_agrees():
    result = analyze(
        source(sensor="fixture:sensor", vendor="FixtureLab", labels=["benign"]),
        ("canonical_jsonl", "ecs_like", "otel_like"),
    )
    ecs = row(result, "ecs_like")
    assert ecs.semantic.decision == "equivalent"
    assert ecs.state == "disagree" and "metadata_context_loss" in classes(result)
    assert {d.path for d in ecs.differences} >= {"/sensor", "/vendor", "/labels"}
    # Two projections may share the same loss; pairwise agreement is not source fidelity.
    assert (
        next(p for p in result.matrix if (p.left, p.right) == ("ecs_like", "otel_like")).state
        == "agree"
    )


@pytest.mark.parametrize(
    "spelling,expected",
    [
        ("2026-01-01T02:00:00+02:00", "agree"),
        ("2026-01-01T00:00:00+02:00", "disagree"),
    ],
)
def test_timezone_spelling_compares_instants_and_only_actual_wall_time_drift_is_labeled(
    spelling, expected
):
    value = parse_json(project_profile(source(), "ecs_like").payload_json)
    value["@timestamp"] = spelling
    result = analyze(names=("ecs_like",), supplied=(supplied("ecs_like", value),))
    assert result.state == expected
    assert ("timezone_drift" in classes(result)) == (expected == "disagree")


def test_arbitrary_time_shift_does_not_invent_a_timezone_cause():
    value = parse_json(project_profile(source(), "ecs_like").payload_json)
    value["@timestamp"] = "2026-01-01T00:00:07Z"
    result = analyze(names=("ecs_like",), supplied=(supplied("ecs_like", value),))
    assert result.state == "disagree"
    assert "timezone_drift" not in classes(result) and "timestamp_precision_loss" not in classes(
        result
    )
    assert any(
        f.finding_class == "adapter_disagreement" and f.field_path == "/timestamp"
        for f in result.findings
    )


@pytest.mark.parametrize(
    "field,value,kind,path",
    [
        ("severity", 3, "severity_mapping_drift", "/severity"),
        ("correlation_id", None, "correlation_key_loss", "/correlation_id"),
        ("action", "allowed", "semantic_loss", "/semantics/action"),
    ],
)
def test_real_adapter_disagreement_has_specific_class_and_values(field, value, kind, path):
    original = source()
    candidate = original.raw.payload | {field: value}
    result = analyze(original, ("canonical_jsonl",), (supplied("canonical_jsonl", candidate),))
    assert result.state == "disagree"
    assert {"adapter_disagreement", kind} <= classes(result)
    assert any(d.path == path and d.expected != d.observed for d in result.results[0].differences)


def test_profile_alias_conflict_remains_unknown_and_names_its_actual_field():
    value = parse_json(project_profile(source(), "ecs_like").payload_json)
    value["source_ip"] = "192.0.2.9"
    result = analyze(names=("ecs_like",), supplied=(supplied("ecs_like", value),))
    assert result.state == "unknown" and result.results[0].profile.event is None
    finding = next(f for f in result.findings if f.finding_class == "field_alias_mismatch")
    assert finding.field_path == "/semantics/source/address"
    assert "source/ip" in canonical_json(result.results[0].profile).replace('","', "/")
    assert result.matrix[0].state == "unknown"


def test_equal_alias_values_are_not_mismatches():
    value = parse_json(project_profile(source(), "ecs_like").payload_json)
    value["source_ip"] = "192.0.2.1"
    result = analyze(names=("ecs_like",), supplied=(supplied("ecs_like", value),))
    assert result.state == "agree" and "field_alias_mismatch" not in classes(result)


def test_unsupported_extra_profile_field_is_unknown_even_with_reconstructed_event():
    value = parse_json(project_profile(source(), "ecs_like").payload_json)
    value["unsupported_context"] = "synthetic"
    result = analyze(names=("ecs_like",), supplied=(supplied("ecs_like", value),))
    assert result.results[0].profile.event is not None
    assert result.state == result.matrix[0].state == "unknown"
    assert any(
        f.finding_class == "unsupported_profile_feature" and f.field_path == "/unsupported_context"
        for f in result.findings
    )


def test_sigma_metadata_never_claims_observed_event_equivalence():
    result = analyze(names=("sigma_metadata",))
    assert result.state == "unknown" and result.matrix[0].state == "unknown"
    assert result.results[0].profile.event is None
    assert "unsupported_profile_feature" in classes(result)
    assert any(i.code == "metadata_only" for i in result.results[0].profile.issues)


def test_existing_csv_blank_vendor_failure_stays_visible():
    result = analyze(names=("canonical_jsonl", "csv"))
    assert row(result, "canonical_jsonl").state == "agree"
    assert row(result, "csv").state == "unknown"
    assert row(result, "csv").adapter.errors
    assert result.state == "unknown"


@pytest.mark.parametrize(
    "name,content",
    [
        ("canonical_jsonl", "not-json"),
        ("ecs_like", "[1]"),
        ("ecs_like", "{broken"),
    ],
)
def test_malformed_representation_is_diagnostic_unknown(name, content):
    result = analyze(
        names=(name,), supplied=(RepresentationInput(representation=name, content=content),)
    )
    assert result.state == result.matrix[0].state == "unknown"
    assert "unsupported_profile_feature" in classes(result)


def test_partial_or_multiple_fixture_events_cannot_be_claimed_equivalent():
    content = encode_fixture((source(),), "canonical_jsonl")
    for extra in (
        "bad-json",
        canonical_json(source().model_dump(mode="json") | {"event_id": "extra"}),
    ):
        result = analyze(
            names=("canonical_jsonl",),
            supplied=(
                RepresentationInput(representation="canonical_jsonl", content=content + extra),
            ),
        )
        assert result.state == "unknown" and not result.results[0].differences
        assert result.matrix[0].state == "unknown"


def test_encoder_unsupported_fields_have_structured_unknown_without_guessing():
    event = source()
    event = type(event).model_validate(event.model_dump() | {"observed_at": "2026-01-01T00:00:01Z"})
    result = analyze(event, ("csv",))
    assert result.state == "unknown" and result.results[0].source is None
    assert "DVI-ENCODING-UNSUPPORTED" in result.results[0].failure


@settings(max_examples=8, deadline=None)
@given(st.permutations(("canonical_jsonl", "ecs_like", "ocsf_like", "otel_like")))
def test_matrix_and_bytes_are_invariant_to_requested_order(names):
    a = MetamorphicInput(source=source(), representations=names)
    b = MetamorphicInput(source=source(), representations=tuple(reversed(names)))
    assert a.stable_digest() == b.stable_digest()
    assert metamorphic_artifacts(a, expected_digest=a.stable_digest()) == metamorphic_artifacts(
        b, expected_digest=b.stable_digest()
    )


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_missing_or_mismatched_pin_blocks_consumers(monkeypatch, pin):
    def forbidden(*args, **kwargs):
        pytest.fail("a consumer ran before input integrity")

    monkeypatch.setattr("dvi_sentinel.metamorphic._prepare", forbidden)
    request = MetamorphicInput(source=source())
    report = analyze_representations(request, expected_digest=pin)
    assert report.state == ("unknown" if pin is None else "unsafe_rejected")
    assert report.input is None and not report.results


@pytest.mark.parametrize("target", ["source", "canonical_jsonl", "ecs_like"])
def test_structural_policy_blocks_unsafe_content_before_comparison(monkeypatch, target):
    def forbidden(*args, **kwargs):
        pytest.fail("comparison consumed rejected evidence")

    monkeypatch.setattr("dvi_sentinel.metamorphic._measure", forbidden)
    event = source()
    if target == "source":
        event = event.model_copy(
            update={"raw": RawSource.from_payload({"command": "fixture"}, adapter="jsonl")}
        )
        request = MetamorphicInput(source=event)
    else:
        value = (
            event.raw.payload
            if target == "canonical_jsonl"
            else parse_json(project_profile(event, target).payload_json)
        )
        value["command"] = "fixture"
        request = MetamorphicInput(
            source=event, representations=(target,), supplied=(supplied(target, value),)
        )
    result = analyze_representations(request, expected_digest=request.stable_digest())
    assert result.state == "unsafe_rejected" and result.input is None
    assert not result.results and not result.findings and not result.matrix
    assert '"command"' not in canonical_json(result)


def test_unexpected_engine_error_propagates(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("unexpected defect")

    monkeypatch.setattr("dvi_sentinel.metamorphic.normalize_profile", broken)
    with pytest.raises(RuntimeError, match="unexpected defect"):
        analyze(names=("ecs_like",))


def test_bounds_duplicates_and_copied_invalid_models_fail_before_measurement():
    for names in ((), ("csv", "csv"), ("not-a-profile",)):
        with pytest.raises(ValidationError):
            MetamorphicInput(source=source(), representations=names)
    with pytest.raises(ValidationError, match="64 KiB"):
        MetamorphicInput(
            source=source(),
            supplied=(RepresentationInput(representation="csv", content="x" * 65_537),),
        )
    with pytest.raises(ValidationError, match="not selected"):
        MetamorphicInput(
            source=source(), representations=("csv",), supplied=(supplied("ecs_like", {}),)
        )
    request = MetamorphicInput(source=source()).model_copy(
        update={"representations": ("csv", "csv")}
    )
    with pytest.raises(ValidationError, match="duplicate"):
        analyze_representations(request, expected_digest=request.stable_digest())


def test_artifacts_have_actual_evidence_paths_and_reject_incomplete_matrix():
    request = MetamorphicInput(
        source=source(timestamp="2026-01-01T00:00:00.123456Z", vendor="FixtureLab")
    )
    artifacts = metamorphic_artifacts(request, expected_digest=request.stable_digest())
    report = json.loads(artifacts["metamorphic_report.json"])
    for finding in report["findings"]:
        item = report
        for part in finding["evidence_ref"].strip("/").split("/"):
            item = item[int(part)] if isinstance(item, list) else item[part]
        assert item
    assert json.loads(artifacts["representation_diff.json"])["findings"] == report["findings"]
    assert json.loads(artifacts["cross_profile_matrix.json"])["comparisons"] == report["matrix"]
    assert [json.loads(line) for line in artifacts["adapter_disagreement.jsonl"].splitlines()] == [
        f for f in report["findings"] if f["finding_class"] == "adapter_disagreement"
    ]
    report["matrix"].pop()
    with pytest.raises(ValidationError, match="MATRIX"):
        MetamorphicReport.model_validate(report)


def test_unresolved_ontology_cannot_pass_by_matching_incomplete_fields():
    result = analyze(source(category="alert", severity=0), ("canonical_jsonl",))
    assert result.state == result.matrix[0].state == "unknown"
    assert result.results[0].semantic.decision == "unknown"
    assert not result.results[0].differences
    assert "unsupported_profile_feature" in classes(result)


def test_fixture_alias_conflict_is_retained_as_a_diagnostic():
    value = source().raw.payload | {"source_ip": "192.0.2.9"}
    result = analyze(names=("canonical_jsonl",), supplied=(supplied("canonical_jsonl", value),))
    assert result.state == "unknown" and "field_alias_mismatch" in classes(result)
    assert any("ALIAS-CONFLICT" in e.code for e in result.results[0].adapter.errors)


def test_changed_event_identity_is_not_silently_realigned():
    value = source().raw.payload | {"event_id": "fixture:other"}
    result = analyze(names=("canonical_jsonl",), supplied=(supplied("canonical_jsonl", value),))
    assert result.state == "disagree"
    assert {d.path for d in result.results[0].differences} == {"/event_id"}


@pytest.mark.parametrize("target", ["input", "adapter", "profile", "matrix"])
def test_changed_artifact_links_or_pair_verdict_are_rejected(target):
    report = analyze(names=("canonical_jsonl", "ecs_like")).model_dump(mode="json")
    if target == "input":
        report["input"]["source"]["event_id"] = "changed"
    elif target == "adapter":
        report["results"][0]["source"]["content"] += "\n"
    elif target == "profile":
        report["results"][1]["profile"]["payload_digest"] = "0" * 64
    else:
        report["matrix"][0]["state"] = "disagree"
    with pytest.raises(ValidationError, match="REFERENCE|MATRIX"):
        MetamorphicReport.model_validate(report)


def test_complete_and_utf8_input_bounds_and_combined_artifact_bound(monkeypatch):
    with pytest.raises(ValidationError, match="64 KiB"):
        MetamorphicInput(
            source=source(),
            supplied=(
                RepresentationInput(
                    representation="csv",
                    content="\u00e9" * 32_769,
                ),
            ),
        )
    with pytest.raises(ValidationError, match="256 KiB"):
        MetamorphicInput(
            source=source(),
            supplied=tuple(
                RepresentationInput(representation=n, content="x" * 65_536)
                for n in REPRESENTATION_IDS[:4]
            ),
        )
    monkeypatch.setattr("dvi_sentinel.metamorphic.MAX_ARTIFACT_BYTES", 1)
    request = MetamorphicInput(source=source(), representations=("canonical_jsonl",))
    with pytest.raises(ValueError, match="OUTPUT"):
        metamorphic_artifacts(request, expected_digest=request.stable_digest())


def test_example_runs_eight_actual_paths_and_refuses_existing_output(tmp_path):
    path = tmp_path / "proof"
    script = Path(__file__).resolve().parents[1] / "examples/cross_representation.py"
    result = subprocess.run(
        [sys.executable, str(script), "--out", str(path)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    report = MetamorphicReport.model_validate_json((path / "metamorphic_report.json").read_text())
    assert len(report.results) == 8 and len(report.matrix) == 64
    assert report.state == "unknown" and "metadata_context_loss" in classes(report)
    assert len(list(path.iterdir())) == 4
    second = subprocess.run(
        [sys.executable, str(script), "--out", str(path)], capture_output=True, text=True
    )
    assert second.returncode != 0 and "new local directory" in second.stderr
