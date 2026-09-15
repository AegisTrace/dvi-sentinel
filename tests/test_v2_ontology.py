"""Behavioral ontology contracts, adversarial uncertainty and real export proof."""

import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.adapters import normalize
from dvi_sentinel.models import (
    DetectionEvent,
    EntityRef,
    RawSource,
    TelemetryEvent,
    ValidationWarning,
)
from dvi_sentinel.ontology import (
    default_profile,
    export_ontology,
    extract_signal,
    ontology_artifacts,
    semantic_equivalence,
)
from dvi_sentinel.ontology_models import (
    EndpointRelation,
    EvidenceBinding,
    FieldBinding,
    Observable,
    OntologyExport,
    OntologyExtraction,
    OntologyProfile,
    SemanticSignal,
)
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.serialization import canonical_json, parse_json


def event(**changes) -> TelemetryEvent:
    data = {
        "event_id": "evt:one",
        "timestamp": "2026-01-01T00:00:00.123456Z",
        "semantics": {
            "category": "flow",
            "action": "observed",
            "protocol": "tcp",
            "source": {"address": "192.0.2.1", "port": 40000},
            "destination": {"address": "198.51.100.2", "port": 443},
        },
        "raw": RawSource.from_payload(
            {"sensor_label": "alpha"},
            adapter="jsonl",
            original_timestamp="2026-01-01T00:00:00.123456Z",
        ),
    }
    return TelemetryEvent.model_validate(data | changes)


def profile(*bindings, **changes) -> OntologyProfile:
    base = default_profile()
    return OntologyProfile.model_validate(
        base.model_dump()
        | {
            "bindings": (*base.bindings, *bindings),
            **changes,
        }
    )


def codes(result):
    return {finding.loss_class for finding in result.findings}


def test_different_representations_share_meaning_and_retain_distinct_provenance():
    json_event = normalize(
        b'{"event_id":"one","timestamp":"2026-01-01T00:00:00Z",'
        b'"category":"flow","action":"observed","protocol":"TCP"}\n',
        "jsonl",
    ).events[0]
    csv_event = normalize(
        b"event_id,timestamp,event_type,action,proto\n"
        b"two,2026-01-01T03:00:00+03:00,flow,observed,tcp\n",
        "csv",
    ).events[0]
    left, right = extract_signal(json_event), extract_signal(csv_event)
    assert semantic_equivalence(left, right).decision == "equivalent"
    assert left.signal == right.signal
    assert left.raw_digest != right.raw_digest
    assert left.event_digest != right.event_digest
    assert {b.raw_digest for b in left.bindings} == {json_event.raw.raw_digest}


def test_action_resource_direction_and_outcome_are_semantic():
    source = event()
    left = extract_signal(source)
    for changes in (
        {"action": "closed"},
        {"outcome": "success"},
        {"protocol": "udp"},
        {"http_path": "/fixture"},
        {"source": source.semantics.destination, "destination": source.semantics.source},
    ):
        changed = event(semantics=source.semantics.model_dump() | changes)
        comparison = semantic_equivalence(left, extract_signal(changed))
        assert comparison.decision == "different"
        assert comparison.transform.changed_fields
        assert set(comparison.transform.changed_fields) <= set(
            comparison.invariant.protected_fields
        )


def test_event_identity_time_and_unbound_metadata_are_not_signal_identity():
    original = event()
    changed = event(
        event_id="evt:two",
        timestamp=original.timestamp + timedelta(days=2),
        raw=RawSource.from_payload({"sensor_label": "beta"}, adapter="csv"),
        labels=("synthetic",),
        tags=("test",),
        confidence=0.9,
    )
    left, right = extract_signal(original), extract_signal(changed)
    assert left.signal == right.signal
    assert semantic_equivalence(left, right).decision == "equivalent"
    bound = profile(FieldBinding(field="sensor_label", paths=("raw.payload.sensor_label",)))
    assert (
        semantic_equivalence(
            extract_signal(original, bound), extract_signal(changed, bound)
        ).decision
        == "different"
    )
    time_bound = profile(FieldBinding(field="exact_time", paths=("timestamp",)))
    assert extract_signal(original, time_bound).signal != extract_signal(changed, time_bound).signal


def test_missing_required_evidence_cannot_be_false_equivalence():
    required = profile(FieldBinding(field="missing", paths=("raw.payload.absent",)))
    left, right = extract_signal(event(), required), extract_signal(event(event_id="two"), required)
    assert left.signal.semantic_digest == right.signal.semantic_digest
    assert left.state == right.state == "unknown"
    assert "missing_required_evidence" in codes(left)
    assert semantic_equivalence(left, right).decision == "unknown"
    assert (
        next(a for a in left.assumptions if a.assumption_id.endswith(":missing")).decision
        == "unknown"
    )
    assert {r.finding_id for r in left.recommendations} == {f.finding_id for f in left.findings}


def test_optional_absence_is_explicit_without_required_loss():
    selected = profile(
        FieldBinding(field="optional", paths=("raw.payload.absent",), required=False)
    )
    result = extract_signal(event(), selected)
    assert result.state == "known"
    assert (
        next(b.observable for b in result.bindings if b.specification.field == "optional").state
        == "missing"
    )


def test_conflicting_aliases_are_not_resolved_by_precedence_or_casefold():
    selected = profile(
        FieldBinding(
            field="label", paths=("raw.payload.a", "raw.payload.b"), normalization="casefold"
        )
    )
    conflicting = event(raw=RawSource.from_payload({"a": "ALPHA", "b": "alpha"}, adapter="jsonl"))
    result = extract_signal(conflicting, selected)
    assert result.state == "ambiguous"
    assert codes(result) == {"ambiguous_field_binding"}
    assert semantic_equivalence(result, result).decision == "unknown"
    aliases = event(raw=RawSource.from_payload({"a": "alpha", "b": "alpha"}, adapter="jsonl"))
    assert extract_signal(aliases, selected).state == "known"


@pytest.mark.parametrize("path", ["semantics.unsupported", "raw.unsupported", "timestamp.year"])
def test_unsupported_selectors_explicit_even_if_optional(path):
    result = extract_signal(
        event(), profile(FieldBinding(field="unknown", paths=(path,), required=False))
    )
    assert codes(result) == {"unknown_mapping"}
    assert result.state == "unknown"


def test_supported_missing_nested_path_and_nonscalar_value():
    selected = profile(FieldBinding(field="nested", paths=("raw.payload.details.label",)))
    assert codes(extract_signal(event(), selected)) == {"missing_required_evidence"}
    values = event(raw=RawSource.from_payload({"details": {"label": ["x", "y"]}}, adapter="jsonl"))
    assert (
        next(
            b.observable.value_json
            for b in extract_signal(values, selected).bindings
            if b.specification.field == "nested"
        )
        == '["x","y"]'
    )


def test_lossy_normalization_and_wrong_normalization_type():
    selected = profile(
        FieldBinding(field="label", paths=("raw.payload.sensor_label",), normalization="casefold")
    )
    uppercase = event(raw=RawSource.from_payload({"sensor_label": "ALPHA"}, adapter="jsonl"))
    result = extract_signal(uppercase, selected)
    assert codes(result) == {"lossy_normalization"}
    assert result.state == "unknown"
    integer = event(raw=RawSource.from_payload({"sensor_label": 12}, adapter="jsonl"))
    assert codes(extract_signal(integer, selected)) == {"unknown_mapping"}


def test_profile_category_and_entity_roles_do_not_guess():
    result = extract_signal(event(), profile(categories=("dns",)))
    assert "unsupported_semantic_category" in codes(result)
    inconsistent = profile(
        FieldBinding(field="peer", paths=("semantics.destination.address",), entity_role="source")
    )
    assert codes(extract_signal(event(), inconsistent)) == {"inconsistent_entity_role"}


def test_resource_requirements_are_category_specific():
    dns = event(semantics={"category": "dns", "action": "query"})
    result = extract_signal(dns)
    assert {f.field for f in result.findings} == {"dns_name"}
    http = event(semantics={"category": "http", "action": "request"})
    assert {f.field for f in extract_signal(http).findings} == {"http_method", "http_path"}
    complete = event(
        semantics={
            "category": "http",
            "action": "request",
            "http_method": "GET",
            "http_path": "/fixture",
        }
    )
    assert extract_signal(complete).state == "known"


def test_timestamp_precision_and_observation_time_require_source_proof():
    precise = profile(timestamp_precision_digits=6)
    assert extract_signal(event(), precise).state == "known"
    rounded = event(
        raw=RawSource.from_payload({}, adapter="jsonl", original_timestamp="2026-01-01T00:00:00Z")
    )
    assert codes(extract_signal(rounded, precise)) == {"timestamp_precision_loss"}
    no_source = event(raw=RawSource.from_payload({}, adapter="jsonl"))
    assert codes(extract_signal(no_source, precise)) == {"unknown_mapping"}
    observed = profile(time_role="observation_time")
    assert "missing_required_evidence" in codes(extract_signal(event(), observed))
    with_observation = event(observed_at=event().timestamp)
    assert extract_signal(with_observation, observed).state == "known"
    assert "unknown_mapping" in codes(
        extract_signal(
            with_observation, profile(time_role="observation_time", timestamp_precision_digits=3)
        )
    )


def test_severity_correlation_confidence_and_warning_evidence():
    alert = event(semantics={"category": "alert", "action": "observed"})
    assert codes(extract_signal(alert)) == {"severity_semantic_loss"}
    assert extract_signal(event(semantics=alert.semantics, severity=4)).state == "known"
    assert codes(extract_signal(event(), profile(correlation_requirement="required"))) == {
        "correlation_key_loss"
    }
    assert (
        extract_signal(
            event(correlation_id="flow:1"), profile(correlation_requirement="required")
        ).state
        == "known"
    )
    selected = profile(confidence_requirement=0.8)
    assert codes(extract_signal(event(), selected)) == {"insufficient_confidence"}
    assert codes(extract_signal(event(confidence=0.7), selected)) == {"insufficient_confidence"}
    low = extract_signal(event(confidence=0.7), selected)
    assert "0.7" in low.findings[0].explanation and "0.8" in low.findings[0].explanation
    assert (
        next(
            item.observable.value_json
            for item in low.bindings
            if item.specification.field == "confidence"
        )
        == "0.7"
    )
    assert extract_signal(event(confidence=0.8), selected).state == "known"
    warning = ValidationWarning(
        code="DVI-FUTURE-LOSS", path="timestamp", explanation="Uninterpreted warning"
    )
    assert codes(extract_signal(event(warnings=(warning,)))) == {"unknown_mapping"}


def test_detection_subclass_and_entity_order_preserve_contract():
    detection = DetectionEvent.model_validate(
        event().model_dump()
        | {
            "semantics": {"category": "alert", "action": "observed"},
            "severity": 4,
            "detector": "lab",
            "signature": "sig:1",
            "title": "Fixture observation",
        }
    )
    result = extract_signal(detection)
    assert result.event_digest == detection.stable_digest()
    entities = (EntityRef(kind="sensor", value="lab"), EntityRef(kind="host", value="demo.example"))
    assert (
        extract_signal(event(entities=entities)).signal
        == extract_signal(event(entities=entities[::-1] * 2)).signal
    )


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=50))
def test_semantic_identity_property_under_unbound_source_changes(label):
    changed = event(raw=RawSource.from_payload({"sensor_label": label}, adapter="csv"))
    assert extract_signal(changed).signal == extract_signal(event()).signal


def test_export_roundtrip_order_and_three_real_artifacts():
    one, two = event(), event(event_id="evt:two", semantics={"category": "dns", "action": "query"})
    export = export_ontology((one, two))
    assert export == export_ontology((two, one))
    assert OntologyExport.model_validate_json(canonical_json(export)) == export
    files = ontology_artifacts(export)
    assert files == ontology_artifacts(export_ontology((two, one)))
    assert set(files) == {"semantic_ontology.json", "ontology_bindings.json", "semantic_loss.json"}
    bindings = parse_json(files["ontology_bindings.json"])
    assert bindings["input_digest"] == export.input_digest
    assert {item["event_id"] for item in bindings["bindings"]} == {one.event_id, two.event_id}
    assert {f["loss_class"] for f in parse_json(files["semantic_loss.json"])["findings"]} == {
        "missing_required_evidence"
    }


@pytest.mark.parametrize("value", [(), (event(), event()), (event(),) * 1001])
def test_export_rejects_empty_duplicate_and_excess_input(value):
    with pytest.raises(ValueError, match="DVI-ONTOLOGY-BOUNDS"):
        export_ontology(value)


@pytest.mark.parametrize(
    "change",
    [
        {"required": "true"},
        {"paths": ("raw.payload.a", "raw.payload.a")},
        {"paths": ("raw..a",)},
        {"paths": ("raw.a.",)},
        {"paths": ("a.b.c.d.e.f.g.h.i",)},
        {"paths": ("__import__('os')",)},
        {"categories": ()},
        {"categories": ("flow", "flow")},
        {"extra": 1},
    ],
)
def test_strict_inert_profile_fields(change):
    with pytest.raises(ValidationError):
        FieldBinding.model_validate({"field": "demo", "paths": ("raw.payload.a",)} | change)


@pytest.mark.parametrize(
    "change",
    [
        {"timestamp_precision_digits": True},
        {"timestamp_precision_digits": 7},
        {"confidence_requirement": "0.9"},
        {"confidence_requirement": float("nan")},
        {"categories": ("flow", "flow")},
        {"bindings": (default_profile().bindings[0],) * 2},
    ],
)
def test_profile_rejects_invalid_requirements(change):
    with pytest.raises(ValidationError):
        profile(**change)


@pytest.mark.parametrize(
    "change",
    [
        {"value_json": '{"a": 1}'},
        {"value_json": '{"a":1,"a":2}'},
        {"value_json": "NaN"},
        {"value_json": "["},
        {"value_json": None},
        {"state": "unknown"},
    ],
)
def test_observable_immutable_canonical_contract(change):
    with pytest.raises(ValidationError):
        Observable.model_validate({"field": "demo", "state": "known", "value_json": '"x"'} | change)


def test_tampered_identity_provenance_state_and_export_rejected():
    result = extract_signal(event())
    with pytest.raises(ValidationError, match="IDENTITY"):
        SemanticSignal.model_validate(result.signal.model_dump() | {"semantic_digest": "0" * 64})
    with pytest.raises(ValidationError, match="frozen_instance"):
        result.signal.action = "other"
    with pytest.raises(ValidationError, match="PROVENANCE"):
        OntologyExtraction.model_validate(result.model_dump() | {"event_id": "different"})
    with pytest.raises(ValidationError, match="BINDING"):
        OntologyExtraction.model_validate(result.model_dump() | {"bindings": result.bindings * 2})
    missing = extract_signal(
        event(), profile(FieldBinding(field="absent", paths=("raw.payload.absent",)))
    )
    with pytest.raises(ValidationError, match="STATE"):
        semantic_equivalence(missing.model_copy(update={"state": "known"}), result)
    export = export_ontology((event(),))
    for change in (
        {"input_digest": "0" * 64},
        {"profile": profile(profile_id="changed")},
        {"extractions": export.extractions * 2},
    ):
        with pytest.raises(ValidationError):
            ontology_artifacts(export.model_copy(update=change))


def test_direct_api_revalidates_events_and_enforces_existing_fixture_policy():
    live_address = event(
        semantics=event().semantics.model_dump() | {"source": {"address": "8.8.8.8"}}
    )
    with pytest.raises(PolicyError):
        extract_signal(live_address)
    prohibited = event(raw=RawSource.from_payload({"command": "fixture text"}, adapter="jsonl"))
    with pytest.raises(PolicyError):
        extract_signal(prohibited)
    with (
        pytest.warns(UserWarning, match="Pydantic serializer warnings"),
        pytest.raises(ValidationError),
    ):
        extract_signal(event().model_copy(update={"confidence": "0.9"}))


def test_precision_rejects_invalid_retained_calendar_without_guessing():
    invalid = event(
        raw=RawSource.from_payload(
            {}, adapter="jsonl", original_timestamp="2026-02-30T00:00:00.123456Z"
        )
    )
    assert codes(extract_signal(invalid, profile(timestamp_precision_digits=6))) == {
        "unknown_mapping"
    }


def test_loader_cannot_remove_required_loss_or_disconnect_evidence():
    result = extract_signal(
        event(), profile(FieldBinding(field="absent", paths=("raw.payload.absent",)))
    )
    with pytest.raises(ValidationError, match="unresolved binding"):
        OntologyExtraction.model_validate(
            result.model_dump()
            | {
                "state": "known",
                "findings": (),
                "recommendations": (),
            }
        )
    with pytest.raises(ValidationError, match="RECOMMENDATION"):
        OntologyExtraction.model_validate(result.model_dump() | {"recommendations": ()})
    with pytest.raises(ValidationError, match="PROVENANCE"):
        OntologyExtraction.model_validate(
            result.model_dump()
            | {
                "findings": (result.findings[0].model_dump() | {"event_id": "wrong"},),
            }
        )
    known = extract_signal(event())
    with pytest.raises(ValidationError, match="signal evidence"):
        OntologyExtraction.model_validate(known.model_dump() | {"bindings": ()})
    with pytest.raises(ValidationError, match="BINDING"):
        EvidenceBinding.model_validate(known.bindings[0].model_dump() | {"candidates": ()})
    with pytest.raises(ValidationError, match="resolved evidence"):
        EvidenceBinding.model_validate(
            known.bindings[0].model_dump()
            | {
                "observable": known.bindings[0].observable.model_dump()
                | {"value_json": '"changed"'},
            }
        )
    with pytest.raises(ValidationError, match="ROLE"):
        EndpointRelation(direction="source_to_destination", source=None, destination=None)
    folded = extract_signal(
        event(raw=RawSource.from_payload({"text": "UPPER"}, adapter="jsonl")),
        profile(
            FieldBinding(field="folded", paths=("raw.payload.text",), normalization="casefold")
        ),
    )
    with pytest.raises(ValidationError, match="unresolved binding"):
        OntologyExtraction.model_validate(
            folded.model_dump()
            | {
                "state": "known",
                "findings": (),
                "recommendations": (),
            }
        )


@pytest.mark.parametrize("value", ["null", '""', "[]", "{}"])
def test_empty_observable_cannot_claim_known(value):
    with pytest.raises(ValidationError, match="empty values"):
        Observable(field="empty", state="known", value_json=value)


def test_event_and_export_byte_bounds_and_bound_value_size():
    oversized = event(
        raw=RawSource.from_payload({"large": "a" * (2 * 1024 * 1024)}, adapter="jsonl")
    )
    with pytest.raises(ValueError, match="exceeds 2 MiB"):
        extract_signal(oversized)
    medium = event(raw=RawSource.from_payload({"large": "a" * (1024 * 1024)}, adapter="jsonl"))
    with pytest.raises(ValueError, match="combined canonical"):
        export_ontology((medium, event(event_id="two", raw=medium.raw)))
    with pytest.raises(ValidationError):
        extract_signal(medium, profile(FieldBinding(field="large", paths=("raw.payload.large",))))


def test_detection_metadata_can_be_explicitly_bound():
    base = event().model_dump() | {
        "semantics": {"category": "alert", "action": "observed"},
        "severity": 4,
        "detector": "lab",
        "signature": "one",
        "title": "Fixture observation",
    }
    one, two = (
        DetectionEvent.model_validate(base),
        DetectionEvent.model_validate(base | {"signature": "two"}),
    )
    selected = profile(FieldBinding(field="rule_identity", paths=("signature",)))
    assert (
        semantic_equivalence(extract_signal(one, selected), extract_signal(two, selected)).decision
        == "different"
    )


def test_executable_example_exports_real_unknown_and_known_evidence(tmp_path):
    script = Path(__file__).parents[1] / "examples/semantic_ontology.py"
    output = tmp_path / "ontology"
    completed = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert "known=2 unknown=1" in completed.stdout
    export = OntologyExport.model_validate_json((output / "semantic_ontology.json").read_bytes())
    assert {item.state for item in export.extractions} == {"known", "unknown"}
    loss = parse_json((output / "semantic_loss.json").read_bytes())
    assert {item["loss_class"] for item in loss["findings"]} == {"missing_required_evidence"}
    for name, expected in ontology_artifacts(export).items():
        assert (output / name).read_bytes() == expected
    repeated = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert repeated.returncode != 0
    for name, expected in ontology_artifacts(export).items():
        assert (output / name).read_bytes() == expected
