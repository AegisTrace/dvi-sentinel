"""Behavioral proof for explicit profile subsets and measured roundtrip losses."""

import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.mapping_models import (
    FieldTrace,
    MappingExport,
    MappingRoundtrip,
    ProfileNormalization,
    ProfileProjection,
    SchemaProfile,
)
from dvi_sentinel.models import DetectionEvent, RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.schema_mapping import (
    mapping_artifacts,
    normalize_profile,
    project_profile,
    roundtrip_profile,
)
from dvi_sentinel.schema_profiles import PROFILE_IDS, schema_profile
from dvi_sentinel.serialization import canonical_json, parse_json


def event(**changes):
    return TelemetryEvent.model_validate(
        {
            "event_id": "fixture:flow",
            "timestamp": "2026-01-01T00:00:00Z",
            "semantics": {
                "category": "flow",
                "action": "observed",
                "protocol": "tcp",
                "source": {"address": "192.0.2.1", "port": 12345},
                "destination": {"address": "198.51.100.2", "port": 443},
            },
            "raw": RawSource.from_payload({"kind": "synthetic"}, adapter="jsonl"),
        }
        | changes
    )


def payload(profile="ecs_like", **changes):
    value = parse_json(project_profile(event(), profile).payload_json)
    return value | changes


@pytest.mark.parametrize(
    "profile", [p for p in PROFILE_IDS if p not in {"sigma_metadata", "suricata_eve"}]
)
def test_lossless_supported_flow_retains_semantic_equivalence(profile):
    source = event()
    result = roundtrip_profile(source, profile)
    assert result.decision == "lossless" and result.semantic_decision == "equivalent"
    assert result.normalization.state == "known"
    assert result.normalization.event.timestamp == source.timestamp
    assert result.normalization.event.semantics == source.semantics
    assert result.provenance_changed == (profile != "dvi")
    assert result.changes == ()


def test_dvi_preserves_complete_detection_subtype_and_source_evidence():
    sample = DetectionEvent.model_validate(
        event().model_dump()
        | {
            "semantics": {"category": "alert", "action": "match"},
            "severity": 3,
            "detector": "fixture:rule",
            "signature": "local-match",
            "title": "Fixture match",
            "techniques": ["lab.tag"],
            "related_event_ids": ["fixture:source"],
        }
    )
    result = roundtrip_profile(sample, "dvi")
    assert result.decision == "lossless" and result.normalization.event == sample
    exported = MappingExport(reports=(result,))
    assert MappingExport.model_validate_json(canonical_json(exported)) == exported


def test_eve_reuses_existing_subset_and_reports_severity_collapse():
    for severity, expected, decision in [
        (2, 2, "lossless"),
        (3, 3, "lossless"),
        (4, 4, "lossless"),
        (5, 4, "lossy"),
    ]:
        sample = event(semantics={"category": "alert", "action": "allowed"}, severity=severity)
        result = roundtrip_profile(sample, "suricata_eve")
        assert result.normalization.event.severity == expected
        assert result.decision == decision
        assert any(i.code == "severity_mapping_drift" for i in result.issues) == (severity == 5)
        assert result.semantic_decision == ("different" if severity == 5 else "equivalent")
        assert result.normalization.event.raw.adapter == "suricata_eve"


def test_eve_unknown_severity_never_gets_an_invented_known_level():
    for level in (0, 1):
        result = roundtrip_profile(
            event(semantics={"category": "alert", "action": "allowed"}, severity=level),
            "suricata_eve",
        )
        assert result.decision == "unknown"
        assert result.normalization.event.severity == 0
        assert "severity" not in parse_json(result.projection.payload_json)["alert"]


def test_ocsf_millisecond_projection_reports_microsecond_loss():
    sample = event(timestamp="2026-01-01T00:00:00.123456Z")
    result = roundtrip_profile(sample, "ocsf_like")
    assert parse_json(result.projection.payload_json)["time"] == 1767225600123
    assert result.normalization.event.timestamp.microsecond == 123000
    assert result.decision == "lossy"
    assert any(i.code == "timestamp_precision_loss" for i in result.issues)
    assert result.semantic_decision == "equivalent"  # Default meaning excludes absolute event time.


def test_nanosecond_conversion_is_exact_and_excess_precision_remains_visible():
    sample = event(
        timestamp="2026-01-01T00:00:00.123456Z",
        observed_at="2026-01-01T00:00:01.234567Z",
        severity=5,
    )
    projected = parse_json(project_profile(sample, "otel_like").payload_json)
    assert projected["Timestamp"] == 1767225600123456000
    assert projected["ObservedTimestamp"] == 1767225601234567000
    assert projected["Attributes"]["dvi.severity"] == 5
    assert "SeverityNumber" not in projected  # Security severity is not log error/fatal severity.
    result = roundtrip_profile(sample, "otel_like")
    assert result.decision == "lossless"
    projected["Timestamp"] += 789
    normalized = normalize_profile(canonical_json(projected), "otel_like")
    assert normalized.event.timestamp.microsecond == 123456
    assert normalized.state == "unknown"
    assert any(i.code == "timestamp_precision_loss" for i in normalized.issues)


@pytest.mark.parametrize(
    "profile,key,value",
    [
        ("ocsf_like", "time", True),
        ("ocsf_like", "time", 1e100),
        ("ocsf_like", "time", 10**40),
        ("otel_like", "Timestamp", -1),
        ("otel_like", "Timestamp", 2**64),
        ("otel_like", "Timestamp", "123"),
        ("zeek_like", "ts", "1e99"),
        ("zeek_like", "ts", []),
        ("ecs_like", "@timestamp", "2026-01-01T00:00:00.1234567Z"),
    ],
)
def test_invalid_time_never_passes_as_a_known_event(profile, key, value):
    result = normalize_profile(canonical_json(payload(profile, **{key: value})), profile)
    assert result.state == "unknown" and result.event is None
    assert any(i.code == "invalid_value" for i in result.issues)


def test_zeek_decimal_time_preserves_microseconds_and_flags_finer_values():
    sample = event(timestamp="1969-12-31T23:59:59.123456Z")
    projected = parse_json(project_profile(sample, "zeek_like").payload_json)
    assert projected["ts"] == "-0.876544"
    assert "id.orig_h" in projected and "id" not in projected
    assert roundtrip_profile(sample, "zeek_like").decision == "lossless"
    projected["ts"] = "1767225600.123456789"
    result = normalize_profile(canonical_json(projected), "zeek_like")
    assert result.state == "unknown" and result.event.timestamp.microsecond == 123456


def test_otel_out_of_range_source_time_is_explicitly_unmapped():
    projected = project_profile(event(timestamp="1969-12-31T23:59:59Z"), "otel_like")
    assert "Timestamp" not in parse_json(projected.payload_json)
    assert any(i.field == "timestamp" and i.code == "unmapped_field" for i in projected.issues)


def test_alias_conflict_is_rejected_before_conversion_and_equal_aliases_are_traceable():
    data = payload(source_ip="192.0.2.9")
    result = normalize_profile(canonical_json(data), "ecs_like")
    assert result.state == "unknown" and result.event is None
    assert any(i.code == "alias_ambiguity" for i in result.issues)
    data["source_ip"] = "192.0.2.1"
    result = normalize_profile(canonical_json(data), "ecs_like")
    assert result.state == "known"
    trace = next(
        item for item in result.fields if item.canonical_field == "semantics.source.address"
    )
    assert trace.profile_paths == (("source", "ip"), ("source_ip",))
    data["timestamp"] = "2026-01-01T00:00:00+00:00"
    result = normalize_profile(canonical_json(data), "ecs_like")
    assert (
        result.state == "unknown"
    )  # Same time, different aliases: no silent choice of representation.


def test_unsupported_profile_content_remains_a_warning_and_unknown():
    data = payload(custom={"description": "unmapped fixture value"})
    result = normalize_profile(canonical_json(data), "ecs_like")
    assert result.event is not None and result.state == "unknown"
    assert any(
        i.code == "unsupported_field" and i.field == "custom/description" for i in result.issues
    )
    assert any(w.code == "DVI-MAPPING-UNSUPPORTED-FIELD" for w in result.event.warnings)


def test_absent_event_identity_or_action_is_never_inferred():
    data = payload("suricata_eve")
    del data["dvi_action"]
    del data["dvi_event_id"]
    result = normalize_profile(canonical_json(data), "suricata_eve")
    assert result.event is None and result.state == "unknown"
    assert {i.field for i in result.issues if i.code == "missing_required_field"} == {
        "event_id",
        "semantics.action",
    }


def test_sigma_is_metadata_with_explicitly_incomplete_event_reconstruction():
    result = roundtrip_profile(event(severity=3, tags=("lab.tag",)), "sigma_metadata")
    assert parse_json(result.projection.payload_json) == {"level": "medium", "tags": ["lab.tag"]}
    assert result.decision == result.semantic_decision == "unknown"
    assert result.normalization.event is None
    assert {i.field for i in result.normalization.issues if i.code == "missing_required_field"} == {
        "event_id",
        "timestamp",
        "semantics.category",
        "semantics.action",
    }
    custom = normalize_profile(
        '{"level":"critical","detection":{"condition":"selection"}}', "sigma_metadata"
    )
    assert any(i.code == "unsupported_field" for i in custom.issues)
    assert custom.event is None


def test_noncanonical_values_and_dropped_metadata_are_reported():
    sample = event(
        semantics={"category": "dns", "action": "query", "dns_name": "DEMO.EXAMPLE."},
        confidence=0.8,
        tags=("lab",),
    )
    result = roundtrip_profile(sample, "suricata_eve")
    assert result.normalization.event.semantics.dns_name == "demo.example"
    assert result.decision == "unknown"
    trace = next(
        item for item in result.normalization.fields if item.canonical_field == "semantics.dns_name"
    )
    assert trace.state == "lossy" and trace.target_json == '"demo.example"'
    assert {item.canonical_field for item in result.changes} >= {"confidence", "semantics.dns_name"}
    zeek = roundtrip_profile(sample, "zeek_like")
    assert zeek.decision == "unknown"
    assert any(i.field == "semantics.dns_name" and i.code == "unmapped_field" for i in zeek.issues)


def test_malformed_schema_and_types_return_explicit_unknown():
    data = payload()
    data["source"]["port"] = True
    result = normalize_profile(canonical_json(data), "ecs_like")
    assert result.event is None and result.state == "unknown"
    assert any(i.code == "invalid_value" for i in result.issues)
    data = payload("dvi", extra="unrecognized")
    result = normalize_profile(canonical_json(data), "dvi")
    assert result.event is None and result.state == "unknown"


def test_policy_rejections_and_bounded_parsing_apply_to_all_entry_points():
    with pytest.raises(PolicyError):
        normalize_profile(canonical_json(payload(source_ip="8.8.8.8")), "ecs_like")
    with pytest.raises(PolicyError):
        project_profile(
            event(
                semantics={
                    "category": "flow",
                    "action": "observed",
                    "source": {"address": "8.8.8.8"},
                }
            ),
            "dvi",
        )
    for text in ('{"time":1,"time":2}', "[]", '{"time":NaN}'):
        with pytest.raises(ValueError):
            normalize_profile(text, "ocsf_like")
    with pytest.raises(ValueError, match="BOUNDS"):
        normalize_profile(" " * (2 * 1024 * 1024 + 1), "dvi")
    with pytest.raises(ValueError, match="BOUNDS"):
        normalize_profile(canonical_json({f"key{i}": i for i in range(257)}), "dvi")
    deep = {}
    for _ in range(18):
        deep = {"nested": deep}
    with pytest.raises(ValueError, match="BOUNDS"):
        normalize_profile(canonical_json(deep), "dvi")
    with pytest.raises(ValueError, match="BOUNDS"):
        mapping_artifacts(())
    with pytest.raises(ValueError, match="BOUNDS"):
        mapping_artifacts((event(), event()))
    with pytest.raises(ValueError, match="BOUNDS"):
        mapping_artifacts(
            tuple(
                event(
                    event_id=f"fixture:{i}",
                    raw=RawSource.from_payload({"text": "a" * 700_000}, adapter="jsonl"),
                )
                for i in range(3)
            )
        )


@given(st.integers(min_value=0, max_value=999_999))
def test_exact_microseconds_survive_nanosecond_roundtrip(microseconds):
    result = roundtrip_profile(
        event(timestamp=f"2026-01-01T00:00:00.{microseconds:06d}Z"), "otel_like"
    )
    assert result.decision == "lossless"
    assert result.normalization.event.timestamp.microsecond == microseconds


def test_exports_are_deterministic_complete_and_sorted_without_input_mutation():
    a, b = event(), event(event_id="fixture:other")
    before = a.stable_digest()
    files = mapping_artifacts((a, b))
    assert files == mapping_artifacts((b, a))
    assert a.stable_digest() == before
    assert len(files) == 11
    report = MappingExport.model_validate_json(files["mapping_report.json"])
    assert len(report.reports) == 14
    graph = parse_json(files["field_alias_graph.json"])
    assert any(edge["role"] == "alias" for edge in graph["edges"])
    assert {r["profile_id"] for r in parse_json(files["roundtrip_report.json"])["records"]} == set(
        PROFILE_IDS
    )
    for profile in PROFILE_IDS:
        assert SchemaProfile.model_validate_json(
            files[f"schema_profiles/{profile}.json"]
        ) == schema_profile(profile)


def test_strict_model_cross_checks_and_unknown_profile():
    with pytest.raises(ValueError, match="PROFILE"):
        schema_profile("unknown")
    profile = schema_profile("ecs_like")
    with pytest.raises(ValidationError, match="PROFILE"):
        SchemaProfile.model_validate(
            profile.model_dump() | {"fields": (*profile.fields, profile.fields[0])}
        )
    result = normalize_profile(canonical_json(payload()), "ecs_like")
    with pytest.raises(ValidationError, match="STATE"):
        ProfileNormalization.model_validate(result.model_dump() | {"state": "unknown"})


@pytest.mark.parametrize("profile", ["dvi", "ocsf_like", "ecs_like", "otel_like", "suricata_eve"])
@pytest.mark.parametrize(
    "semantics",
    [
        {"category": "dns", "action": "query", "dns_name": "demo.example"},
        {"category": "http", "action": "request", "http_method": "GET", "http_path": "/fixture"},
    ],
)
def test_supported_application_resources_survive_each_declared_event_profile(profile, semantics):
    sample = event(semantics=semantics)
    result = roundtrip_profile(sample, profile)
    assert result.semantic_decision == "equivalent"
    assert result.normalization.event.semantics == sample.semantics
    assert not any(i.code == "unmapped_field" for i in result.issues)


def test_roundtrip_references_and_canonical_snapshots_reject_tampering():
    result = roundtrip_profile(event(), "ecs_like")
    for change in (
        {"source": event(event_id="unrelated")},
        {"normalization": result.normalization.model_copy(update={"profile_id": "dvi"})},
        {"normalization": result.normalization.model_copy(update={"payload_digest": "0" * 64})},
        {"provenance_changed": False},
        {"semantic_decision": "unknown"},
    ):
        with pytest.raises(ValidationError):
            MappingRoundtrip.model_validate(result.model_dump() | change)
    with pytest.raises(ValidationError, match="PAYLOAD"):
        ProfileProjection.model_validate(result.projection.model_dump() | {"payload_json": "[]"})
    with pytest.raises(ValidationError, match="SNAPSHOT"):
        FieldTrace.model_validate(
            result.projection.fields[0].model_dump() | {"source_json": '{"a": 1}'}
        )


@pytest.mark.parametrize(
    "profile,data",
    [
        ("sigma_metadata", {"level": "emergency"}),
        ("suricata_eve", {"alert": {"severity": 99}}),
    ],
)
def test_unsupported_severity_values_are_reported_not_coerced(profile, data):
    result = normalize_profile(canonical_json(payload(profile) | data), profile)
    assert result.event is None and result.state == "unknown"
    assert any(i.field == "severity" and i.code == "invalid_value" for i in result.issues)


def test_example_writes_actual_profile_evidence_and_refuses_replacement(tmp_path):
    script = Path(__file__).parents[1] / "examples/schema_profiles.py"
    output = tmp_path / "profiles"
    result = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert "profiles=7" in result.stdout
    report = MappingExport.model_validate_json((output / "mapping_report.json").read_bytes())
    assert len(report.reports) == 7
    source = report.reports[0].source
    for name, expected in mapping_artifacts((source,)).items():
        assert (output / name).read_bytes() == expected
    denied = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert denied.returncode == 2 and "new local directory" in denied.stderr
