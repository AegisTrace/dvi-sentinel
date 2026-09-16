"""Immutable contracts for bounded local schema projections and their loss evidence."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from dvi_sentinel.models import (
    DetectionEvent,
    Identifier,
    NonEmpty,
    Sha256,
    TelemetryEvent,
    ValueModel,
)
from dvi_sentinel.serialization import canonical_json, digest, parse_json

ProfileId = Literal[
    "dvi", "ocsf_like", "ecs_like", "otel_like", "suricata_eve", "zeek_like", "sigma_metadata"
]
Codec = Literal[
    "identity", "rfc3339", "epoch_ms", "epoch_ns", "epoch_seconds", "eve_severity", "sigma_level"
]
KeyPath = Annotated[tuple[NonEmpty, ...], Field(min_length=1, max_length=6)]
Snapshot = Annotated[str, Field(max_length=2 * 1024 * 1024)]


class FieldProjection(ValueModel):
    canonical_field: NonEmpty
    path: KeyPath
    aliases: Annotated[tuple[KeyPath, ...], Field(max_length=4)] = ()
    codec: Codec = "identity"
    extension: StrictBool = False


class SchemaProfile(ValueModel):
    profile_id: ProfileId
    revision: Literal["1"] = "1"
    reference_version: NonEmpty
    reference_url: NonEmpty
    scope: NonEmpty
    fields: Annotated[tuple[FieldProjection, ...], Field(max_length=40)]
    metadata_only: StrictBool = False

    @model_validator(mode="after")
    def unique_fields(self) -> Self:
        names = [field.canonical_field for field in self.fields]
        paths = [path for field in self.fields for path in (field.path, *field.aliases)]
        if len(set(names)) != len(names) or len(set(paths)) != len(paths):
            raise ValueError("DVI-MAPPING-PROFILE: field names and paths must be unique")
        return self


class MappingIssue(ValueModel):
    code: Literal[
        "unmapped_field",
        "unsupported_field",
        "alias_ambiguity",
        "missing_required_field",
        "invalid_value",
        "timestamp_precision_loss",
        "severity_mapping_drift",
        "value_changed",
        "metadata_only",
        "source_provenance_changed",
    ]
    field: NonEmpty
    impact: Literal["loss", "unknown", "provenance"]
    explanation: NonEmpty


class FieldTrace(ValueModel):
    canonical_field: NonEmpty
    profile_paths: tuple[KeyPath, ...]
    source_json: Snapshot | None
    target_json: Snapshot | None
    state: Literal["mapped", "unmapped", "lossy", "unknown"]

    @model_validator(mode="after")
    def canonical_snapshots(self) -> Self:
        for value in (self.source_json, self.target_json):
            if value is not None and canonical_json(parse_json(value)) != value:
                raise ValueError("DVI-MAPPING-SNAPSHOT: expected canonical JSON")
        return self


class ProfileProjection(ValueModel):
    profile_id: ProfileId
    source_digest: Sha256
    payload_json: Snapshot
    fields: tuple[FieldTrace, ...]
    issues: tuple[MappingIssue, ...]

    @model_validator(mode="after")
    def canonical_payload(self) -> Self:
        payload = parse_json(self.payload_json)
        if not isinstance(payload, dict) or canonical_json(payload) != self.payload_json:
            raise ValueError("DVI-MAPPING-PAYLOAD: expected canonical JSON object")
        return self


class ProfileNormalization(ValueModel):
    profile_id: ProfileId
    payload_digest: Sha256
    event: DetectionEvent | TelemetryEvent | None
    fields: tuple[FieldTrace, ...]
    issues: tuple[MappingIssue, ...]
    state: Literal["known", "unknown"]

    @model_validator(mode="after")
    def known_needs_evidence(self) -> Self:
        known = self.event is not None and not any(i.impact != "provenance" for i in self.issues)
        if (self.state == "known") != known:
            raise ValueError("DVI-MAPPING-STATE: state disagrees with evidence")
        return self


class MappingRoundtrip(ValueModel):
    schema_version: Literal["1"] = "1"
    source: DetectionEvent | TelemetryEvent
    projection: ProfileProjection
    normalization: ProfileNormalization
    changes: tuple[FieldTrace, ...]
    issues: tuple[MappingIssue, ...]
    semantic_decision: Literal["equivalent", "different", "unknown"]
    decision: Literal["lossless", "lossy", "unknown"]
    provenance_changed: StrictBool

    @model_validator(mode="after")
    def related_inputs(self) -> Self:
        if self.source.stable_digest() != self.projection.source_digest:
            raise ValueError("DVI-MAPPING-REFERENCE: source digest differs")
        if self.projection.profile_id != self.normalization.profile_id:
            raise ValueError("DVI-MAPPING-REFERENCE: profiles differ")
        if digest(parse_json(self.projection.payload_json)) != self.normalization.payload_digest:
            raise ValueError("DVI-MAPPING-REFERENCE: payload digest differs")
        candidate = self.normalization.event
        if self.provenance_changed != (candidate is not None and self.source.raw != candidate.raw):
            raise ValueError("DVI-MAPPING-REFERENCE: provenance disposition differs")
        if self.decision == "lossless" and (
            self.normalization.state != "known"
            or self.changes
            or self.semantic_decision != "equivalent"
            or any(issue.impact != "provenance" for issue in self.issues)
        ):
            raise ValueError("DVI-MAPPING-STATE: lossless decision contains unresolved loss")
        return self


class MappingExport(ValueModel):
    schema_version: Literal["1"] = "1"
    reports: Annotated[tuple[MappingRoundtrip, ...], Field(min_length=1, max_length=224)]


class LossRecord(ValueModel):
    event_id: Identifier
    profile_id: ProfileId
    issues: tuple[MappingIssue, ...]


class LossExport(ValueModel):
    schema_version: Literal["1"] = "1"
    records: tuple[LossRecord, ...]


class AliasEdge(ValueModel):
    profile_id: ProfileId
    canonical_field: NonEmpty
    path: KeyPath
    role: Literal["primary", "alias"]


class AliasGraph(ValueModel):
    schema_version: Literal["1"] = "1"
    edges: tuple[AliasEdge, ...]


class RoundtripSummary(ValueModel):
    event_id: Identifier
    profile_id: ProfileId
    source_digest: Sha256
    payload_digest: Sha256
    destination_digest: Sha256 | None
    decision: Literal["lossless", "lossy", "unknown"]
    semantic_decision: Literal["equivalent", "different", "unknown"]
    provenance_changed: StrictBool


class RoundtripExport(ValueModel):
    schema_version: Literal["1"] = "1"
    records: tuple[RoundtripSummary, ...]
