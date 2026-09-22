"""Bounded cross-representation inputs and measured results (pure data models)."""

import hashlib
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from dvi_sentinel.adapters import NormalizationResult
from dvi_sentinel.differential_models import SchemaDifference
from dvi_sentinel.mapping_models import ProfileNormalization, ProfileProjection
from dvi_sentinel.models import NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.ontology_models import SemanticEquivalence
from dvi_sentinel.serialization import canonical_json, digest, parse_json

RepresentationId = Literal[
    "canonical_jsonl",
    "csv",
    "suricata_eve",
    "zeek_like",
    "ecs_like",
    "ocsf_like",
    "otel_like",
    "sigma_metadata",
]
REPRESENTATION_IDS: tuple[RepresentationId, ...] = (
    "canonical_jsonl",
    "csv",
    "ecs_like",
    "ocsf_like",
    "otel_like",
    "sigma_metadata",
    "suricata_eve",
    "zeek_like",
)
FindingClass = Literal[
    "semantic_loss",
    "timestamp_precision_loss",
    "timezone_drift",
    "severity_mapping_drift",
    "field_alias_mismatch",
    "correlation_key_loss",
    "adapter_disagreement",
    "unsupported_profile_feature",
    "metadata_context_loss",
]
ComparisonState = Literal["agree", "disagree", "unknown"]


class RepresentationInput(ValueModel):
    representation: RepresentationId
    content: Annotated[str, Field(max_length=2 * 1024 * 1024)]


class MetamorphicInput(ValueModel):
    source: TelemetryEvent
    representations: Annotated[tuple[RepresentationId, ...], Field(min_length=1, max_length=8)] = (
        REPRESENTATION_IDS
    )
    supplied: Annotated[tuple[RepresentationInput, ...], Field(max_length=8)] = ()

    @field_validator("representations")
    @classmethod
    def ordered_names(cls, value: tuple[RepresentationId, ...]) -> tuple[RepresentationId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("DVI-METAMORPHIC-IDENTITY: duplicate representation")
        return tuple(sorted(value))

    @field_validator("supplied")
    @classmethod
    def ordered_sources(
        cls, value: tuple[RepresentationInput, ...]
    ) -> tuple[RepresentationInput, ...]:
        if len({v.representation for v in value}) != len(value):
            raise ValueError("DVI-METAMORPHIC-IDENTITY: duplicate supplied representation")
        if any(len(v.content.encode("utf-8")) > 65_536 for v in value):
            raise ValueError("DVI-METAMORPHIC-BOUNDS: supplied representation exceeds 64 KiB")
        return tuple(sorted(value, key=lambda v: v.representation))

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if any(v.representation not in self.representations for v in self.supplied):
            raise ValueError("DVI-METAMORPHIC-IDENTITY: supplied content was not selected")
        if len(canonical_json(self).encode("utf-8")) > 262_144:
            raise ValueError("DVI-METAMORPHIC-BOUNDS: complete input exceeds 256 KiB")
        return self


class RepresentationResult(ValueModel):
    representation: RepresentationId
    state: ComparisonState
    source: RepresentationInput | None
    projection: ProfileProjection | None = None
    adapter: NormalizationResult | None = None
    profile: ProfileNormalization | None = None
    semantic: SemanticEquivalence | None = None
    differences: tuple[SchemaDifference, ...] = ()
    failure: NonEmpty | None = None

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.source is not None and self.source.representation != self.representation:
            raise ValueError("DVI-METAMORPHIC-REFERENCE: representation differs")
        if self.adapter is not None and self.profile is not None:
            raise ValueError("DVI-METAMORPHIC-REFERENCE: only one normalizer per row")
        if self.adapter is not None and (
            self.source is None
            or self.adapter.input_digest != hashlib.sha256(self.source.content.encode()).hexdigest()
            or self.adapter.adapter
            != ("jsonl" if self.representation == "canonical_jsonl" else self.representation)
        ):
            raise ValueError("DVI-METAMORPHIC-REFERENCE: adapter input changed")
        if self.projection is not None and (
            self.source is None
            or self.projection.profile_id != self.representation
            or self.projection.payload_json != self.source.content
        ):
            raise ValueError("DVI-METAMORPHIC-REFERENCE: projection input changed")
        if self.profile is not None and (
            self.source is None
            or self.profile.profile_id != self.representation
            or self.profile.payload_digest != digest(parse_json(self.source.content))
        ):
            raise ValueError("DVI-METAMORPHIC-REFERENCE: profile input changed")
        if self.state != "unknown" and (
            self.failure is not None
            or self.semantic is None
            or self.semantic.decision == "unknown"
            or (self.adapter is None and self.profile is None)
        ):
            raise ValueError("DVI-METAMORPHIC-STATE: unresolved evidence cannot agree/disagree")
        if self.state != "unknown" and (
            (
                self.adapter is not None
                and (not self.adapter.parser_success or len(self.adapter.events) != 1)
            )
            or (
                self.profile is not None
                and (
                    self.profile.event is None
                    or any(i.impact == "unknown" for i in self.profile.issues)
                )
            )
        ):
            raise ValueError("DVI-METAMORPHIC-STATE: incomplete normalization cannot resolve")
        if self.state == "agree" and (
            self.differences
            or self.semantic is None
            or self.semantic.decision != "equivalent"
            or any(
                issue.impact != "provenance"
                for owner in (self.projection, self.profile)
                if owner is not None
                for issue in owner.issues
            )
        ):
            raise ValueError("DVI-METAMORPHIC-STATE: agreement contains differences")
        return self


class RepresentationFinding(ValueModel):
    input_digest: Sha256
    finding_class: FindingClass
    representation: RepresentationId
    field_path: NonEmpty
    evidence_ref: NonEmpty
    explanation: NonEmpty


class ProfileComparison(ValueModel):
    left: RepresentationId
    right: RepresentationId
    state: ComparisonState
    semantic: SemanticEquivalence | None
    differences: tuple[SchemaDifference, ...]
    evidence_refs: tuple[NonEmpty, NonEmpty]

    @model_validator(mode="after")
    def coherent(self) -> Self:
        expected = (
            "unknown"
            if self.semantic is None or self.semantic.decision == "unknown"
            else "disagree"
            if self.differences or self.semantic.decision == "different"
            else "agree"
        )
        if self.state != expected:
            raise ValueError("DVI-METAMORPHIC-MATRIX: pair state differs from measured evidence")
        return self


class MetamorphicReport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    state: Literal["agree", "disagree", "unknown", "unsafe_rejected"]
    input: MetamorphicInput | None
    results: Annotated[tuple[RepresentationResult, ...], Field(max_length=8)]
    findings: Annotated[tuple[RepresentationFinding, ...], Field(max_length=4096)]
    matrix: Annotated[tuple[ProfileComparison, ...], Field(max_length=64)]
    explanation: NonEmpty

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.input is None:
            if (
                self.results
                or self.findings
                or self.matrix
                or self.state not in {"unknown", "unsafe_rejected"}
            ):
                raise ValueError("DVI-METAMORPHIC-GATE: blocked input cannot be exported")
            return self
        if self.input.stable_digest() != self.input_digest:
            raise ValueError("DVI-METAMORPHIC-REFERENCE: input digest differs")
        names = tuple(row.representation for row in self.results)
        if names != self.input.representations or tuple(
            (p.left, p.right) for p in self.matrix
        ) != tuple((left, right) for left in names for right in names):
            raise ValueError("DVI-METAMORPHIC-MATRIX: results and complete matrix must align")
        expected = (
            "unknown"
            if any(row.state == "unknown" for row in self.results)
            else "disagree"
            if any(row.state == "disagree" for row in self.results)
            else "agree"
        )
        if self.state != expected:
            raise ValueError("DVI-METAMORPHIC-STATE: report differs from measured rows")
        if any(
            f.representation not in names or f.input_digest != self.input_digest
            for f in self.findings
        ):
            raise ValueError("DVI-METAMORPHIC-REFERENCE: finding lacks representation")
        supplied = {v.representation: v for v in self.input.supplied}
        for row in self.results:
            if (
                row.projection is not None
                and row.projection.source_digest != self.input.source.stable_digest()
            ):
                raise ValueError("DVI-METAMORPHIC-REFERENCE: projection belongs to another event")
            if row.representation in supplied and row.source != supplied[row.representation]:
                raise ValueError("DVI-METAMORPHIC-REFERENCE: supplied bytes changed")
        for i, left in enumerate(self.results):
            for j, right in enumerate(self.results):
                pair = self.matrix[i * len(names) + j]
                if pair.evidence_refs != (f"/results/{i}", f"/results/{j}") or (
                    (left.state == "unknown" or right.state == "unknown")
                    and pair.state != "unknown"
                ):
                    raise ValueError("DVI-METAMORPHIC-MATRIX: unresolved rows or wrong references")
        return self


class RepresentationDiff(ValueModel):
    input_digest: Sha256
    findings: tuple[RepresentationFinding, ...]


class CrossProfileMatrix(ValueModel):
    input_digest: Sha256
    comparisons: tuple[ProfileComparison, ...]
