"""Pinned run history, immutable baseline bindings and drift evidence (D)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from dvi_sentinel.confidence_models import ConfidenceInput, ConfidenceReport, SeedComparison
from dvi_sentinel.mapping_models import ProfileId, SchemaProfile
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.serialization import canonical_json

DriftClass = Literal[
    "stable_strong",
    "still_fragile",
    "newly_fragile",
    "recovered",
    "unstable",
    "incompatible",
    "unknown",
]
MemoryState = Literal["evaluated", "unknown", "unsafe_rejected"]


class DetectorRevision(ValueModel):
    detector_id: Identifier
    version: Identifier
    comparison_contract: Identifier
    definition_digest: Sha256


class ProfileStamp(ValueModel):
    profile_id: ProfileId
    revision: Identifier
    definition_digest: Sha256

    @classmethod
    def from_profile(cls, profile: SchemaProfile) -> Self:
        return cls(
            profile_id=profile.profile_id,
            revision=profile.revision,
            definition_digest=profile.stable_digest(),
        )


class DriftRecord(ValueModel):
    id: Identifier
    sequence: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    detector: DetectorRevision
    profiles: Annotated[tuple[ProfileStamp, ...], Field(min_length=1, max_length=7)]
    measurement: ConfidenceInput

    @field_validator("profiles")
    @classmethod
    def ordered_profiles(cls, rows: tuple[ProfileStamp, ...]) -> tuple[ProfileStamp, ...]:
        if len({r.profile_id for r in rows}) != len(rows):
            raise ValueError("DVI-MEMORY-PROFILES: duplicate profile identity")
        return tuple(sorted(rows, key=lambda row: row.profile_id))

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.measurement.previous:
            raise ValueError("DVI-MEMORY-RECORD: a record contains one current-only seed batch")
        for run in self.measurement.current:
            if run.snapshot.detector_digest != self.detector.definition_digest or any(
                p.evidence.expected is not None
                and p.evidence.expected.detector != self.detector.detector_id
                for p in run.evidence
            ):
                raise ValueError("DVI-MEMORY-DETECTOR: metadata differs from retained observations")
        return self


class PinnedRecord(ValueModel):
    record: DriftRecord
    expected_digest: Sha256


class BaselineEntry(ValueModel):
    name: Identifier
    record_id: Identifier
    record_digest: Sha256


class DriftMemory(ValueModel):
    schema_version: Literal["1"] = "1"
    records: Annotated[tuple[PinnedRecord, ...], Field(max_length=8)] = ()
    baselines: Annotated[tuple[BaselineEntry, ...], Field(max_length=16)] = ()

    @field_validator("records")
    @classmethod
    def ordered_records(cls, rows: tuple[PinnedRecord, ...]) -> tuple[PinnedRecord, ...]:
        if len({p.record.id for p in rows}) != len(rows) or len(
            {p.record.sequence for p in rows}
        ) != len(rows):
            raise ValueError("DVI-MEMORY-IDENTITY: record IDs and sequences must be unique")
        return tuple(sorted(rows, key=lambda p: p.record.sequence))

    @field_validator("baselines")
    @classmethod
    def ordered_baselines(cls, rows: tuple[BaselineEntry, ...]) -> tuple[BaselineEntry, ...]:
        if len({row.name for row in rows}) != len(rows):
            raise ValueError("DVI-MEMORY-BASELINE: baseline names must be unique")
        return tuple(sorted(rows, key=lambda row: row.name))

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if (
            sum(len(run.evidence) for p in self.records for run in p.record.measurement.current)
            > 512
        ):
            raise ValueError("DVI-MEMORY-BOUNDS: at most 512 evidence records in history")
        if len(canonical_json(self).encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("DVI-MEMORY-BOUNDS: history exceeds 4 MiB")
        return self


class DriftPolicy(ValueModel):
    minimum_confidence: Literal["low_confidence", "moderate_confidence"] = "moderate_confidence"
    max_plausible_detection_drop: Annotated[float, Field(ge=0, le=1)] = 0.05


class DriftInput(ValueModel):
    schema_version: Literal["1"] = "1"
    memory: DriftMemory
    current_id: Identifier
    named_baseline: Identifier | None = None
    policy: DriftPolicy = DriftPolicy()

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len(canonical_json(self).encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("DVI-MEMORY-BOUNDS: complete request exceeds 4 MiB")
        return self


class DriftGate(ValueModel):
    status: Literal["pass", "fail", "unknown"]
    exit_status: Literal[0, 1, 2]
    reasons: tuple[Identifier, ...]

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.exit_status != {"pass": 0, "fail": 1, "unknown": 2}[self.status]:
            raise ValueError("DVI-MEMORY-GATE: exit status differs from decision")
        if tuple(sorted(set(self.reasons))) != self.reasons or not self.reasons:
            raise ValueError("DVI-MEMORY-GATE: require unique ordered decision reasons")
        return self


class DriftPoint(ValueModel):
    record_id: Identifier
    record_digest: Sha256
    confidence: ConfidenceReport


class DriftComparison(ValueModel):
    id: Identifier
    kind: Literal["previous", "baseline"]
    previous_id: Identifier
    previous_digest: Sha256
    current_id: Identifier
    current_digest: Sha256
    classification: DriftClass
    gate: DriftGate
    reasons: tuple[Identifier, ...]
    compatibility_details: tuple[NonEmpty, ...] = ()
    seed_results: Annotated[tuple[SeedComparison, ...], Field(max_length=8)] = ()


class DriftReport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    input: DriftInput | None
    state: MemoryState
    points: Annotated[tuple[DriftPoint, ...], Field(max_length=8)] = ()
    trend: Annotated[tuple[DriftComparison, ...], Field(max_length=7)] = ()
    baseline_comparison: DriftComparison | None = None
    classification: DriftClass
    gate: DriftGate
    reasons: tuple[Identifier, ...]
    interpretation: NonEmpty

    @model_validator(mode="after")
    def derived(self) -> Self:
        if self.input is None:
            if (
                self.points
                or self.trend
                or self.baseline_comparison
                or self.state == "evaluated"
                or self.classification != "unknown"
                or self.gate.status != ("fail" if self.state == "unsafe_rejected" else "unknown")
            ):
                raise ValueError("DVI-MEMORY-GATE: blocked input cannot contain derived history")
            return self
        from dvi_sentinel.regression_memory import INTERPRETATION, _derive, _prefix, _verify_memory

        if self.input_digest != self.input.stable_digest():
            raise ValueError("DVI-MEMORY-PIN: report input changed")
        _verify_memory(self.input.memory)
        records = _prefix(self.input)
        if len(records) != len(self.points):
            raise ValueError("DVI-MEMORY-POINTS: history coverage differs")
        for record, point in zip(records, self.points, strict=True):
            if (
                point.record_id != record.id
                or point.record_digest != record.stable_digest()
                or point.confidence.input != record.measurement
                or point.confidence.state != "measured"
            ):
                raise ValueError("DVI-MEMORY-POINTS: confidence belongs to another observation")
        expected = _derive(self.input, self.points)
        actual = (
            self.state,
            self.trend,
            self.baseline_comparison,
            self.classification,
            self.gate,
            self.reasons,
        )
        if actual != expected or self.interpretation != INTERPRETATION:
            raise ValueError("DVI-MEMORY-DERIVATION: drift decisions differ from retained evidence")
        return self


class MemoryArtifact(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    state: MemoryState
    memory: DriftMemory | None
    memory_digest: Sha256 | None

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.memory_digest != (self.memory.stable_digest() if self.memory is not None else None):
            raise ValueError("DVI-MEMORY-PIN: ledger digest differs")
        if self.state == "unsafe_rejected" and self.memory is not None:
            raise ValueError("DVI-MEMORY-GATE: unsafe history must be omitted")
        return self


class RegistryArtifact(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    memory_digest: Sha256 | None
    state: MemoryState
    entries: tuple[BaselineEntry, ...]


class UncertaintyArtifact(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    state: MemoryState
    trend: tuple[DriftComparison, ...]
    baseline_comparison: DriftComparison | None
    classification: DriftClass
    gate: DriftGate
    interpretation: NonEmpty
