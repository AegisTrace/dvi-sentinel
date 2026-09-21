"""Bounded evidence and immutable multi-oracle decisions (pure data models)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictFloat, StrictInt, model_validator

from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.harness_models import HarnessResult
from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES
from dvi_sentinel.models import (
    DetectionEvent,
    Identifier,
    NonEmpty,
    Sha256,
    TelemetryEvent,
    ValueModel,
)
from dvi_sentinel.scenario import DetectionExpectation
from dvi_sentinel.serialization import canonical_json, digest

OracleId = Literal[
    "safety",
    "schema",
    "semantic",
    "temporal",
    "differential",
    "detection",
    "statistical",
    "evidence",
    "provenance",
]
ORACLE_IDS: tuple[OracleId, ...] = (
    "detection",
    "differential",
    "evidence",
    "provenance",
    "safety",
    "schema",
    "semantic",
    "statistical",
    "temporal",
)
GATE_IDS = frozenset({"safety", "schema", "semantic", "evidence", "provenance"})
VOTER_IDS = frozenset({"detection", "temporal", "statistical"})
Decision = Literal["pass", "fail", "warn", "unknown", "not_applicable", "unsafe_rejected"]
ConsensusState = Literal[
    "confirmed",
    "probable",
    "ambiguous",
    "unknown",
    "suppressed_false_positive",
    "unsafe_rejected",
    "not_enough_evidence",
]
Event = DetectionEvent | TelemetryEvent
EvidencePath = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^/[\w./-]+$")]
Confidence = Annotated[StrictFloat, Field(ge=0, le=1)]


class OracleEvidence(ValueModel):
    """One proposed detection gap, with actual fixture events and observations."""

    subject_id: Identifier
    events: Annotated[tuple[Event, ...], Field(max_length=128)]
    expected: DetectionExpectation | None = None
    observation: HarnessResult | None = None
    repetitions: Annotated[tuple[HarnessResult, ...], Field(max_length=128)] = ()
    representations: Annotated[tuple[FixtureRepresentation, ...], Field(max_length=3)] = ()
    required_paths: Annotated[tuple[EvidencePath, ...], Field(max_length=32)] = (
        "/events",
        "/expected",
        "/observation",
    )
    precision_digits: Annotated[StrictInt, Field(ge=0, le=6)] = 0
    minimum_repetitions: Annotated[StrictInt, Field(ge=2, le=128)] = 3

    @model_validator(mode="after")
    def bounded(self) -> Self:
        groups: list[tuple[TelemetryEvent, ...]] = [self.events]
        observations = (*self.repetitions, *((self.observation,) if self.observation else ()))
        for observation in observations:
            if len(observation.detections) > 128:
                raise ValueError("DVI-ORACLE-BOUNDS: at most 128 detections per observation")
            groups.append(observation.detections)
        if any(len({event.event_id for event in group}) != len(group) for group in groups):
            raise ValueError("DVI-ORACLE-EVENTS: event IDs must be unique within each observation")
        repeat_ids = [item.case_id for item in self.repetitions]
        if len(set(repeat_ids)) != len(repeat_ids):
            raise ValueError("DVI-ORACLE-REPETITIONS: repetition IDs must be unique")
        if self.observation and self.observation.case_id in repeat_ids:
            raise ValueError("DVI-ORACLE-REPETITIONS: primary observation cannot count as a repeat")
        if self.observation and self.observation.case_id != self.subject_id:
            raise ValueError("DVI-ORACLE-SUBJECT: primary observation belongs to another subject")
        if len({item.representation for item in self.representations}) != len(self.representations):
            raise ValueError("DVI-ORACLE-REPRESENTATIONS: representation names must be unique")
        if len(set(self.required_paths)) != len(self.required_paths):
            raise ValueError("DVI-ORACLE-EVIDENCE: required paths must be unique")
        if len(canonical_json(self).encode("utf-8")) > MAX_FIXTURE_BYTES:
            raise ValueError("DVI-ORACLE-BOUNDS: combined evidence exceeds 2 MiB")
        return self


class OracleDecision(ValueModel):
    """Confidence is local evidence resolution, never a probability of truth."""

    oracle_id: OracleId
    subject_id: Identifier
    input_digest: Sha256
    decision: Decision
    confidence: Confidence
    confidence_basis: NonEmpty
    severity: Annotated[StrictInt, Field(ge=0, le=5)]
    evidence_refs: Annotated[tuple[EvidencePath, ...], Field(max_length=256)] = ()
    reason_codes: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()
    explanation: NonEmpty
    uncertainty: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()
    blocking: StrictBool = False

    @model_validator(mode="after")
    def coherent(self) -> Self:
        for values in (self.evidence_refs, self.reason_codes, self.uncertainty):
            if tuple(sorted(set(values))) != values:
                raise ValueError(
                    "DVI-ORACLE-ORDER: evidence and reason lists must be unique/sorted"
                )
        must_block = self.oracle_id in {"safety", "provenance"} and self.decision in {
            "fail",
            "unsafe_rejected",
        }
        if self.blocking != must_block:
            raise ValueError("DVI-ORACLE-BLOCKING: only safety/provenance failures override")
        if self.decision == "unsafe_rejected" and not must_block:
            raise ValueError("DVI-ORACLE-BLOCKING: unsafe rejection requires an integrity gate")
        return self


class OracleResult(OracleDecision):
    digest: Sha256

    @classmethod
    def from_decision(cls, decision: OracleDecision) -> Self:
        return cls.model_validate(decision.model_dump(mode="json") | {"digest": digest(decision)})

    @model_validator(mode="after")
    def verify_digest(self) -> Self:
        if self.digest != digest(self.model_dump(mode="json", exclude={"digest"})):
            raise ValueError("DVI-ORACLE-DIGEST: decision content changed")
        return self


class OracleConsensus(ValueModel):
    schema_version: Literal["1"] = "1"
    subject_id: Identifier
    input_digest: Sha256
    claim: Literal["local_detection_gap"] = "local_detection_gap"
    state: ConsensusState
    confidence: Confidence
    confidence_basis: NonEmpty
    decisions: Annotated[tuple[OracleResult, ...], Field(min_length=1, max_length=9)]
    supporting_oracles: tuple[OracleId, ...]
    opposing_oracles: tuple[OracleId, ...]
    blocking_oracles: tuple[OracleId, ...]
    missing_oracles: tuple[OracleId, ...]
    disagreements: tuple[OracleId, ...]
    explanation: NonEmpty
    evidence: OracleEvidence | None = None

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.evidence is not None and (
            self.evidence.subject_id != self.subject_id
            or self.evidence.stable_digest() != self.input_digest
        ):
            raise ValueError("DVI-ORACLE-CONSENSUS: evidence differs from decision inputs")
        if any(
            row.subject_id != self.subject_id or row.input_digest != self.input_digest
            for row in self.decisions
        ):
            raise ValueError("DVI-ORACLE-CONSENSUS: decision references another input")
        if tuple(row.oracle_id for row in self.decisions) != tuple(
            sorted({row.oracle_id for row in self.decisions})
        ):
            raise ValueError("DVI-ORACLE-CONSENSUS: decisions must be unique and sorted")
        return self


class UncertaintyReport(ValueModel):
    schema_version: Literal["1"] = "1"
    subject_id: Identifier
    input_digest: Sha256
    state: ConsensusState
    confidence: Confidence
    unresolved_oracles: tuple[OracleId, ...]
    reason_codes: tuple[Identifier, ...]
    explanation: NonEmpty


class OracleMatrixCell(ValueModel):
    oracle_id: OracleId
    role: Literal["gate", "diagnostic", "corroborating"]
    decision: Decision
    confidence: Confidence
    result_digest: Sha256


class OracleMatrix(ValueModel):
    schema_version: Literal["1"] = "1"
    subject_id: Identifier
    input_digest: Sha256
    cells: Annotated[tuple[OracleMatrixCell, ...], Field(min_length=1, max_length=9)]
