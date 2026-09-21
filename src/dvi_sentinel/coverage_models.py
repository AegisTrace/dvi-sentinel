"""Bounded inputs and measured discovery coverage records (pure data models)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.adapters import NormalizationResult
from dvi_sentinel.differential_models import SchemaDifference
from dvi_sentinel.mapping_models import MappingRoundtrip, ProfileId
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.ontology_models import OntologyExtraction, SemanticEquivalence
from dvi_sentinel.oracle_models import OracleConsensus, OracleEvidence, OracleResult
from dvi_sentinel.serialization import canonical_json

Dimension = Literal[
    "semantic_signal",
    "invariant_state",
    "matcher_branch",
    "adapter_path",
    "schema_profile_path",
    "temporal_relation_state",
    "oracle_disagreement_class",
    "fragility_class",
    "field_mapping_path",
    "normalization_loss_path",
    "correlation_path",
    "evidence_quality_state",
]
DIMENSIONS: tuple[Dimension, ...] = (
    "adapter_path",
    "correlation_path",
    "evidence_quality_state",
    "field_mapping_path",
    "fragility_class",
    "invariant_state",
    "matcher_branch",
    "normalization_loss_path",
    "oracle_disagreement_class",
    "schema_profile_path",
    "semantic_signal",
    "temporal_relation_state",
)
State = Literal["known", "unknown", "unsafe_rejected"]
GateState = Literal["pass", "unknown", "unsafe_rejected"]
RetentionReason = Literal[
    "new_coverage", "duplicate_coverage", "unknown_coverage", "unsafe_rejected"
]
Count = Annotated[StrictInt, Field(ge=0, le=200_000)]


class CoverageCaseInput(ValueModel):
    evidence: OracleEvidence
    expected_digest: Sha256 | None = None
    reference_events: Annotated[tuple[TelemetryEvent, ...], Field(max_length=8)] = ()
    reference_digest: Sha256 | None = None
    profiles: Annotated[tuple[ProfileId, ...], Field(max_length=3)] = ("dvi",)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len(self.evidence.events) > 8:
            raise ValueError("DVI-COVERAGE-BOUNDS: at most eight input events per case")
        if len({e.event_id for e in self.reference_events}) != len(self.reference_events):
            raise ValueError("DVI-COVERAGE-REFERENCE: duplicate reference event IDs")
        if len(set(self.profiles)) != len(self.profiles):
            raise ValueError("DVI-COVERAGE-PROFILE: duplicate profile")
        if len(canonical_json(self).encode("utf-8")) > 262_144:
            raise ValueError("DVI-COVERAGE-BOUNDS: complete input case exceeds 256 KiB")
        return self


class AdapterMeasurement(ValueModel):
    representation: NonEmpty
    normalized: NormalizationResult
    differences: tuple[SchemaDifference, ...]


class CoverageMeasurements(ValueModel):
    signals: Annotated[tuple[OntologyExtraction, ...], Field(max_length=8)]
    invariants: Annotated[tuple[SemanticEquivalence, ...], Field(max_length=8)]
    adapters: Annotated[tuple[AdapterMeasurement, ...], Field(max_length=3)]
    mappings: Annotated[tuple[MappingRoundtrip, ...], Field(max_length=24)]
    match: MatchResult | None
    oracles: Annotated[tuple[OracleResult, ...], Field(min_length=9, max_length=9)]
    consensus: OracleConsensus


class DimensionObservation(ValueModel):
    dimension: Dimension
    state: State
    values: Annotated[tuple[NonEmpty, ...], Field(max_length=1024)]
    evidence_refs: Annotated[tuple[NonEmpty, ...], Field(max_length=16)]
    explanation: NonEmpty

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if tuple(sorted(set(self.values))) != self.values:
            raise ValueError("DVI-COVERAGE-VALUES: values must be unique and sorted")
        if self.state == "known" and not self.values:
            raise ValueError("DVI-COVERAGE-VALUES: known dimensions need measured values")
        return self


class CaseCoverage(ValueModel):
    case_id: Identifier
    input_digest: Sha256
    state: State
    observations: Annotated[tuple[DimensionObservation, ...], Field(min_length=12, max_length=12)]
    input: CoverageCaseInput | None
    measurements: CoverageMeasurements | None

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if tuple(row.dimension for row in self.observations) != DIMENSIONS:
            raise ValueError("DVI-COVERAGE-DIMENSIONS: require all dimensions in canonical order")
        state = (
            "unsafe_rejected"
            if any(row.state == "unsafe_rejected" for row in self.observations)
            else "unknown"
            if any(row.state == "unknown" for row in self.observations)
            else "known"
        )
        if self.state != state:
            raise ValueError("DVI-COVERAGE-STATE: case state differs from its observations")
        if self.input is not None and (
            self.input.stable_digest() != self.input_digest
            or self.input.evidence.subject_id != self.case_id
        ):
            raise ValueError("DVI-COVERAGE-DIGEST: retained input changed")
        if self.state == "unsafe_rejected" and (
            self.input is not None or self.measurements is not None
        ):
            raise ValueError("DVI-COVERAGE-SAFETY: blocked input cannot be re-exported")
        if self.state == "known" and (self.input is None or self.measurements is None):
            raise ValueError("DVI-COVERAGE-EVIDENCE: known coverage needs retained measurements")
        return self


class CoverageToken(ValueModel):
    dimension: Dimension
    value: NonEmpty


class RetentionDecision(ValueModel):
    case_id: Identifier
    input_digest: Sha256
    retained: StrictBool
    new_tokens: Annotated[tuple[CoverageToken, ...], Field(max_length=12_288)]
    reason: RetentionReason
    explanation: NonEmpty

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.retained != bool(self.new_tokens) or self.retained != (
            self.reason == "new_coverage"
        ):
            raise ValueError("DVI-COVERAGE-RETENTION: retention needs actual new tokens")
        return self


class GrowthPoint(ValueModel):
    case_id: Identifier
    added: Count
    cumulative: Count


class CoverageEvidenceGate(ValueModel):
    state: GateState
    passed: StrictBool
    unresolved_cases: Annotated[tuple[Identifier, ...], Field(max_length=16)]
    explanation: NonEmpty

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.passed != (self.state == "pass") or (self.passed and self.unresolved_cases):
            raise ValueError("DVI-COVERAGE-GATE: unresolved evidence cannot pass")
        return self


class SemanticCoverage(ValueModel):
    schema_version: Literal["1"] = "1"
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    cases: Annotated[tuple[CaseCoverage, ...], Field(min_length=1, max_length=16)]
    tokens: Annotated[tuple[CoverageToken, ...], Field(max_length=196_608)]
    retention: Annotated[tuple[RetentionDecision, ...], Field(min_length=1, max_length=16)]
    growth: Annotated[tuple[GrowthPoint, ...], Field(min_length=1, max_length=16)]
    evidence_gate: CoverageEvidenceGate

    @model_validator(mode="after")
    def coherent(self) -> Self:
        case_ids = tuple(case.case_id for case in self.cases)
        if (
            len(set(case_ids)) != len(case_ids)
            or tuple(row.case_id for row in self.retention) != case_ids
            or tuple(row.case_id for row in self.growth) != case_ids
        ):
            raise ValueError("DVI-COVERAGE-IDENTITY: case, retention and growth rows must align")
        seen: set[tuple[Dimension, str]] = set()
        for case, retention, point in zip(self.cases, self.retention, self.growth, strict=True):
            if retention.input_digest != case.input_digest:
                raise ValueError("DVI-COVERAGE-DIGEST: queue entry belongs to another input")
            measured = {
                (row.dimension, value)
                for row in case.observations
                if row.state == "known"
                for value in row.values
            }
            added = measured - seen
            seen.update(measured)
            if (
                tuple((t.dimension, t.value) for t in retention.new_tokens) != tuple(sorted(added))
                or point.added != len(added)
                or point.cumulative != len(seen)
            ):
                raise ValueError("DVI-COVERAGE-GROWTH: duplicate or unmeasured coverage counted")
        if tuple((t.dimension, t.value) for t in self.tokens) != tuple(sorted(seen)):
            raise ValueError("DVI-COVERAGE-TOTAL: tokens differ from measured union")
        expected = (
            "unsafe_rejected"
            if any(case.state == "unsafe_rejected" for case in self.cases)
            else "unknown"
            if any(case.state == "unknown" for case in self.cases)
            else "pass"
        )
        if self.evidence_gate.state != expected or self.evidence_gate.unresolved_cases != tuple(
            sorted(case.case_id for case in self.cases if case.state != "known")
        ):
            raise ValueError("DVI-COVERAGE-GATE: skipped unresolved cases cannot bypass gate")
        return self


class CoverageGrowth(ValueModel):
    seed: StrictInt
    points: tuple[GrowthPoint, ...]
    final_count: Count


class CoverageRetention(ValueModel):
    seed: StrictInt
    decisions: tuple[RetentionDecision, ...]
    evidence_gate: CoverageEvidenceGate
