"""Immutable temporal and correlation evidence records."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.ontology_models import JsonSnapshot
from dvi_sentinel.serialization import canonical_json, parse_json

TemporalPredicate = Literal[
    "before",
    "after",
    "within",
    "same_entity",
    "same_flow",
    "same_correlation_key",
    "at_least_k_of_n",
    "no_contradictory_context",
    "alert_within_window",
    "sequence_order",
]
TemporalState = Literal["supported", "contradicted", "unknown"]


class TemporalCheck(ValueModel):
    predicate: TemporalPredicate
    event_ids: Annotated[tuple[Identifier, ...], Field(max_length=128)]
    outcome: TemporalState
    reason_codes: Annotated[tuple[Identifier, ...], Field(max_length=16)] = ()
    expected_json: JsonSnapshot | None = None
    observed_json: JsonSnapshot | None = None
    explanation: NonEmpty

    @model_validator(mode="after")
    def canonical_values(self) -> Self:
        for value in (self.expected_json, self.observed_json):
            if value is not None and canonical_json(parse_json(value)) != value:
                raise ValueError("DVI-TEMPORAL-VALUE: snapshots must be canonical JSON")
        return self


class TemporalTrace(ValueModel):
    trace_id: Identifier
    sequence_index: Annotated[StrictInt, Field(ge=0)]
    check: TemporalCheck
    normalized_timestamps: Annotated[tuple[JsonSnapshot, ...], Field(max_length=128)]
    source_precision_digits: Annotated[tuple[StrictInt | None, ...], Field(max_length=128)] = ()
    timezone_normalized: StrictBool = True

    @model_validator(mode="after")
    def trace_integrity(self) -> Self:
        if self.check.event_ids and len(self.normalized_timestamps) != len(self.check.event_ids):
            raise ValueError("DVI-TEMPORAL-TRACE: timestamps must match event references")
        if self.source_precision_digits and len(self.source_precision_digits) != len(
            self.check.event_ids
        ):
            raise ValueError("DVI-TEMPORAL-TRACE: precision evidence must match event references")
        return self


class CorrelationEvidence(ValueModel):
    key: Identifier
    event_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=128)]
    values_json: Annotated[tuple[JsonSnapshot | None, ...], Field(min_length=1, max_length=128)]
    outcome: TemporalState
    explanation: NonEmpty

    @model_validator(mode="after")
    def linked_values(self) -> Self:
        if len(self.event_ids) != len(self.values_json) or len(set(self.event_ids)) != len(
            self.event_ids
        ):
            raise ValueError("DVI-TEMPORAL-CORRELATION: values must match unique event IDs")
        for value in self.values_json:
            if value is not None and canonical_json(parse_json(value)) != value:
                raise ValueError("DVI-TEMPORAL-VALUE: correlation snapshots must be canonical JSON")
        return self


class SequenceFinding(ValueModel):
    finding_id: Identifier
    predicate: TemporalPredicate
    event_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=128)]
    outcome: TemporalState
    reason_codes: Annotated[tuple[Identifier, ...], Field(max_length=16)]
    explanation: NonEmpty


class TemporalSummary(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    ordered_event_ids: Annotated[tuple[Identifier, ...], Field(max_length=128)]
    traces: Annotated[tuple[TemporalTrace, ...], Field(max_length=512)]
    findings: Annotated[tuple[SequenceFinding, ...], Field(max_length=512)]
    correlation_evidence: Annotated[tuple[CorrelationEvidence, ...], Field(max_length=512)] = ()
    state: TemporalState

    @model_validator(mode="after")
    def summary_integrity(self) -> Self:
        if len(set(self.ordered_event_ids)) != len(self.ordered_event_ids):
            raise ValueError("DVI-TEMPORAL-SUMMARY: event IDs must be unique")
        if any(
            item.check.event_ids and not set(item.check.event_ids) <= set(self.ordered_event_ids)
            for item in self.traces
        ):
            raise ValueError("DVI-TEMPORAL-SUMMARY: trace references unknown events")
        return self


class CorrelationEvidenceExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    evidence: Annotated[tuple[CorrelationEvidence, ...], Field(max_length=512)]


class SequenceFindingsExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    findings: Annotated[tuple[SequenceFinding, ...], Field(max_length=512)]
