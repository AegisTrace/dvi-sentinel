"""Inspectable matching evidence; completeness is availability, not confidence."""

from typing import Annotated, Literal

from pydantic import Field, JsonValue

from dvi_sentinel.models import Identifier, NonEmpty, ValueModel

MatchStatus = Literal["detected", "missed", "unknown"]
MatchReason = Literal[
    "DVI-MATCH-DETECTED",
    "DVI-MATCH-NO-CANDIDATE",
    "DVI-MATCH-LATE",
    "DVI-MATCH-EARLY",
    "DVI-MATCH-MISSING-FIELD",
    "DVI-MATCH-SEVERITY",
    "DVI-MATCH-LABEL",
    "DVI-MATCH-TAG",
    "DVI-MATCH-TECHNIQUE",
    "DVI-MATCH-SIGNATURE",
    "DVI-MATCH-TITLE",
    "DVI-MATCH-SOURCE",
    "DVI-MATCH-EVENT-ID",
    "DVI-MATCH-CORRELATION",
    "DVI-MATCH-NORMALIZATION",
    "DVI-MATCH-AMBIGUOUS-EXPECTATION",
    "DVI-MATCH-AMBIGUOUS-OBSERVATION",
    "DVI-MATCH-TIME-REFERENCE",
    "DVI-MATCH-HARNESS",
    "DVI-MATCH-INVARIANT",
]


class MatchComparison(ValueModel):
    field: NonEmpty
    expected: JsonValue
    observed: JsonValue
    outcome: Literal["pass", "missing", "contradiction", "unknown"]
    reason: MatchReason


class CandidateMatch(ValueModel):
    event_id: Identifier
    status: MatchStatus
    reason: MatchReason
    alert_delay_ms: float | None = None
    comparisons: tuple[MatchComparison, ...]
    missing_evidence: tuple[NonEmpty, ...]
    contradictory_evidence: tuple[NonEmpty, ...]
    evidence_completeness: Annotated[float, Field(ge=0, le=1)]


class MatchResult(ValueModel):
    schema_version: Literal["1"] = "1"
    case_id: Identifier
    status: MatchStatus
    reason: MatchReason
    explanation: NonEmpty
    matching_event_ids: tuple[Identifier, ...] = ()
    alert_delay_ms: float | None = None
    candidates: tuple[CandidateMatch, ...] = ()
    missing_evidence: tuple[NonEmpty, ...] = ()
    contradictory_evidence: tuple[NonEmpty, ...] = ()
    evidence_completeness: Annotated[float, Field(ge=0, le=1)] = 0.0
