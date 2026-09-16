"""Evidence-bound relations extending the ontology's immutable records."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from dvi_sentinel.models import Identifier, NonEmpty, ValueModel
from dvi_sentinel.ontology_models import (
    JsonSnapshot,
    OntologyExtraction,
    SemanticInvariant,
    SemanticTransform,
)
from dvi_sentinel.score_models import Ratio
from dvi_sentinel.serialization import canonical_json, digest, parse_json

# Roles reuse the full ontology context so bare signal hashes cannot hide missing evidence.
Signal = OntologyExtraction
Evidence = OntologyExtraction
Truth = Literal["true", "false", "unknown"]
Effect = Literal["supported", "not_supported", "unknown", "suppressed_false_positive"]
OracleDecision = Literal["pass", "fail", "unknown"]
AlgebraField = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[\w.:/-]+$")]
Operation = Literal[
    "preserves", "requires", "contradicts", "implies", "equivalent", "weakens", "explains"
]


class Invariant(SemanticInvariant):
    protected_fields: Annotated[tuple[AlgebraField, ...], Field(min_length=1, max_length=128)]
    reference: Signal

    @model_validator(mode="after")
    def unique_protected_fields(self) -> Self:
        if tuple(sorted(set(self.protected_fields))) != self.protected_fields:
            raise ValueError("DVI-ALGEBRA-INVARIANT: fields must be unique and sorted")
        identity = digest(
            {"reference": self.reference.stable_digest(), "fields": list(self.protected_fields)}
        )
        if self.invariant_id != f"invariant:{identity}":
            raise ValueError("DVI-ALGEBRA-INVARIANT: identity differs from its evidence contract")
        return self


class Transform(SemanticTransform):
    source: Signal
    destination: Signal

    @model_validator(mode="after")
    def verified_change(self) -> Self:
        if (self.source_digest, self.destination_digest) != (
            self.source.event_digest,
            self.destination.event_digest,
        ):
            raise ValueError("DVI-ALGEBRA-TRANSFORM: event references differ")
        before = self.source.signal.meaning().model_dump()
        after = self.destination.signal.meaning().model_dump()
        changed = tuple(sorted(name for name in before if before[name] != after[name]))
        identity = digest(
            {"source": self.source.stable_digest(), "destination": self.destination.stable_digest()}
        )
        if self.changed_fields != changed or self.transform_id != f"transform:{identity}":
            raise ValueError("DVI-ALGEBRA-TRANSFORM: change record differs from its evidence")
        return self


class Relation(ValueModel):
    operation: Operation
    subjects: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=3)]


class RelationCheck(ValueModel):
    field: AlgebraField
    truth: Truth
    expected_json: JsonSnapshot | None
    actual_json: JsonSnapshot | None
    reason_code: Identifier
    explanation: NonEmpty

    @model_validator(mode="after")
    def canonical_values(self) -> Self:
        for value in (self.expected_json, self.actual_json):
            if value is not None and canonical_json(parse_json(value)) != value:
                raise ValueError("DVI-ALGEBRA-VALUE: check values must use canonical JSON")
        return self


class OracleResult(ValueModel):
    """This evaluator's result; confidence is an evidence-support fraction, not probability."""

    oracle_id: Identifier
    subject_id: Identifier
    decision: OracleDecision
    confidence: Ratio
    confidence_basis: Literal["satisfied_required_evidence_fraction"] = (
        "satisfied_required_evidence_fraction"
    )
    reason_codes: tuple[Identifier, ...]
    evidence_refs: tuple[NonEmpty, ...]
    explanation: NonEmpty
    blocking: StrictBool


class AlgebraDecision(ValueModel):
    relation: Relation
    truth: Truth
    effect: Effect
    checks: Annotated[tuple[RelationCheck, ...], Field(max_length=128)]
    oracle: OracleResult
    confidence_before: Ratio | None = None
    confidence_after: Ratio | None = None

    @model_validator(mode="after")
    def consistent_decision(self) -> Self:
        expected = {"true": "pass", "false": "fail", "unknown": "unknown"}[self.truth]
        if self.oracle.decision != expected or self.oracle.subject_id != (
            "relation:" + self.relation.stable_digest()
        ):
            raise ValueError("DVI-ALGEBRA-DECISION: oracle and relation disagree")
        effect = (
            "unknown"
            if self.truth == "unknown"
            else (
                "not_supported"
                if self.truth == "false"
                else (
                    "suppressed_false_positive"
                    if self.relation.operation == "contradicts"
                    else "supported"
                )
            )
        )
        if self.effect != effect or self.oracle.blocking != (effect != "supported"):
            raise ValueError("DVI-ALGEBRA-DECISION: disposition contradicts the relation")
        if (self.confidence_before is not None or self.confidence_after is not None) != (
            self.relation.operation == "weakens"
        ):
            raise ValueError("DVI-ALGEBRA-CONFIDENCE: only weakening records a confidence change")
        if self.relation.operation == "weakens" and (
            self.confidence_before is None or self.confidence_after != self.oracle.confidence
        ):
            raise ValueError("DVI-ALGEBRA-CONFIDENCE: weakening needs both support fractions")
        return self


class SemanticPlan(ValueModel):
    schema_version: Literal["1"] = "1"
    transform: Transform
    invariant: Invariant
    decisions: Annotated[tuple[AlgebraDecision, ...], Field(min_length=6, max_length=262)]

    @model_validator(mode="after")
    def shared_reference(self) -> Self:
        if self.invariant.reference != self.transform.source:
            raise ValueError("DVI-ALGEBRA-PLAN: invariant and transform have different sources")
        return self
