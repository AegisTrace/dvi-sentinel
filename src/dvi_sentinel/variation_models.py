"""Auditable variation plans, parameters, lineage, and invariant results."""

from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt

from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel

Family = Literal["baseline", "timing", "ordering", "metadata", "noise", "volume", "dropout"]


class VariationParameter(ValueModel):
    name: NonEmpty
    value: StrictInt | str | tuple[str, ...]


class VariationConstraint(ValueModel):
    name: NonEmpty
    minimum: StrictInt
    maximum: StrictInt


class VariationStrategy(ValueModel):
    id: Identifier
    family: Family
    allowed_changes: tuple[NonEmpty, ...]
    protected_invariants: tuple[NonEmpty, ...]
    constraints: tuple[VariationConstraint, ...] = ()
    safety_class: Literal["local_synthetic"] = "local_synthetic"


class EventLineage(ValueModel):
    event_id: Identifier
    original_event_id: Identifier | None
    role: Literal["original", "duplicate", "noise"]


class MetamorphicInvariant(ValueModel):
    id: Identifier
    passed: StrictBool
    explanation: NonEmpty


class SemanticPreservationResult(ValueModel):
    checks: tuple[MetamorphicInvariant, ...]

    @property
    def valid(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)


class VariationCase(ValueModel):
    id: Identifier
    family: Family
    parameters: tuple[VariationParameter, ...]
    events: tuple[TelemetryEvent, ...]
    lineage: tuple[EventLineage, ...]
    preservation: SemanticPreservationResult
    distance: Annotated[StrictFloat, Field(ge=0)]


class VariationPlan(ValueModel):
    schema_version: Literal["1"] = "1"
    tool_version: str
    scenario_id: Identifier
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    input_digest: Sha256
    config_digest: Sha256
    strategies: tuple[VariationStrategy, ...]
    cases: tuple[VariationCase, ...]
    attempted: StrictInt = 0
    skipped_noop: StrictInt = 0
    skipped_invalid: StrictInt = 0
    event_budget_exhausted: StrictBool = False
    event_budget: Annotated[StrictInt, Field(ge=1, le=50_000)] = 50_000
    omissions: tuple["CandidateOmission", ...] = ()

    @property
    def valid_cases(self) -> tuple[VariationCase, ...]:
        return tuple(case for case in self.cases if case.preservation.valid)


class CandidateOmission(ValueModel):
    attempt: StrictInt
    family: Family
    code: Literal["DVI-VAR-OVERFLOW", "DVI-VAR-FIELD-LIMIT", "DVI-VAR-EVENT-BUDGET"]
