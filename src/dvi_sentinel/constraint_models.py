"""Finite exploration contracts (pure immutable data models)."""

from itertools import product
from math import prod
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import digest
from dvi_sentinel.variation_models import SemanticPreservationResult

Option = Literal[
    "none",
    "timestamp_precision",
    "timezone",
    "ordering",
    "schema_alias",
    "severity_normalization",
    "duplicates",
    "benign_noise",
    "bounded_volume",
    "drop:sensor",
    "drop:vendor",
    "drop:confidence",
    "drop:correlation_id",
    "drop:labels",
    "drop:tags",
    "name:sensor",
    "name:vendor",
]
Count = Annotated[StrictInt, Field(ge=0, le=50_000)]
Category = Literal["constraint", "permission", "invariant", "safety", "schema", "bounds"]
SkipReason = Literal["coverage_redundant", "case_budget", "event_budget"]


class Parameter(ValueModel):
    name: Identifier
    options: Annotated[tuple[Option, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len(set(self.options)) != len(self.options):
            raise ValueError("DVI-CONSTRAINT-SPACE: duplicate options")
        return self


class Binding(ValueModel):
    parameter: Identifier
    option: Option


Assignment = Annotated[tuple[Binding, ...], Field(min_length=1, max_length=6)]


class Constraint(ValueModel):
    """Forbid this conjunction of exact, inert parameter/option bindings."""

    id: Identifier
    forbidden: Assignment
    explanation: NonEmpty

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({term.parameter for term in self.forbidden}) != len(self.forbidden):
            raise ValueError("DVI-CONSTRAINT-TERMS: duplicate parameter in conjunction")
        return self


class ParameterSpace(ValueModel):
    parameters: Annotated[tuple[Parameter, ...], Field(min_length=2, max_length=6)]
    constraints: Annotated[tuple[Constraint, ...], Field(max_length=32)] = ()
    strength: Annotated[StrictInt, Field(ge=1, le=4)] = 2

    @model_validator(mode="after")
    def bounded(self) -> Self:
        names = {parameter.name: parameter.options for parameter in self.parameters}
        if len(names) != len(self.parameters):
            raise ValueError("DVI-CONSTRAINT-SPACE: duplicate parameter name")
        if self.strength > len(names) or prod(map(len, names.values())) > 512:
            raise ValueError("DVI-CONSTRAINT-BOUNDS: strength exceeds dimensions or >512 rows")
        active = [option for options in names.values() for option in options if option != "none"]
        if len(active) != len(set(active)):
            raise ValueError("DVI-CONSTRAINT-SPACE: each operation belongs to one dimension")
        if len({item.id for item in self.constraints}) != len(self.constraints):
            raise ValueError("DVI-CONSTRAINT-TERMS: duplicate constraint ID")
        for constraint in self.constraints:
            for term in constraint.forbidden:
                if term.parameter not in names or term.option not in names[term.parameter]:
                    raise ValueError("DVI-CONSTRAINT-TERMS: undeclared parameter/option")
        return self

    def assignments(self) -> tuple[tuple[Binding, ...], ...]:
        parameters = sorted(self.parameters, key=lambda item: item.name)
        return tuple(
            tuple(Binding(parameter=p.name, option=o) for p, o in zip(parameters, row, strict=True))
            for row in product(*(sorted(parameter.options) for parameter in parameters))
        )


class BudgetPolicy(ValueModel):
    max_cases: Annotated[StrictInt, Field(ge=0, le=128)] = 64
    max_events: Annotated[StrictInt, Field(ge=0, le=4096)] = 4096


class ConstraintDecision(ValueModel):
    constraint_id: Identifier
    passed: StrictBool
    category: Category
    reason_code: Identifier
    explanation: NonEmpty


class InvalidCombination(ValueModel):
    assignment: Assignment
    decisions: Annotated[tuple[ConstraintDecision, ...], Field(min_length=1, max_length=64)]


class SkippedCombination(ValueModel):
    assignment: Assignment
    reason: SkipReason
    explanation: NonEmpty


class ExplorationStep(ValueModel):
    operation: Option
    input_digest: Sha256
    output_digest: Sha256
    preservation: SemanticPreservationResult


class ExplorationCase(ValueModel):
    id: Identifier
    assignment: Assignment
    events: Annotated[tuple[TelemetryEvent, ...], Field(min_length=1, max_length=128)]
    steps: Annotated[tuple[ExplorationStep, ...], Field(max_length=6)]
    events_digest: Sha256

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.events_digest != digest([e.model_dump(mode="json") for e in self.events]):
            raise ValueError("DVI-EXPLORE-DIGEST: candidate content changed")
        if len({e.event_id for e in self.events}) != len(self.events):
            raise ValueError("DVI-EXPLORE-IDENTITY: duplicate candidate event IDs")
        if any(not step.preservation.valid for step in self.steps):
            raise ValueError("DVI-EXPLORE-TRACE: rejected transformation in selected case")
        if self.steps and (
            self.steps[-1].output_digest != self.events_digest
            or any(
                a.output_digest != b.input_digest
                for a, b in zip(self.steps, self.steps[1:], strict=False)
            )
        ):
            raise ValueError("DVI-EXPLORE-TRACE: transformation chain is disconnected")
        return self


class EligibleCombination(ValueModel):
    assignment: Assignment
    event_count: Annotated[StrictInt, Field(ge=1, le=128)]
    events_digest: Sha256


class CoveringArray(ValueModel):
    strength: Annotated[StrictInt, Field(ge=1, le=4)]
    rows: Annotated[tuple[Assignment, ...], Field(max_length=128)]
    theoretical_interactions: Count
    feasible_interactions: Count
    covered_interactions: Count
    infeasible_interactions: Annotated[tuple[Assignment, ...], Field(max_length=8192)]
    uncovered_interactions: Annotated[tuple[Assignment, ...], Field(max_length=8192)]
    state: Literal["complete", "partial", "infeasible"]
    events_selected: Count

    @model_validator(mode="after")
    def coherent(self) -> Self:
        state = (
            "infeasible"
            if not self.feasible_interactions
            else "partial"
            if self.uncovered_interactions
            else "complete"
        )
        if (
            self.state != state
            or self.covered_interactions + len(self.uncovered_interactions)
            != self.feasible_interactions
            or self.feasible_interactions + len(self.infeasible_interactions)
            != self.theoretical_interactions
            or len(set(self.rows)) != len(self.rows)
            or len(set(self.uncovered_interactions)) != len(self.uncovered_interactions)
            or len(set(self.infeasible_interactions)) != len(self.infeasible_interactions)
        ):
            raise ValueError("DVI-EXPLORE-COVERAGE: inconsistent interaction accounting")
        return self


class ExplorationPlan(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    input_events: Annotated[tuple[TelemetryEvent, ...], Field(min_length=1, max_length=32)]
    config_digest: Sha256
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    space: ParameterSpace
    policy: VariationPolicy
    budget: BudgetPolicy
    cases: Annotated[tuple[ExplorationCase, ...], Field(max_length=128)]
    invalid: Annotated[tuple[InvalidCombination, ...], Field(max_length=512)]
    skipped: Annotated[tuple[SkippedCombination, ...], Field(max_length=512)]
    covering: CoveringArray

    @model_validator(mode="after")
    def linked(self) -> Self:
        expected = digest(
            {
                "space": self.space.model_dump(mode="json"),
                "policy": self.policy.model_dump(mode="json"),
                "budget": self.budget.model_dump(mode="json"),
                "seed": self.seed,
            }
        )
        if (
            self.input_digest != digest([e.model_dump(mode="json") for e in self.input_events])
            or self.config_digest != expected
        ):
            raise ValueError("DVI-EXPLORE-DIGEST: input or configuration changed")
        accounted = (
            *[case.assignment for case in self.cases],
            *[row.assignment for row in self.invalid],
            *[row.assignment for row in self.skipped],
        )
        if len(set(accounted)) != len(accounted) or set(accounted) != set(self.space.assignments()):
            raise ValueError("DVI-EXPLORE-ACCOUNTING: every combination must be accounted once")
        if (
            tuple(case.assignment for case in self.cases) != self.covering.rows
            or sum(len(case.events) for case in self.cases) != self.covering.events_selected
            or len(self.cases) > self.budget.max_cases
            or self.covering.events_selected > self.budget.max_events
            or any(decision.passed for row in self.invalid for decision in row.decisions)
        ):
            raise ValueError(
                "DVI-EXPLORE-ACCOUNTING: selected rows, budgets or rejections disagree"
            )
        for case in self.cases:
            start = case.steps[0].input_digest if case.steps else case.events_digest
            if start != self.input_digest:
                raise ValueError("DVI-EXPLORE-TRACE: selected trace belongs to another input")
        return self


class ExplorationManifest(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    config_digest: Sha256
    seed: StrictInt
    attempted: Count
    selected: Count
    rejected: Count
    skipped: Count
    state: Literal["complete", "partial", "infeasible"]
    artifact_digests: dict[str, Sha256]


class InvalidCombinations(ValueModel):
    input_digest: Sha256
    invalid: Annotated[tuple[InvalidCombination, ...], Field(max_length=512)]
    skipped: Annotated[tuple[SkippedCombination, ...], Field(max_length=512)]
