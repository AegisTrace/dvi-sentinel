"""Typed CLI request envelopes and evidence-linked results (D)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, model_validator

from dvi_sentinel.artifact_models import ArtifactEntry
from dvi_sentinel.constraint_models import BudgetPolicy, ParameterSpace
from dvi_sentinel.models import DetectionEvent, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.scenario import VariationPolicy

CommandName = Literal[
    "ontology",
    "map-schema",
    "analyze-rule",
    "temporal",
    "oracles",
    "explore",
    "explain",
    "confidence",
    "graph",
    "benchmark",
]
Seed = Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]


class EventInput(ValueModel):
    schema_version: Literal["1"] = "1"
    events: Annotated[
        tuple[DetectionEvent | TelemetryEvent, ...], Field(min_length=1, max_length=1000)
    ]

    @model_validator(mode="after")
    def safe_unique(self) -> Self:
        if len({e.event_id for e in self.events}) != len(self.events):
            raise ValueError("DVI-CLI-EVENTS: event IDs must be unique")
        rejected = evaluate_events(self.events)
        if rejected:
            raise PolicyError(rejected)
        return self


class TemporalInput(EventInput):
    window_ms: Annotated[StrictInt, Field(ge=0, le=86_400_000)] = 1000
    pattern: Annotated[tuple[NonEmpty, ...], Field(max_length=128)] = ()
    precision_digits: Annotated[StrictInt, Field(ge=0, le=6)] = 0


class ExplorationInput(EventInput):
    space: ParameterSpace
    policy: VariationPolicy
    budget: BudgetPolicy = BudgetPolicy()
    seed: Seed = 42


class InputPin(ValueModel):
    role: NonEmpty
    sha256: Sha256
    size_bytes: Annotated[StrictInt, Field(ge=0)]


class AnalysisResult[T: ValueModel](ValueModel):
    schema_version: Literal["1"] = "1"
    command: CommandName
    status: Literal["completed", "failed"] = "completed"
    exit_status: Literal[0, 1] = 0
    summary: NonEmpty
    sources: tuple[InputPin, ...]
    artifacts: tuple[ArtifactEntry, ...]
    result: T
