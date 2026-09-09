"""Declared comparison inputs, compatibility evidence, deltas, and gate decisions."""

from typing import Annotated, Literal

from pydantic import Field, StrictInt, model_validator

from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.score_models import CaseAssessment, FragilityClass, ResilienceFrontier


class ComparisonSnapshot(ValueModel):
    schema_version: NonEmpty = "1"
    tool_version: NonEmpty
    scenario_id: Identifier
    scenario_digest: Sha256
    input_digest: Sha256
    config_digest: Sha256
    detector_digest: Sha256
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    case_input_digests: dict[Identifier, Sha256]
    assessments: Annotated[tuple[CaseAssessment, ...], Field(max_length=1000)]
    probes: Annotated[tuple[AssumptionProbe, ...], Field(max_length=32)] = ()
    differential: DifferentialReport | None = None

    @model_validator(mode="after")
    def identified_cases(self) -> "ComparisonSnapshot":
        ids = [row.case_id for row in self.assessments]
        if len(set(ids)) != len(ids) or set(ids) != set(self.case_input_digests):
            raise ValueError("unique assessments and exactly corresponding input digests required")
        return self


class ComparisonThresholds(ValueModel):
    max_detection_rate_drop: Annotated[float, Field(ge=0, le=1)] = 0.0
    max_unknown_rate_increase: Annotated[float, Field(ge=0, le=1)] = 0.0
    max_semantic_preservation_drop: Annotated[float, Field(ge=0, le=1)] = 0.0
    max_adapter_disagreement_increase: Annotated[float, Field(ge=0, le=1)] = 0.0
    max_new_misses: Annotated[StrictInt, Field(ge=0)] = 0


class MetricDelta(ValueModel):
    metric: NonEmpty
    previous: float | None
    current: float | None
    delta: float | None


class FamilyDelta(ValueModel):
    family: NonEmpty
    metrics: tuple[MetricDelta, ...]


class ThresholdDecision(ValueModel):
    metric: NonEmpty
    deterioration: float | None
    allowed: float
    status: Literal["pass", "fail", "unknown"]


class ComparisonResult(ValueModel):
    schema_version: Literal["1"] = "1"
    status: Literal["passed", "regressed", "unknown", "incompatible"]
    exit_status: Literal[0, 1, 2]
    reasons: tuple[NonEmpty, ...]
    previous: ResilienceFrontier | None = None
    current: ResilienceFrontier | None = None
    metrics: tuple[MetricDelta, ...] = ()
    families: tuple[FamilyDelta, ...] = ()
    newly_missed: tuple[Identifier, ...] = ()
    recovered: tuple[Identifier, ...] = ()
    unchanged_misses: tuple[Identifier, ...] = ()
    new_fragility_classes: tuple[FragilityClass, ...] = ()
    removed_fragility_classes: tuple[FragilityClass, ...] = ()
    thresholds: tuple[ThresholdDecision, ...] = ()
