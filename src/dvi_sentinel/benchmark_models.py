"""Declared fixture benchmark oracles and reproducible measured evidence."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.score_models import CaseAssessment, FragilityClass, ResilienceFrontier
from dvi_sentinel.shrinking_models import MinimalCounterexample
from dvi_sentinel.variation_models import Family, VariationPlan

BenchmarkFamily = Literal[
    "schema_alias",
    "timestamp_precision",
    "timezone",
    "ordering",
    "optional_field",
    "severity_mapping",
    "correlation_key",
    "benign_noise",
    "volume",
    "adapter_disagreement",
]


class MetricRange(ValueModel):
    metric: Literal["detection_rate", "adapter_disagreement_rate"]
    minimum: Annotated[float, Field(ge=0, le=1)] | None
    maximum: Annotated[float, Field(ge=0, le=1)] | None

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if (self.minimum is None) != (self.maximum is None) or (
            self.minimum is not None and self.maximum is not None and self.minimum > self.maximum
        ):
            raise ValueError("metric bounds must both be null or ordered ratios")
        return self


class MinimalExpectation(ValueModel):
    event_count: Annotated[StrictInt, Field(ge=1, le=10000)]
    changed_originals: Annotated[StrictInt, Field(ge=0)]
    added_events: Annotated[StrictInt, Field(ge=0)]
    order_inversions: Annotated[StrictInt, Field(ge=0)] = 0


class BenchmarkCase(ValueModel):
    id: Identifier
    family: BenchmarkFamily
    description: NonEmpty
    scenario: NonEmpty
    control: StrictBool
    probe_name: Identifier | None = None
    shrink_family: Family | None = None
    comparison_fixture: NonEmpty | None = None
    target_status: Literal["robust", "fragile", "agree", "disagree"]
    reason_code: NonEmpty
    finding_classes: tuple[FragilityClass, ...]
    minimum: MinimalExpectation | None
    metrics: Annotated[tuple[MetricRange, ...], Field(min_length=1, max_length=2)]

    @model_validator(mode="after")
    def target(self) -> Self:
        if (self.probe_name is None) == (self.comparison_fixture is None):
            raise ValueError("benchmark requires exactly one probe or comparison fixture")
        if self.minimum is not None and (self.probe_name is None or self.shrink_family is None):
            raise ValueError("minimal reproducer expectation requires a shrinkable probe")
        return self


class BenchmarkSuite(ValueModel):
    schema_version: Literal["1"] = "1"
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)] = 42
    event_budget: Annotated[StrictInt, Field(ge=1, le=50000)] = 256
    cases: Annotated[tuple[BenchmarkCase, ...], Field(min_length=1, max_length=40)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("benchmark IDs must be unique")
        return self


class BenchmarkCheck(ValueModel):
    name: NonEmpty
    passed: StrictBool
    expected: NonEmpty
    observed: NonEmpty


class BenchmarkResult(ValueModel):
    case: BenchmarkCase
    source_digests: dict[str, Sha256]
    plan: VariationPlan
    assessments: tuple[CaseAssessment, ...]
    checks: tuple[BenchmarkCheck, ...]
    frontier: ResilienceFrontier
    probes: tuple[AssumptionProbe, ...] = ()
    differential: DifferentialReport | None = None
    minimum: MinimalCounterexample | None = None

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)


class BenchmarkReport(ValueModel):
    schema_version: Literal["1"] = "1"
    tool_version: str
    suite_digest: Sha256
    seed: StrictInt
    results: tuple[BenchmarkResult, ...]

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(result.passed for result in self.results)
