"""The strict YAML-facing V1 scenario contract; parsing lives in policy.py."""

from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt, field_validator

from dvi_sentinel.harness_models import FixtureHarnessConfig, RuleHarnessConfig
from dvi_sentinel.models import Identifier, NonEmpty, Timestamp, ValueModel


class ScenarioMetadata(ValueModel):
    id: Identifier
    title: NonEmpty
    description: NonEmpty


class FixtureInput(ValueModel):
    path: NonEmpty
    format: Literal["jsonl", "csv", "suricata_eve"]
    provenance: Literal["synthetic", "documentation"]


class DetectionExpectation(ValueModel):
    detector: NonEmpty
    signature: NonEmpty | None = None
    title_contains: NonEmpty | None = None
    min_severity: Annotated[StrictInt, Field(ge=0, le=5)] = 0
    labels: tuple[NonEmpty, ...] = ()
    tags: tuple[NonEmpty, ...] = ()
    techniques: tuple[NonEmpty, ...] = ()
    event_ids: tuple[Identifier, ...] = ()
    correlation_id: Identifier | None = None
    reference_time: Timestamp | None = None
    max_delay_ms: Annotated[StrictInt, Field(ge=0, le=86_400_000)] = 60_000
    required_fields: tuple[
        Literal["signature", "title", "severity", "labels", "correlation_id", "related_event_ids"],
        ...,
    ] = ("signature",)


class VariationPolicy(ValueModel):
    families: tuple[
        Literal["timing", "ordering", "metadata", "noise", "volume", "dropout"], ...
    ] = ()
    max_variants: Annotated[StrictInt, Field(ge=1, le=1000)] = 32
    max_jitter_ms: Annotated[StrictInt, Field(ge=0, le=60_000)] = 0
    max_noise_events: Annotated[StrictInt, Field(ge=0, le=1000)] = 0
    max_duplicates: Annotated[StrictInt, Field(ge=0, le=100)] = 0
    order_independent: StrictBool = False
    optional_fields: tuple[
        Literal["sensor", "vendor", "labels", "tags", "correlation_id", "confidence"], ...
    ] = ()

    @field_validator("families", "optional_fields")
    @classmethod
    def no_duplicates(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate policy entries are not allowed")
        return value


class ScoringConfig(ValueModel):
    min_detection_rate: Annotated[StrictFloat, Field(ge=0, le=1)] = 1.0
    max_unknown_rate: Annotated[StrictFloat, Field(ge=0, le=1)] = 0.0


class ReportingConfig(ValueModel):
    title: NonEmpty = "DVI Sentinel resilience analysis"


class SafetyDeclaration(ValueModel):
    local_only: StrictBool
    synthetic_only: StrictBool
    no_execution: StrictBool

    @field_validator("local_only", "synthetic_only", "no_execution")
    @classmethod
    def must_attest(cls, value: bool) -> bool:
        if not value:
            raise ValueError("DVI-POL-003: all safety declarations must be true")
        return value


class Scenario(ValueModel):
    schema_version: Literal["1"] = "1"
    metadata: ScenarioMetadata
    inputs: Annotated[tuple[FixtureInput, ...], Field(min_length=1, max_length=16)]
    expected: DetectionExpectation
    harness: Annotated[FixtureHarnessConfig | RuleHarnessConfig, Field(discriminator="kind")]
    variations: VariationPolicy = Field(default_factory=VariationPolicy)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    safety: SafetyDeclaration
