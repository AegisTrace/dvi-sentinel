"""Concrete local-harness request, result, and rule contracts."""

from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr, model_validator

from dvi_sentinel.models import DetectionEvent, Identifier, NonEmpty, TelemetryEvent, ValueModel


class HarnessRequest(ValueModel):
    case_id: Identifier
    events: Annotated[tuple[TelemetryEvent, ...], Field(max_length=10_000)]
    capability: str = "local_fixture"


class HarnessIssue(ValueModel):
    code: Literal[
        "DVI-HARNESS-UNSUPPORTED",
        "DVI-HARNESS-NO-FIXTURE",
        "DVI-HARNESS-POLICY",
        "DVI-HARNESS-MALFORMED",
        "DVI-HARNESS-DUPLICATE-ID",
    ]
    explanation: NonEmpty


class RuleTrace(ValueModel):
    rule_id: Identifier
    candidate_count: int
    reason: Literal[
        "RULE_MATCH",
        "RULE_CONDITION_MISS",
        "RULE_COUNT_MISS",
        "RULE_ORDER_MISS",
        "RULE_WINDOW_MISS",
    ]


class HarnessResult(ValueModel):
    case_id: Identifier
    status: Literal["complete", "unknown"]
    detections: tuple[DetectionEvent, ...] = ()
    issues: tuple[HarnessIssue, ...] = ()
    traces: tuple[RuleTrace, ...] = ()


class FixtureCase(ValueModel):
    case_id: Identifier
    detections: tuple[DetectionEvent, ...]

    @model_validator(mode="after")
    def unique_detections(self) -> "FixtureCase":
        if len({d.event_id for d in self.detections}) != len(self.detections):
            raise ValueError("duplicate detection IDs in fixture case")
        return self


class FixtureResults(ValueModel):
    schema_version: Literal["1"] = "1"
    cases: Annotated[tuple[FixtureCase, ...], Field(max_length=1000)]

    @model_validator(mode="after")
    def unique_cases(self) -> "FixtureResults":
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("duplicate fixture case IDs")
        return self


class RuleCondition(ValueModel):
    field: NonEmpty
    operator: Literal["eq", "contains", "gte", "exists"]
    value: StrictStr | StrictInt | StrictFloat | StrictBool | None = None

    @model_validator(mode="after")
    def supported_field(self) -> "RuleCondition":
        fields = {
            "category",
            "action",
            "protocol",
            "severity",
            "sensor",
            "vendor",
            "labels",
            "tags",
            "correlation_id",
            "timestamp_text",
        }
        parts = self.field.split(".")
        if self.field not in fields and not (
            parts[0] == "raw"
            and 2 <= len(parts) <= 6
            and all(part.isidentifier() for part in parts)
        ):
            raise ValueError("DVI-HARNESS-UNSUPPORTED: unsupported rule field")
        if self.operator == "exists" and self.value is not None:
            raise ValueError("exists does not accept a value")
        if self.operator != "exists" and self.value is None:
            raise ValueError("comparison requires a non-null value")
        if self.operator == "gte" and (
            isinstance(self.value, bool) or not isinstance(self.value, int | float)
        ):
            raise ValueError("gte requires a numeric value")
        return self


class LocalRule(ValueModel):
    id: Identifier
    detector: NonEmpty
    signature: NonEmpty
    title: NonEmpty
    conditions: Annotated[tuple[RuleCondition, ...], Field(min_length=1, max_length=16)]
    min_count: Annotated[StrictInt, Field(ge=1, le=10_000)] = 1
    max_count: Annotated[StrictInt, Field(ge=1, le=10_000)] | None = None
    max_total_events: Annotated[StrictInt, Field(ge=1, le=10_000)] | None = None
    require_time_order: StrictBool = False
    window_ms: Annotated[StrictInt, Field(ge=0, le=86_400_000)] | None = None
    delay_ms: Annotated[StrictInt, Field(ge=0, le=86_400_000)] = 0
    severity: Annotated[StrictInt, Field(ge=0, le=5)] = 4
    labels: tuple[NonEmpty, ...] = ()
    tags: tuple[NonEmpty, ...] = ()

    @model_validator(mode="after")
    def count_bounds(self) -> "LocalRule":
        if self.max_count is not None and self.max_count < self.min_count:
            raise ValueError("max_count must be at least min_count")
        return self


class FixtureHarnessConfig(ValueModel):
    kind: Literal["fixture"]
    path: NonEmpty


class RuleHarnessConfig(ValueModel):
    kind: Literal["rule_logic"]
    rules: Annotated[tuple[LocalRule, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def unique_rules(self) -> "RuleHarnessConfig":
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("duplicate rule IDs")
        return self
