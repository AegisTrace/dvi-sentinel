"""Per-representation normalized evidence and typed disagreement findings."""

from typing import Annotated, Literal

from pydantic import Field, JsonValue

from dvi_sentinel.adapters import NormalizationResult
from dvi_sentinel.fixture_encoding import Representation
from dvi_sentinel.harness_models import HarnessResult
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel

DifferenceClass = Literal[
    "adapter_disagreement",
    "schema_fragility",
    "field_mapping_loss",
    "timestamp_precision_drift",
    "severity_normalization_drift",
    "optional_field_loss",
    "correlation_key_loss",
]


class FixtureRepresentation(ValueModel):
    representation: Representation
    content: Annotated[str, Field(max_length=2_097_152)]


class SchemaDifference(ValueModel):
    finding_class: DifferenceClass
    event_id: Identifier | None = None
    path: NonEmpty
    expected: JsonValue
    observed: JsonValue
    explanation: NonEmpty


class DifferentialCase(ValueModel):
    id: Identifier
    representation: Representation
    status: Literal["agree", "disagree", "unknown"]
    reason: NonEmpty
    source: FixtureRepresentation | None = None
    normalized: NormalizationResult | None = None
    observation: HarnessResult | None = None
    differences: tuple[SchemaDifference, ...] = ()
    evidence_paths: tuple[NonEmpty, ...] = ()


class DifferentialReport(ValueModel):
    schema_version: Literal["1"] = "1"
    tool_version: str
    input_digest: Sha256
    events: tuple[TelemetryEvent, ...]
    baseline: HarnessResult
    cases: tuple[DifferentialCase, ...]
