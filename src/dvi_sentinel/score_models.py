"""Transparent numerator/denominator metrics and per-family observed boundaries."""

from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.models import Identifier, NonEmpty, ValueModel
from dvi_sentinel.variation_models import Family, SemanticPreservationResult

Count = Annotated[StrictInt, Field(ge=0)]


class Ratio(ValueModel):
    numerator: Count
    denominator: Count
    value: Annotated[float, Field(ge=0, le=1)] | None

    @model_validator(mode="after")
    def consistent(self) -> "Ratio":
        calculated = self.numerator / self.denominator if self.denominator else None
        if self.numerator > self.denominator or self.value != calculated:
            raise ValueError("ratio must exactly reflect its numerator and denominator")
        return self


class CaseAssessment(ValueModel):
    case_id: Identifier
    family: Family
    distance: Annotated[float, Field(ge=0)]
    preservation: SemanticPreservationResult
    parser_success: StrictBool | None
    match: MatchResult | None = None

    @model_validator(mode="after")
    def same_case(self) -> "CaseAssessment":
        if self.match and self.match.case_id != self.case_id:
            raise ValueError("match case ID must identify this assessment")
        return self


class VariantMetrics(ValueModel):
    total: Count
    tested: Count
    semantically_valid: Count
    invalid: Count
    detected: Count
    missed: Count
    unknown: Count
    detection_rate: Ratio
    miss_rate: Ratio
    unknown_rate: Ratio
    measured_detection_rate: Ratio
    invariant_pass_rate: Ratio
    semantic_preservation_rate: Ratio
    parser_success_rate: Ratio
    parser_unknown: Count
    evidence_completeness: Ratio
    evidence_cases: Count
    latency_samples: Count
    latency_p50_ms: float | None
    latency_p95_ms: float | None


class BoundaryCase(ValueModel):
    case_id: Identifier
    distance: Annotated[float, Field(ge=0)]


class FamilyFrontier(ValueModel):
    family: Family
    metrics: VariantMetrics
    minimal_miss_distance: float | None
    hardest_safe_detected: BoundaryCase | None
    easiest_safe_missed: BoundaryCase | None


FragilityClass = Literal[
    "schema",
    "timestamp_timezone",
    "ordering",
    "optional_field_dependency",
    "severity_normalization",
    "correlation_key_dependency",
    "noise_sensitivity",
    "volume_sensitivity",
    "adapter_disagreement",
]


class FragilityFinding(ValueModel):
    id: Identifier
    finding_class: FragilityClass
    source: Literal["variation", "probe", "differential"]
    case_id: Identifier
    evidence_paths: tuple[NonEmpty, ...]
    rationale: NonEmpty


class ResilienceFrontier(ValueModel):
    schema_version: Literal["1"] = "1"
    baseline: CaseAssessment | None
    metrics: VariantMetrics
    families: tuple[FamilyFrontier, ...]
    adapter_disagreement_rate: Ratio
    adapter_unknown: Count
    findings: tuple[FragilityFinding, ...]
