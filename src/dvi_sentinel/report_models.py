"""Inspectable report data and direct evidence references, without graph machinery."""

from typing import Annotated, Any, Literal

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from dvi_sentinel.artifact_models import ArtifactEntry, RunRecord, portable_path
from dvi_sentinel.comparison_models import ComparisonResult
from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.lineage_models import LineageSummary
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.score_models import CaseAssessment, ResilienceFrontier
from dvi_sentinel.shrinking_models import MinimalCounterexample


class EvidenceReference(ValueModel):
    artifact: NonEmpty
    sha256: Sha256
    line: Annotated[int, Field(ge=1)] | None = None
    pointer: str = ""
    _path = field_validator("artifact")(portable_path)


class EventProvenance(ValueModel):
    event_id: Identifier
    record_digest: Sha256
    raw_digest: Sha256
    reference: EvidenceReference


class FindingProvenance(ValueModel):
    finding_id: Identifier
    scenario_id: Identifier
    scenario_digest: Sha256
    fixture_artifacts: tuple[NonEmpty, ...]
    event_ids: tuple[Identifier, ...]
    references: tuple[EvidenceReference, ...]


class ProvenanceReport(ValueModel):
    schema_version: Literal["1"] = "1"
    run_id: Identifier
    evidence_digest: Sha256
    artifacts: tuple[ArtifactEntry, ...]
    events: tuple[EventProvenance, ...]
    findings: tuple[FindingProvenance, ...]


class ReportDocument(ValueModel):
    schema_version: Literal["1", "2"] = "1"
    run: RunRecord
    frontier: ResilienceFrontier
    cases: tuple[CaseAssessment, ...]
    probes: tuple[AssumptionProbe, ...]
    differential: DifferentialReport | None
    minimal: MinimalCounterexample | None
    regression: ComparisonResult | None
    provenance: ProvenanceReport
    limitations: tuple[NonEmpty, ...]
    lineage: LineageSummary | None = None

    @model_serializer(mode="wrap")
    def serialize_version(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        values: dict[str, Any] = handler(self)
        if self.schema_version == "1":
            values.pop("lineage", None)
        return values

    @model_validator(mode="after")
    def lineage_version(self) -> "ReportDocument":
        if (self.schema_version == "2") != (self.lineage is not None):
            raise ValueError("schema-2 reports require a provenance DAG summary")
        return self
