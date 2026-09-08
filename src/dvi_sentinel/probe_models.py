"""Explicit, reproducible counterfactual observations, without statistical scores."""

from typing import Literal

from dvi_sentinel.harness_models import HarnessResult
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.variation_models import EventLineage, SemanticPreservationResult

ProbeClass = Literal[
    "timestamp_precision",
    "timezone",
    "ordering",
    "optional_field",
    "schema_alias",
    "severity_normalization",
    "sensor_vendor",
    "correlation",
    "labels_tags",
    "duplicates",
    "benign_noise",
    "bounded_volume",
]


class ProbeSpec(ValueModel):
    name: Identifier
    finding_class: ProbeClass
    hypothesis: NonEmpty
    transformation: NonEmpty
    invariant: NonEmpty


class AssumptionProbe(ValueModel):
    schema_version: Literal["1"] = "1"
    id: Identifier
    spec: ProbeSpec
    input_digest: Sha256
    config_digest: Sha256
    observed_result: Literal["fragile", "robust", "unknown", "not_applicable", "invalid"]
    reason: NonEmpty
    confidence_rationale: NonEmpty
    evidence_paths: tuple[NonEmpty, ...]
    baseline: HarnessResult
    candidate: HarnessResult | None = None
    events: tuple[TelemetryEvent, ...] = ()
    lineage: tuple[EventLineage, ...] = ()
    preservation: SemanticPreservationResult | None = None
    missing_identities: tuple[tuple[str, str], ...] = ()
