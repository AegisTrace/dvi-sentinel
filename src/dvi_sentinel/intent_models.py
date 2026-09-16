"""Immutable, evidence-linked local intent declarations and analysis records."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.ontology_models import EvidenceBinding, FieldBinding, FieldPath, JsonSnapshot
from dvi_sentinel.serialization import canonical_json, parse_json

IntentFormat = Literal["dvi", "sigma_metadata", "v1_rule"]
IntentState = Literal["supported", "contradicted", "unknown"]
IntentLoss = Literal[
    "supported",
    "missing_required_field",
    "optional_evidence_absent",
    "unsupported_operator",
    "unsupported_condition_shape",
    "logsource_mismatch",
    "severity_mismatch",
    "field_alias_ambiguity",
    "normalization_loss",
    "correlation_key_missing",
    "time_window_unrepresentable",
    "metadata_context_dropped",
    "technique_tag_dropped",
    "value_mismatch",
]


class IntentOperator(ValueModel):
    name: Identifier = "exists"
    value_json: JsonSnapshot | None = None

    @model_validator(mode="after")
    def valid_value(self) -> Self:
        if (
            self.value_json is not None
            and canonical_json(parse_json(self.value_json)) != self.value_json
        ):
            raise ValueError("DVI-INTENT-VALUE: expected canonical JSON")
        if self.name == "exists" and self.value_json is not None:
            raise ValueError("DVI-INTENT-VALUE: exists takes no comparison value")
        if self.name in {"eq", "contains", "gte"} and self.value_json is None:
            raise ValueError("DVI-INTENT-VALUE: comparison value required")
        return self


class IntentFieldRequirement(ValueModel):
    field: Identifier
    paths: Annotated[tuple[FieldPath, ...], Field(min_length=1, max_length=8)]
    required: StrictBool = True
    operators: Annotated[tuple[IntentOperator, ...], Field(min_length=1, max_length=16)] = (
        IntentOperator(),
    )
    normalization: Literal["identity", "casefold"] = "identity"

    @model_validator(mode="after")
    def valid_binding(self) -> Self:
        self.binding()
        return self

    def binding(self) -> FieldBinding:
        return FieldBinding(
            field=self.field,
            paths=self.paths,
            required=self.required,
            normalization=self.normalization,
            affects_identity=False,
        )


class IntentLogsource(ValueModel):
    category: Identifier | None = None
    adapter: Identifier | None = None
    sensor: NonEmpty | None = None
    vendor: NonEmpty | None = None
    product: NonEmpty | None = None
    service: NonEmpty | None = None


class IntentCorrelation(ValueModel):
    field: Identifier
    same_value_required: StrictBool = True


class IntentTimeWindow(ValueModel):
    duration_ms: Annotated[StrictInt, Field(ge=0, le=86_400_000)]
    timestamp_field: Identifier
    precision_digits: Annotated[StrictInt, Field(ge=0, le=6)] = 3
    order_required: StrictBool = False


class IntentSeverityExpectation(ValueModel):
    minimum: Annotated[StrictInt, Field(ge=0, le=5)]
    maximum: Annotated[StrictInt, Field(ge=0, le=5)] = 5
    scope: Literal["input", "detection"] = "input"

    @model_validator(mode="after")
    def ordered_bounds(self) -> Self:
        if self.maximum < self.minimum:
            raise ValueError("DVI-INTENT-SEVERITY: maximum is below minimum")
        return self


class IntentEvidenceRequirement(ValueModel):
    path: NonEmpty
    required: StrictBool = True
    explanation: NonEmpty


class IntentAssumption(ValueModel):
    assumption_id: Identifier
    explanation: NonEmpty
    evidence_refs: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()
    requires_evaluation: StrictBool = True
    detail_json: JsonSnapshot | None = None

    @model_validator(mode="after")
    def valid_detail(self) -> Self:
        if (
            self.detail_json is not None
            and canonical_json(parse_json(self.detail_json)) != self.detail_json
        ):
            raise ValueError("DVI-INTENT-VALUE: assumption details require canonical JSON")
        return self


class DetectionIntent(ValueModel):
    schema_version: Literal["1"] = "1"
    intent_id: Identifier
    title: NonEmpty
    fields: Annotated[tuple[IntentFieldRequirement, ...], Field(max_length=32)]
    condition_shape: NonEmpty = "all"
    logsource: IntentLogsource = IntentLogsource()
    correlation: IntentCorrelation | None = None
    time_window: IntentTimeWindow | None = None
    severity: IntentSeverityExpectation | None = None
    evidence: Annotated[tuple[IntentEvidenceRequirement, ...], Field(max_length=32)] = ()
    context_labels: Annotated[tuple[NonEmpty, ...], Field(max_length=32)] = ()
    context_tags: Annotated[tuple[NonEmpty, ...], Field(max_length=32)] = ()
    technique_tags: Annotated[tuple[NonEmpty, ...], Field(max_length=32)] = ()
    metadata_scope: Literal["input", "detection"] = "input"
    assumptions: Annotated[tuple[IntentAssumption, ...], Field(max_length=32)] = ()

    @model_validator(mode="after")
    def linked_requirements(self) -> Self:
        fields = {field.field: field for field in self.fields}
        if (
            len(fields) != len(self.fields)
            or sum(len(f.operators) for f in self.fields) > 64
            or len({item.assumption_id for item in self.assumptions}) != len(self.assumptions)
        ):
            raise ValueError("DVI-INTENT-BOUNDS: unique fields and at most 64 operators required")
        references = [self.correlation.field] if self.correlation else []
        if self.time_window:
            references.append(self.time_window.timestamp_field)
        if any(name not in fields or not fields[name].required for name in references):
            raise ValueError("DVI-INTENT-REFERENCE: correlation/time must name a required field")
        if self.time_window and not any(
            path in {"timestamp", "observed_at"}
            for path in fields[self.time_window.timestamp_field].paths
        ):
            raise ValueError("DVI-INTENT-TIME: timestamp_field must bind timestamp or observed_at")
        return self


class IntentCheck(ValueModel):
    field: NonEmpty
    code: IntentLoss
    outcome: Literal["supported", "contradicted", "unknown", "optional_absent"]
    expected_json: JsonSnapshot | None = None
    observed_json: JsonSnapshot | None = None
    explanation: NonEmpty

    @model_validator(mode="after")
    def consistent_values(self) -> Self:
        if (self.code == "supported") != (self.outcome == "supported"):
            raise ValueError("DVI-INTENT-CHECK: supported code/outcome disagree")
        for value in (self.expected_json, self.observed_json):
            if value is not None and canonical_json(parse_json(value)) != value:
                raise ValueError("DVI-INTENT-VALUE: check snapshots require canonical JSON")
        return self


class ParsedIntent(ValueModel):
    source_format: IntentFormat
    source_digest: Sha256
    intent: DetectionIntent
    unsupported: Annotated[tuple[IntentCheck, ...], Field(max_length=128)] = ()

    @model_validator(mode="after")
    def unresolved_diagnostics(self) -> Self:
        if any(item.outcome != "unknown" for item in self.unsupported):
            raise ValueError("DVI-INTENT-PARSE: unsupported diagnostics must remain unknown")
        return self


def checks_state(checks: tuple[IntentCheck, ...]) -> IntentState:
    if any(item.outcome == "unknown" for item in checks):
        return "unknown"
    if any(item.outcome == "contradicted" for item in checks):
        return "contradicted"
    return "supported" if any(item.outcome == "supported" for item in checks) else "unknown"


class IntentCandidate(ValueModel):
    event_id: Identifier
    event_digest: Sha256
    bindings: Annotated[tuple[EvidenceBinding, ...], Field(max_length=32)]
    checks: Annotated[tuple[IntentCheck, ...], Field(max_length=256)]
    state: IntentState

    @model_validator(mode="after")
    def consistent_evidence(self) -> Self:
        if self.state != checks_state(self.checks):
            raise ValueError("DVI-INTENT-STATE: candidate state disagrees with checks")
        if any(
            (item.event_id, item.event_digest) != (self.event_id, self.event_digest)
            for item in self.bindings
        ):
            raise ValueError("DVI-INTENT-EVIDENCE: binding belongs to another event")
        return self


class IntentAnalysis(ValueModel):
    schema_version: Literal["1"] = "1"
    analysis_scope: Literal["single_event_evidence_support"] = "single_event_evidence_support"
    parsed: ParsedIntent
    candidates: Annotated[tuple[IntentCandidate, ...], Field(max_length=128)]
    global_checks: Annotated[tuple[IntentCheck, ...], Field(max_length=256)]
    state: IntentState

    @staticmethod
    def derive_state(
        candidates: tuple[IntentCandidate, ...], global_checks: tuple[IntentCheck, ...]
    ) -> IntentState:
        if any(item.outcome != "supported" for item in global_checks) or not candidates:
            return "unknown"
        if any(item.state == "supported" for item in candidates):
            return "supported"
        return "contradicted" if all(c.state == "contradicted" for c in candidates) else "unknown"

    @model_validator(mode="after")
    def consistent_state(self) -> Self:
        if self.state != self.derive_state(self.candidates, self.global_checks):
            raise ValueError("DVI-INTENT-STATE: analysis state disagrees with evidence")
        if len({item.event_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("DVI-INTENT-EVIDENCE: duplicate candidate identity")
        return self


class UnsupportedConditions(ValueModel):
    schema_version: Literal["1"] = "1"
    source_digest: Sha256
    checks: Annotated[tuple[IntentCheck, ...], Field(max_length=256)]


class IntentAssumptions(ValueModel):
    schema_version: Literal["1"] = "1"
    intent_id: Identifier
    assumptions: Annotated[tuple[IntentAssumption, ...], Field(max_length=32)]
