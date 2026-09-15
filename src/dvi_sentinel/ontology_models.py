"""Immutable semantic projections, explicit evidence contracts and loss records (D)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictFloat, StrictInt, model_validator

from dvi_sentinel.models import EntityRef, Identifier, NetworkEndpoint, NonEmpty, Sha256, ValueModel
from dvi_sentinel.serialization import canonical_json, digest, parse_json

Category = Literal["flow", "dns", "http", "alert"]
EvidenceState = Literal["known", "missing", "ambiguous", "unknown"]
LossClass = Literal[
    "missing_required_evidence",
    "ambiguous_field_binding",
    "lossy_normalization",
    "unsupported_semantic_category",
    "inconsistent_entity_role",
    "timestamp_precision_loss",
    "correlation_key_loss",
    "severity_semantic_loss",
    "unknown_mapping",
    "insufficient_confidence",
]
Confidence = Annotated[StrictFloat, Field(ge=0, le=1)]
FieldPath = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z_][\w.]*$")]
JsonSnapshot = Annotated[str, Field(max_length=65_536)]


class Observable(ValueModel):
    field: Identifier
    state: EvidenceState
    value_json: JsonSnapshot | None = None

    @model_validator(mode="after")
    def canonical_value(self) -> Self:
        if (self.state == "known") != (self.value_json is not None):
            raise ValueError("DVI-ONTOLOGY-VALUE: only known evidence has a resolved value")
        if self.value_json is not None:
            value = parse_json(self.value_json)
            if value is None or value == "" or value == [] or value == {}:
                raise ValueError("DVI-ONTOLOGY-VALUE: empty values must remain missing")
            if canonical_json(value) != self.value_json:
                raise ValueError("DVI-ONTOLOGY-VALUE: value must be canonical JSON")
        return self


class FieldBinding(ValueModel):
    """A finite inert selector; multiple paths are aliases, never first-match precedence."""

    field: Identifier
    paths: Annotated[tuple[FieldPath, ...], Field(min_length=1, max_length=8)]
    required: StrictBool = True
    affects_identity: StrictBool = True
    categories: tuple[Category, ...] = ("flow", "dns", "http", "alert")
    normalization: Literal["identity", "casefold"] = "identity"
    entity_role: Literal["source", "destination"] | None = None

    @model_validator(mode="after")
    def finite_paths(self) -> Self:
        if len(set(self.paths)) != len(self.paths) or any(
            len(path.split(".")) > 8 or ".." in path or path.endswith(".") for path in self.paths
        ):
            raise ValueError("DVI-ONTOLOGY-PATH: unique paths of at most eight segments required")
        if not self.categories or len(set(self.categories)) != len(self.categories):
            raise ValueError("DVI-ONTOLOGY-CATEGORY: unique nonempty binding categories required")
        return self

    def resolve(self, candidates: tuple[Observable, ...]) -> Observable:
        """Resolve recorded aliases; conflicting values remain ambiguous before normalization."""
        values = {item.value_json for item in candidates if item.state == "known"}
        if any(item.state != "known" and item.state != "missing" for item in candidates):
            return Observable(field=self.field, state="unknown")
        if len(values) > 1:
            return Observable(field=self.field, state="ambiguous")
        if not values:
            return Observable(field=self.field, state="missing")
        value = next(iter(values))
        if self.normalization == "casefold" and value is not None:
            original = parse_json(value)
            if not isinstance(original, str):
                return Observable(field=self.field, state="unknown")
            value = canonical_json(original.casefold())
        return Observable(field=self.field, state="known", value_json=value)


class EvidenceBinding(ValueModel):
    event_id: Identifier
    event_digest: Sha256
    raw_digest: Sha256
    specification: FieldBinding
    observable: Observable
    candidates: tuple[Observable, ...]

    @model_validator(mode="after")
    def matching_field(self) -> Self:
        if self.specification.field != self.observable.field or tuple(
            item.field for item in self.candidates
        ) != tuple(sorted(self.specification.paths)):
            raise ValueError(
                "DVI-ONTOLOGY-BINDING: field and candidate paths must match the contract"
            )
        if self.observable != self.specification.resolve(self.candidates):
            raise ValueError(
                "DVI-ONTOLOGY-BINDING: resolved evidence differs from recorded aliases"
            )
        return self


class DetectionAssumption(ValueModel):
    assumption_id: Identifier
    requirement: NonEmpty
    decision: Literal["pass", "fail", "unknown"]
    evidence_fields: tuple[Identifier, ...]
    explanation: NonEmpty


class SemanticInvariant(ValueModel):
    invariant_id: Identifier
    protected_fields: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=128)]
    explanation: NonEmpty


class SemanticTransform(ValueModel):
    transform_id: Identifier
    source_digest: Sha256
    destination_digest: Sha256
    changed_fields: tuple[Identifier, ...]


class SemanticFinding(ValueModel):
    finding_id: Identifier
    event_id: Identifier
    loss_class: LossClass
    field: Identifier
    explanation: NonEmpty
    evidence_refs: tuple[Identifier, ...]
    blocking: StrictBool = True


class SemanticRecommendation(ValueModel):
    recommendation_id: Identifier
    finding_id: Identifier
    evidence_fields: tuple[Identifier, ...]
    action: NonEmpty


class OntologyProfile(ValueModel):
    schema_version: Literal["1"] = "1"
    profile_id: Identifier
    categories: Annotated[tuple[Category, ...], Field(min_length=1, max_length=4)]
    bindings: Annotated[tuple[FieldBinding, ...], Field(min_length=1, max_length=64)]
    time_role: Literal["event_time", "observation_time"] = "event_time"
    timestamp_precision_digits: Annotated[StrictInt, Field(ge=0, le=6)] = 0
    confidence_requirement: Confidence | None = None
    correlation_requirement: Literal["optional", "required"] = "optional"

    @model_validator(mode="after")
    def unique_fields(self) -> Self:
        if len({binding.field for binding in self.bindings}) != len(self.bindings):
            raise ValueError("DVI-ONTOLOGY-PROFILE: evidence field names must be unique")
        if len(set(self.categories)) != len(self.categories):
            raise ValueError("DVI-ONTOLOGY-PROFILE: categories must be unique")
        return self


class EndpointRelation(ValueModel):
    direction: Literal["source_to_destination", "incomplete"]
    source: NetworkEndpoint | None
    destination: NetworkEndpoint | None

    @model_validator(mode="after")
    def consistent_direction(self) -> Self:
        complete = self.source is not None and self.destination is not None
        if complete != (self.direction == "source_to_destination"):
            raise ValueError("DVI-ONTOLOGY-ROLE: endpoint direction contradicts endpoint presence")
        return self


class SignalMeaning(ValueModel):
    """No event IDs, raw hashes, adapter names, profile labels or absolute times by default."""

    category: Category
    action: NonEmpty
    outcome: Literal["success", "failure", "unknown"]
    entities: tuple[EntityRef, ...]
    source_destination_relation: EndpointRelation
    protocol: Literal["tcp", "udp", "icmp", "other"] | None
    resource: tuple[Observable, ...]
    time_role: Literal["event_time", "observation_time"]
    timestamp_precision_digits: Annotated[StrictInt, Field(ge=0, le=6)]
    evidence_requirements: tuple[Identifier, ...]
    confidence_requirement: Confidence | None
    correlation_requirement: Literal["optional", "required"]
    evidence: tuple[Observable, ...]


class SemanticSignal(SignalMeaning):
    signal_id: Identifier
    semantic_digest: Sha256

    @classmethod
    def from_meaning(cls, meaning: SignalMeaning) -> Self:
        identity = meaning.stable_digest()
        return cls.model_validate(
            meaning.model_dump() | {"signal_id": f"signal:{identity}", "semantic_digest": identity}
        )

    def meaning(self) -> SignalMeaning:
        return SignalMeaning.model_validate(
            self.model_dump(exclude={"signal_id", "semantic_digest"})
        )

    @model_validator(mode="after")
    def verify_identity(self) -> Self:
        identity = self.meaning().stable_digest()
        if self.semantic_digest != identity or self.signal_id != f"signal:{identity}":
            raise ValueError("DVI-ONTOLOGY-IDENTITY: signal digest does not match its meaning")
        return self


class OntologyExtraction(ValueModel):
    schema_version: Literal["1"] = "1"
    event_id: Identifier
    event_digest: Sha256
    raw_digest: Sha256
    profile_digest: Sha256
    state: Literal["known", "unknown", "ambiguous"]
    signal: SemanticSignal
    bindings: tuple[EvidenceBinding, ...]
    assumptions: tuple[DetectionAssumption, ...]
    findings: tuple[SemanticFinding, ...]
    recommendations: tuple[SemanticRecommendation, ...]

    @model_validator(mode="after")
    def evidence_integrity(self) -> Self:
        ambiguous = any(item.observable.state == "ambiguous" for item in self.bindings)
        expected = "ambiguous" if ambiguous else "unknown" if self.findings else "known"
        if self.state != expected:
            raise ValueError("DVI-ONTOLOGY-STATE: unresolved evidence cannot become known")
        if any(
            (item.event_id, item.event_digest, item.raw_digest)
            != (self.event_id, self.event_digest, self.raw_digest)
            for item in self.bindings
        ):
            raise ValueError("DVI-ONTOLOGY-PROVENANCE: bindings belong to another event")
        if len({item.specification.field for item in self.bindings}) != len(self.bindings):
            raise ValueError("DVI-ONTOLOGY-BINDING: duplicate field binding")
        for item in self.bindings:
            unresolved = item.observable.state in {"unknown", "ambiguous"} or (
                item.observable.state == "missing" and item.specification.required
            )
            lossy = item.specification.normalization == "casefold" and any(
                candidate.state == "known" and candidate.value_json != item.observable.value_json
                for candidate in item.candidates
            )
            if (unresolved or lossy) and not any(
                f.field == item.specification.field for f in self.findings
            ):
                raise ValueError("DVI-ONTOLOGY-STATE: unresolved binding needs a loss finding")
        projected = tuple(
            item.observable for item in self.bindings if item.specification.affects_identity
        )
        if projected != self.signal.evidence:
            raise ValueError("DVI-ONTOLOGY-BINDING: signal evidence differs from its bindings")
        if any(item.event_id != self.event_id for item in self.findings):
            raise ValueError("DVI-ONTOLOGY-PROVENANCE: findings belong to another event")
        if {item.finding_id for item in self.recommendations} != {
            item.finding_id for item in self.findings
        }:
            raise ValueError("DVI-ONTOLOGY-RECOMMENDATION: recommendations must link to findings")
        return self


class SemanticEquivalence(ValueModel):
    decision: Literal["equivalent", "different", "unknown"]
    explanation: NonEmpty
    transform: SemanticTransform
    invariant: SemanticInvariant


class OntologyExport(ValueModel):
    schema_version: Literal["1"] = "1"
    profile: OntologyProfile
    input_digest: Sha256
    extractions: Annotated[tuple[OntologyExtraction, ...], Field(min_length=1, max_length=1000)]

    @model_validator(mode="after")
    def profile_integrity(self) -> Self:
        if any(item.profile_digest != self.profile.stable_digest() for item in self.extractions):
            raise ValueError("DVI-ONTOLOGY-PROFILE: export mixes different profiles")
        if len({item.event_id for item in self.extractions}) != len(self.extractions):
            raise ValueError("DVI-ONTOLOGY-INPUT: duplicate event identity")
        expected = digest([item.event_digest for item in self.extractions])
        if self.input_digest != expected:
            raise ValueError("DVI-ONTOLOGY-INPUT: export input digest differs")
        return self


class BindingExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    profile_digest: Sha256
    bindings: tuple[EvidenceBinding, ...]


class LossExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    profile_digest: Sha256
    findings: tuple[SemanticFinding, ...]
    recommendations: tuple[SemanticRecommendation, ...]
