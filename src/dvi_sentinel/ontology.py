"""Pure, bounded ontology extraction and semantic comparison over safe V1 events (A)."""

import re
from typing import Literal

from pydantic import JsonValue

from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES
from dvi_sentinel.models import DetectionEvent, TelemetryEvent, utc_timestamp
from dvi_sentinel.ontology_models import (
    BindingExport,
    DetectionAssumption,
    EndpointRelation,
    EvidenceBinding,
    FieldBinding,
    LossClass,
    LossExport,
    Observable,
    OntologyExport,
    OntologyExtraction,
    OntologyProfile,
    SemanticEquivalence,
    SemanticFinding,
    SemanticInvariant,
    SemanticRecommendation,
    SemanticSignal,
    SemanticTransform,
    SignalMeaning,
)
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.serialization import canonical_json, digest

# Paths are inert dictionary selectors. No getattr/eval, wildcard, array traversal or I/O.
CANONICAL_PATHS = frozenset(
    {
        "event_id",
        "timestamp",
        "observed_at",
        "severity",
        "confidence",
        "labels",
        "tags",
        "correlation_id",
        "entities",
        "raw.adapter",
        "raw.sensor",
        "raw.vendor",
        "raw.original_timestamp",
        "raw.raw_digest",
        "raw.record_index",
        "detector",
        "signature",
        "title",
        "related_event_ids",
        "techniques",
        *(
            f"semantics.{field}"
            for field in (
                "category",
                "action",
                "outcome",
                "protocol",
                "source",
                "destination",
                "dns_name",
                "http_method",
                "http_path",
            )
        ),
        *(
            f"semantics.{role}.{field}"
            for role in ("source", "destination")
            for field in ("address", "port")
        ),
    }
)


def default_profile() -> OntologyProfile:
    """The DVI canonical subset, with required DNS/HTTP resources and alert severity."""
    return OntologyProfile(
        profile_id="dvi-canonical:1",
        categories=("flow", "dns", "http", "alert"),
        bindings=(
            FieldBinding(field="category", paths=("semantics.category",)),
            FieldBinding(field="action", paths=("semantics.action",)),
            FieldBinding(field="timestamp", paths=("timestamp",), affects_identity=False),
            FieldBinding(
                field="observed_at", paths=("observed_at",), required=False, affects_identity=False
            ),
            FieldBinding(
                field="source_time_text",
                paths=("raw.original_timestamp",),
                required=False,
                affects_identity=False,
            ),
            FieldBinding(
                field="confidence", paths=("confidence",), required=False, affects_identity=False
            ),
            FieldBinding(
                field="source", paths=("semantics.source",), required=False, entity_role="source"
            ),
            FieldBinding(
                field="destination",
                paths=("semantics.destination",),
                required=False,
                entity_role="destination",
            ),
            FieldBinding(field="protocol", paths=("semantics.protocol",), required=False),
            FieldBinding(field="dns_name", paths=("semantics.dns_name",), categories=("dns",)),
            FieldBinding(
                field="http_method", paths=("semantics.http_method",), categories=("http",)
            ),
            FieldBinding(field="http_path", paths=("semantics.http_path",), categories=("http",)),
            FieldBinding(field="severity", paths=("severity",), categories=("alert",)),
            FieldBinding(field="correlation_id", paths=("correlation_id",), required=False),
        ),
    )


def _observe(field: str, value: JsonValue, *, supported: bool = True) -> Observable:
    if not supported:
        return Observable(field=field, state="unknown")
    if value is None or value == "" or value == [] or value == {}:
        return Observable(field=field, state="missing")
    return Observable(field=field, state="known", value_json=canonical_json(value))


def _select(data: dict[str, JsonValue], path: str) -> Observable:
    supported = path in CANONICAL_PATHS or path.startswith("raw.payload.")
    value: JsonValue = data
    if supported:
        for part in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
    return _observe(path, value, supported=supported)


def _finding(
    event: TelemetryEvent, code: LossClass, field: str, explanation: str
) -> SemanticFinding:
    identity = digest({"event": event.stable_digest(), "code": code, "field": field})
    return SemanticFinding(
        finding_id=f"finding:{identity}",
        event_id=event.event_id,
        loss_class=code,
        field=field,
        explanation=explanation,
        evidence_refs=(field,),
    )


def _bind(
    event: TelemetryEvent,
    data: dict[str, JsonValue],
    spec: FieldBinding,
) -> tuple[EvidenceBinding, tuple[SemanticFinding, ...]]:
    candidates = tuple(_select(data, path) for path in sorted(spec.paths))
    observable = spec.resolve(candidates)
    findings = []
    if observable.state == "unknown":
        findings.append(
            _finding(
                event,
                "unknown_mapping",
                spec.field,
                "A selector or its requested normalization is unsupported for this evidence.",
            )
        )
    elif observable.state == "ambiguous":
        findings.append(
            _finding(
                event,
                "ambiguous_field_binding",
                spec.field,
                "Declared alias paths contain different values; no precedence was guessed.",
            )
        )
    elif (
        spec.normalization == "casefold"
        and observable.state == "known"
        and any(
            item.state == "known" and item.value_json != observable.value_json
            for item in candidates
        )
    ):
        findings.append(
            _finding(
                event,
                "lossy_normalization",
                spec.field,
                "Casefold discards distinctions; equivalence needs independent justification.",
            )
        )
    if observable.state == "missing" and spec.required:
        findings.append(
            _finding(
                event,
                "missing_required_evidence",
                spec.field,
                "No nonempty value satisfies the declared evidence requirement.",
            )
        )
    opposite = "destination" if spec.entity_role == "source" else "source"
    if spec.entity_role and any(
        path == f"semantics.{opposite}" or path.startswith(f"semantics.{opposite}.")
        for path in spec.paths
    ):
        findings.append(
            _finding(
                event,
                "inconsistent_entity_role",
                spec.field,
                "The declared entity role contradicts the canonical endpoint role.",
            )
        )
    binding = EvidenceBinding(
        event_id=event.event_id,
        event_digest=event.stable_digest(),
        raw_digest=event.raw.raw_digest,
        specification=spec,
        observable=observable,
        candidates=candidates,
    )
    return binding, tuple(findings)


def _profile_checks(event: TelemetryEvent, profile: OntologyProfile) -> tuple[SemanticFinding, ...]:
    findings = []
    if event.semantics.category not in profile.categories:
        findings.append(
            _finding(
                event,
                "unsupported_semantic_category",
                "category",
                "This canonical event category is outside the declared ontology profile.",
            )
        )
    if profile.correlation_requirement == "required" and event.correlation_id is None:
        findings.append(
            _finding(
                event,
                "correlation_key_loss",
                "correlation_id",
                "The profile requires a correlation key; none is present.",
            )
        )
    if profile.confidence_requirement is not None and (
        event.confidence is None or event.confidence < profile.confidence_requirement
    ):
        findings.append(
            _finding(
                event,
                "insufficient_confidence",
                "confidence",
                f"Source confidence {event.confidence!r} does not satisfy required minimum "
                f"{profile.confidence_requirement}. "
                "This is not a calibrated statistical estimate.",
            )
        )
    if profile.time_role == "observation_time" and event.observed_at is None:
        findings.append(
            _finding(
                event,
                "missing_required_evidence",
                "observed_at",
                "Observation time is required by the profile but absent.",
            )
        )
    if profile.timestamp_precision_digits:
        # V1 preserves original event time text, but has no source precision record for observed_at.
        source = event.raw.original_timestamp if profile.time_role == "event_time" else None
        match = re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,6}))?(?:Z|[+-]\d{2}:?\d{2})",
            source or "",
        )
        if match is not None:
            try:
                utc_timestamp(re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", source or ""))
            except ValueError:
                match = None
        if match is None:
            findings.append(
                _finding(
                    event,
                    "unknown_mapping",
                    "timestamp_precision",
                    "Source timestamp precision cannot be established from retained evidence.",
                )
            )
        elif len(match.group(1) or "") < profile.timestamp_precision_digits:
            findings.append(
                _finding(
                    event,
                    "timestamp_precision_loss",
                    "timestamp_precision",
                    "Source timestamp has fewer fractional digits than the required precision.",
                )
            )
    for warning in event.warnings:
        if warning.code not in {"DVI-ADAPTER-TIMEZONE", "DVI-ADAPTER-SEVERITY-MISSING"}:
            findings.append(
                _finding(
                    event,
                    "unknown_mapping",
                    "normalization_warning",
                    "An unrecognized normalization warning needs explicit interpretation.",
                )
            )
    return tuple(findings)


def extract_signal(
    event: TelemetryEvent, profile: OntologyProfile | None = None
) -> OntologyExtraction:
    """Project one safe event; equal incomplete projections cannot prove equivalence."""
    if len(canonical_json(event).encode("utf-8")) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-ONTOLOGY-BOUNDS: canonical event exceeds 2 MiB")
    # Revalidate at the public boundary (including objects created with model_copy/model_construct).
    event_type = DetectionEvent if isinstance(event, DetectionEvent) else TelemetryEvent
    event = event_type.model_validate(event.model_dump(mode="json"))
    profile = OntologyProfile.model_validate((profile or default_profile()).model_dump())
    decisions = evaluate_events((event,))
    if decisions:
        raise PolicyError(decisions)
    data = event.model_dump(mode="json")
    data["raw"]["payload"] = event.raw.payload
    bindings = []
    findings = list(_profile_checks(event, profile))
    for spec in sorted(profile.bindings, key=lambda item: item.field):
        if event.semantics.category not in spec.categories:
            continue
        binding, losses = _bind(event, data, spec)
        bindings.append(binding)
        findings.extend(losses)
        if spec.required and "severity" in spec.paths and event.severity == 0:
            findings.append(
                _finding(
                    event,
                    "severity_semantic_loss",
                    spec.field,
                    "Normalized severity is unknown; no detection severity can be established.",
                )
            )
    semantics = event.semantics
    resource = tuple(
        _observe(name, semantics.model_dump(mode="json")[name])
        for name in ("dns_name", "http_method", "http_path")
    )
    meaning = SignalMeaning(
        category=semantics.category,
        action=semantics.action,
        outcome=semantics.outcome,
        entities=tuple(sorted(set(event.entities), key=lambda item: (item.kind, item.value))),
        source_destination_relation=EndpointRelation(
            direction="source_to_destination"
            if semantics.source and semantics.destination
            else "incomplete",
            source=semantics.source,
            destination=semantics.destination,
        ),
        protocol=semantics.protocol,
        resource=resource,
        time_role=profile.time_role,
        timestamp_precision_digits=profile.timestamp_precision_digits,
        evidence_requirements=tuple(
            sorted(
                {item.specification.field for item in bindings if item.specification.required}
                | ({"correlation_id"} if profile.correlation_requirement == "required" else set())
                | ({"confidence"} if profile.confidence_requirement is not None else set())
            )
        ),
        confidence_requirement=profile.confidence_requirement,
        correlation_requirement=profile.correlation_requirement,
        evidence=tuple(item.observable for item in bindings if item.specification.affects_identity),
    )
    unique_findings = tuple(
        sorted(
            {item.finding_id: item for item in findings}.values(),
            key=lambda item: (item.field, item.loss_class),
        )
    )
    assumptions = tuple(
        DetectionAssumption(
            assumption_id=f"assumption:{item.specification.field}",
            requirement=f"Resolve {item.specification.field} under its declared evidence contract.",
            decision="unknown"
            if any(f.field == item.specification.field for f in unique_findings)
            else "pass",
            evidence_fields=(item.specification.field,),
            explanation="Optional absence is explicit; unresolved required evidence stays unknown.",
        )
        for item in bindings
    )
    recommendations = tuple(
        SemanticRecommendation(
            recommendation_id=f"recommendation:{item.finding_id.removeprefix('finding:')}",
            finding_id=item.finding_id,
            evidence_fields=item.evidence_refs,
            action=_recommendation(item.loss_class),
        )
        for item in unique_findings
    )
    return OntologyExtraction(
        event_id=event.event_id,
        event_digest=event.stable_digest(),
        raw_digest=event.raw.raw_digest,
        profile_digest=profile.stable_digest(),
        signal=SemanticSignal.from_meaning(meaning),
        bindings=tuple(bindings),
        assumptions=assumptions,
        findings=unique_findings,
        recommendations=recommendations,
        state="ambiguous"
        if any(item.observable.state == "ambiguous" for item in bindings)
        else "unknown"
        if unique_findings
        else "known",
    )


def _recommendation(code: LossClass) -> str:
    return {
        "missing_required_evidence": "Provide required fixture evidence and rerun extraction.",
        "ambiguous_field_binding": "Resolve alias conflicts against retained source values.",
        "lossy_normalization": "Preserve distinctions or independently justify normalization.",
        "unsupported_semantic_category": "Use a tested profile supporting this category.",
        "inconsistent_entity_role": "Correct role declarations using canonical endpoint evidence.",
        "timestamp_precision_loss": "Supply required precision or revise the declared requirement.",
        "correlation_key_loss": "Retain the required correlation key through normalization.",
        "severity_semantic_loss": "Supply a supported severity mapping with source evidence.",
        "unknown_mapping": "Define and test the unsupported mapping or evidence interpretation.",
        "insufficient_confidence": "Provide supported source confidence; never guess a value.",
    }[code]


def semantic_equivalence(
    left: OntologyExtraction, right: OntologyExtraction
) -> SemanticEquivalence:
    """Compare complete meaning and record observed change in an inert transform value."""
    left = OntologyExtraction.model_validate(left.model_dump())
    right = OntologyExtraction.model_validate(right.model_dump())
    before, after = left.signal.meaning().model_dump(), right.signal.meaning().model_dump()
    changed = tuple(sorted(name for name in before if before[name] != after[name]))
    decision: Literal["unknown", "different", "equivalent"] = (
        "unknown"
        if left.state != "known" or right.state != "known"
        else ("different" if changed else "equivalent")
    )
    return SemanticEquivalence(
        decision=decision,
        explanation={
            "unknown": "Unresolved evidence prevents equivalence even when digests match.",
            "different": "Complete projections differ in the listed semantic fields.",
            "equivalent": "Both projections satisfy their requirements and share declared meaning.",
        }[decision],
        transform=SemanticTransform(
            transform_id="transform:"
            + digest({"left": left.event_digest, "right": right.event_digest}),
            source_digest=left.event_digest,
            destination_digest=right.event_digest,
            changed_fields=changed,
        ),
        invariant=SemanticInvariant(
            invariant_id="ontology:meaning-preserved",
            protected_fields=tuple(sorted(before)),
            explanation="Meaning must agree with all required evidence resolved.",
        ),
    )


def export_ontology(
    events: tuple[TelemetryEvent, ...], profile: OntologyProfile | None = None
) -> OntologyExport:
    """At most 1,000 safe events, sorted by unique event identity; no implicit I/O."""
    if not 1 <= len(events) <= 1000 or len({item.event_id for item in events}) != len(events):
        raise ValueError("DVI-ONTOLOGY-BOUNDS: require 1..1000 events with unique IDs")
    if sum(len(canonical_json(event).encode("utf-8")) for event in events) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-ONTOLOGY-BOUNDS: combined canonical events exceed 2 MiB")
    selected = profile or default_profile()
    extractions = tuple(
        extract_signal(event, selected) for event in sorted(events, key=lambda item: item.event_id)
    )
    return OntologyExport(
        profile=selected,
        input_digest=digest([item.event_digest for item in extractions]),
        extractions=extractions,
    )


def ontology_artifacts(export: OntologyExport) -> dict[str, bytes]:
    """Build the three real bounded exports; these are analysis files, not a V1 run bundle."""
    export = OntologyExport.model_validate(export.model_dump())
    # Each view retains the same input/profile anchors and full source references where needed.
    return {
        "semantic_ontology.json": json_bytes(export),
        "ontology_bindings.json": json_bytes(
            BindingExport(
                input_digest=export.input_digest,
                profile_digest=export.profile.stable_digest(),
                bindings=tuple(item for result in export.extractions for item in result.bindings),
            )
        ),
        "semantic_loss.json": json_bytes(
            LossExport(
                input_digest=export.input_digest,
                profile_digest=export.profile.stable_digest(),
                findings=tuple(item for result in export.extractions for item in result.findings),
                recommendations=tuple(
                    item for result in export.extractions for item in result.recommendations
                ),
            )
        ),
    }
