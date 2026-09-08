"""Finite single-assumption transformations using the existing policy boundary."""

from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.models import EventSemantics, RawSource, TelemetryEvent
from dvi_sentinel.policy import evaluate_events
from dvi_sentinel.probe_models import ProbeClass, ProbeSpec
from dvi_sentinel.probe_sources import semantic_projection, source_variant
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.variation_models import (
    EventLineage,
    Family,
    MetamorphicInvariant,
    SemanticPreservationResult,
)


def specifications() -> tuple[ProbeSpec, ...]:
    entries: list[tuple[str, ProbeClass, str]] = [
        ("timestamp_precision", "timestamp_precision", "rewrite exact fractional precision"),
        ("timezone", "timezone", "rewrite the same instant with a fixed UTC offset"),
        ("ordering", "ordering", "reverse explicitly order-independent events"),
        ("schema_alias", "schema_alias", "rename one supported source alias per record"),
        ("severity_normalization", "severity_normalization", "use an equivalent severity spelling"),
        ("duplicates", "duplicates", "append one duplicate with explicit logical lineage"),
        ("benign_noise", "benign_noise", "append one labeled benign background event"),
        ("bounded_volume", "bounded_volume", "append the declared maximum duplicate count"),
    ]
    for field in ("sensor", "vendor", "confidence", "correlation_id", "labels", "tags"):
        kind: ProbeClass = (
            "correlation"
            if field == "correlation_id"
            else "labels_tags"
            if field in {"labels", "tags"}
            else "optional_field"
        )
        entries.append((f"drop:{field}", kind, f"remove declared optional {field}"))
    for field in ("sensor", "vendor"):
        entries.append((f"name:{field}", "sensor_vendor", f"alias declared optional {field}"))
    return tuple(
        ProbeSpec(
            name=name,
            finding_class=kind,
            hypothesis=f"Baseline detection identities survive: {transformation}",
            transformation=transformation,
            invariant="Original event meaning and coverage survive within declared permissions",
        )
        for name, kind, transformation in sorted(entries)
    )


def permission(spec: ProbeSpec, policy: VariationPolicy) -> bool:
    name = spec.name
    if name.startswith("drop:"):
        return "dropout" in policy.families and name[5:] in policy.optional_fields
    if name.startswith("name:"):
        return "metadata" in policy.families and name[5:] in policy.optional_fields
    if name == "ordering":
        return "ordering" in policy.families and policy.order_independent
    if name in {"timestamp_precision", "timezone"}:
        return "timing" in policy.families
    if name in {"schema_alias", "severity_normalization"}:
        return "metadata" in policy.families
    if name == "benign_noise":
        return "noise" in policy.families and policy.max_noise_events >= 1
    return "volume" in policy.families and policy.max_duplicates >= (
        2 if name == "bounded_volume" else 1
    )


def transform(
    spec: ProbeSpec,
    original: tuple[TelemetryEvent, ...],
    policy: VariationPolicy,
) -> tuple[tuple[TelemetryEvent, ...], tuple[EventLineage, ...], SemanticPreservationResult]:
    name = spec.name
    events = list(original)
    lineage = [
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in events
    ]
    family: Family = "baseline"
    if name in {"timestamp_precision", "timezone", "schema_alias", "severity_normalization"}:
        candidate = tuple(source_variant(e, name) for e in original)
        checks = (
            MetamorphicInvariant(
                id="DVI-INV-REPRESENTATION",
                passed=all(
                    semantic_projection(a) == semantic_projection(b)
                    for a, b in zip(original, candidate, strict=True)
                ),
                explanation="Independent re-parsing preserves all normalized fields",
            ),
            MetamorphicInvariant(
                id="DVI-INV-POLICY",
                passed=not evaluate_events(candidate),
                explanation="Transformed raw and normalized data satisfy policy",
            ),
        )
        return candidate, tuple(lineage), SemanticPreservationResult(checks=checks)
    if name == "ordering":
        family = "ordering"
        events.reverse()
    elif name.startswith(("drop:", "name:")):
        field = name[5:]
        family = "dropout" if name.startswith("drop:") else "metadata"
        for index, event in enumerate(events):
            data = event.model_dump()
            target = data["raw"] if field in {"sensor", "vendor"} else data
            if family == "dropout":
                target[field] = () if field in {"labels", "tags"} else None
            elif target[field] is not None:
                target[field] = "fixture-sensor-alias"
            events[index] = TelemetryEvent.model_validate(data)
    elif name in {"duplicates", "bounded_volume"}:
        family = "volume"
        count = 1 if name == "duplicates" else policy.max_duplicates
        for index in range(count):
            before = original[index % len(original)]
            event_id = f"probe:duplicate:{index}"
            events.append(
                TelemetryEvent.model_validate(before.model_dump() | {"event_id": event_id})
            )
            lineage.append(
                EventLineage(event_id=event_id, original_event_id=before.event_id, role="duplicate")
            )
    elif name == "benign_noise":
        family = "noise"
        event_id = "probe:noise:0"
        events.append(
            TelemetryEvent(
                event_id=event_id,
                timestamp=min(e.timestamp for e in original),
                semantics=EventSemantics(category="flow", action="background", protocol="udp"),
                raw=RawSource.from_payload(
                    {"kind": "benign_background", "index": 0}, adapter="synthetic_noise"
                ),
                labels=("dvi:background",),
            )
        )
        lineage.append(EventLineage(event_id=event_id, original_event_id=None, role="noise"))
    candidate = tuple(events)
    return (
        candidate,
        tuple(lineage),
        check_candidate(original, candidate, tuple(lineage), policy, family),
    )
