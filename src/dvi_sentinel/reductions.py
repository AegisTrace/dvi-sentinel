"""Finite, simplifying counterfactual proposals; validation remains independent."""

from collections.abc import Iterator
from datetime import timedelta

from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.probe_models import ProbeSpec
from dvi_sentinel.probe_sources import semantic_projection, source_variant
from dvi_sentinel.probe_transforms import permission, specifications
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.variation_models import (
    EventLineage,
    Family,
    MetamorphicInvariant,
    SemanticPreservationResult,
)

Reduction = tuple[str, tuple[TelemetryEvent, ...], tuple[EventLineage, ...]]
SOURCE_PROBES = {"timestamp_precision", "timezone", "schema_alias", "severity_normalization"}


def validate_reduction(
    original: tuple[TelemetryEvent, ...],
    events: tuple[TelemetryEvent, ...],
    lineage: tuple[EventLineage, ...],
    policy: VariationPolicy,
    family: Family,
    probe: ProbeSpec | None = None,
) -> SemanticPreservationResult:
    if probe is None:
        return check_candidate(original, events, lineage, policy, family)
    declared = any(
        spec.name == probe.name and spec.finding_class == probe.finding_class
        for spec in specifications()
    )
    permitted = declared and permission(probe, policy)
    if probe.name not in SOURCE_PROBES:
        implied = (
            "dropout"
            if probe.name.startswith("drop:")
            else "metadata"
            if probe.name.startswith("name:")
            else "volume"
            if probe.name in {"duplicates", "bounded_volume"}
            else "noise"
            if probe.name == "benign_noise"
            else "ordering"
        )
        checked = check_candidate(original, events, lineage, policy, family)
        return SemanticPreservationResult(
            checks=(
                *checked.checks,
                MetamorphicInvariant(
                    id="DVI-INV-PROBE",
                    passed=permitted and implied == family,
                    explanation="Probe class and family agree with the declared catalog",
                ),
            )
        )
    # Representation shrinking can only revert independently valid source rewrites.
    covered = [e.event_id for e in events] == [e.event_id for e in original] and len(
        {e.event_id for e in events}
    ) == len(events)
    refs = tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in original
    )
    exact = permitted and covered and lineage == refs
    if exact:
        try:
            exact = all(
                after in (before, source_variant(before, probe.name))
                and semantic_projection(before) == semantic_projection(after)
                for before, after in zip(original, events, strict=True)
            )
        except (ValueError, OverflowError):
            exact = False
    try:
        safe = not evaluate_events(events)
    except PolicyError:
        safe = False
    return SemanticPreservationResult(
        checks=(
            MetamorphicInvariant(
                id="DVI-INV-REDUCTION",
                passed=exact,
                explanation="Only a declared equivalent source rewrite or its original survives",
            ),
            MetamorphicInvariant(
                id="DVI-INV-POLICY",
                passed=safe,
                explanation="Reduced source and normalized content remain safe",
            ),
        )
    )


def reductions(
    original: tuple[TelemetryEvent, ...],
    events: tuple[TelemetryEvent, ...],
    lineage: tuple[EventLineage, ...],
    family: Family,
    policy: VariationPolicy,
    *,
    representation: bool = False,
    ablation: bool = False,
) -> Iterator[Reduction]:
    originals = {e.event_id: e for e in original}
    if family in {"volume", "noise"} and not representation:
        added = {ref.event_id for ref in lineage if ref.role != "original"}
        for event in reversed(events):
            if event.event_id in added:
                yield (
                    f"remove:{event.event_id}",
                    tuple(e for e in events if e.event_id != event.event_id),
                    tuple(ref for ref in lineage if ref.event_id != event.event_id),
                )
        return
    if family == "ordering" and not representation:
        positions = {e.event_id: i for i, e in enumerate(original)}
        for index in range(len(events) - 1):
            if positions[events[index].event_id] > positions[events[index + 1].event_id]:
                changed = list(events)
                changed[index], changed[index + 1] = changed[index + 1], changed[index]
                yield f"swap:{index}:{index + 1}", tuple(changed), lineage
        return
    for index, event in enumerate(events):
        before = originals[event.event_id]
        replacements: list[tuple[str, TelemetryEvent]] = []
        if representation:
            if event != before:
                replacements.append(("source", before))
        elif family == "timing":
            offset = (event.timestamp - before.timestamp) // timedelta(microseconds=1)
            if offset:
                sign = 1 if offset > 0 else -1
                targets = [0]
                if not ablation:
                    step = abs(offset) // 2
                    while step:
                        targets.append(offset - sign * step)
                        step //= 2
                for target in dict.fromkeys(targets):
                    delta = timedelta(microseconds=target)
                    replacements.append(
                        (
                            f"time_us:{target}",
                            TelemetryEvent.model_validate(
                                event.model_dump()
                                | {
                                    "timestamp": before.timestamp + delta,
                                    "observed_at": before.observed_at + delta
                                    if before.observed_at
                                    else None,
                                }
                            ),
                        )
                    )
        elif family in {"metadata", "dropout"}:
            for field in policy.optional_fields:
                data = event.model_dump()
                old = before.model_dump()
                target_data = data["raw"] if field in {"sensor", "vendor"} else data
                source = old["raw"] if field in {"sensor", "vendor"} else old
                if target_data[field] != source[field]:
                    target_data[field] = source[field]
                    replacements.append((field, TelemetryEvent.model_validate(data)))
        for label, replacement in replacements:
            yield (
                f"revert:{event.event_id}:{label}",
                (*events[:index], replacement, *events[index + 1 :]),
                lineage,
            )
