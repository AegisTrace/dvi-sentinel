"""Independent semantic/safety checks for normalized telemetry transformations."""

from collections import Counter
from typing import Any

from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.variation_models import (
    EventLineage,
    Family,
    MetamorphicInvariant,
    SemanticPreservationResult,
)


def _protected(event: TelemetryEvent, family: Family, policy: VariationPolicy) -> dict[str, Any]:
    data = event.model_dump(mode="json")
    data.pop("event_id")
    if family == "timing":
        data.pop("timestamp")
        data.pop("observed_at")
    if family in {"metadata", "dropout"}:
        for field in policy.optional_fields:
            if family == "metadata" and field not in {"sensor", "vendor"}:
                continue
            if field in {"sensor", "vendor"}:
                data["raw"].pop(field)
            else:
                data.pop(field)
    return data


def check_candidate(
    original: tuple[TelemetryEvent, ...],
    candidate: tuple[TelemetryEvent, ...],
    lineage: tuple[EventLineage, ...],
    policy: VariationPolicy,
    family: Family,
) -> SemanticPreservationResult:
    checks: list[MetamorphicInvariant] = []

    def check(code: str, passed: bool, explanation: str) -> None:
        checks.append(MetamorphicInvariant(id=code, passed=passed, explanation=explanation))

    original_by_id = {event.event_id: event for event in original}
    candidate_by_id = {event.event_id: event for event in candidate}
    ids = [event.event_id for event in candidate]
    refs = [item.event_id for item in lineage]
    identity_ok = (
        len(original_by_id) == len(original)
        and len(set(ids)) == len(ids)
        and len(set(refs)) == len(refs)
        and set(ids) == set(refs)
    )
    check(
        "DVI-INV-IDENTITY", identity_ok, "event IDs are unique and lineage covers every candidate"
    )
    roles = Counter(item.role for item in lineage)
    originals = [item.original_event_id for item in lineage if item.role == "original"]
    original_mapping_ok = Counter(originals) == Counter(original_by_id.keys()) and all(
        item.event_id == item.original_event_id for item in lineage if item.role == "original"
    )
    check("DVI-INV-COVERAGE", original_mapping_ok, "every original event survives exactly once")
    protected_ok = True
    timing_ok = True
    noise_ok = True
    transform_ok = True
    for item in lineage:
        event = candidate_by_id.get(item.event_id)
        if event is None:
            protected_ok = False
            continue
        if item.role == "noise":
            noise_ok &= (
                item.original_event_id is None
                and event.semantics.category == "flow"
                and event.semantics.action == "background"
                and event.severity == 0
                and event.labels == ("dvi:background",)
                and event.correlation_id is None
                and event.raw.adapter == "synthetic_noise"
                and event.semantics.protocol == "udp"
                and event.raw.payload.get("kind") == "benign_background"
                and set(event.raw.payload) == {"kind", "index"}
                and type(event.raw.payload.get("index")) is int
            )
            continue
        before = original_by_id.get(item.original_event_id or "")
        if before is None:
            protected_ok = False
            continue
        protected_ok &= _protected(event, family, policy) == _protected(before, family, policy)
        if family in {"metadata", "dropout"}:
            for field in policy.optional_fields:
                if family == "metadata" and field not in {"sensor", "vendor"}:
                    continue
                left = getattr(before.raw if field in {"sensor", "vendor"} else before, field)
                right = getattr(event.raw if field in {"sensor", "vendor"} else event, field)
                allowed: tuple[object, ...]
                if family == "metadata":
                    allowed = (
                        (left, left.upper(), left.lower(), "fixture-sensor-alias")
                        if isinstance(left, str)
                        else (left,)
                    )
                else:
                    allowed = (left, () if field in {"labels", "tags"} else None)
                transform_ok &= right in allowed
        if family == "timing":
            offset = event.timestamp - before.timestamp
            timing_ok &= abs(offset.total_seconds() * 1000) <= policy.max_jitter_ms + 1e-9
            if before.observed_at is None:
                timing_ok &= event.observed_at is None
            else:
                timing_ok &= (
                    event.observed_at is not None
                    and event.observed_at - before.observed_at == offset
                )
    check(
        "DVI-INV-PROTECTED",
        protected_ok,
        "semantics, severity, raw payload, and undeclared fields remain unchanged",
    )
    check("DVI-INV-TIMING", timing_ok, "jitter stays in bounds and preserves observation delay")
    check(
        "DVI-INV-TRANSFORM",
        transform_ok,
        "metadata uses declared benign forms; dropout only removes values",
    )
    check(
        "DVI-INV-NOISE",
        noise_ok,
        "added background is explicitly synthetic, uncorrelated, and non-alerting",
    )
    permitted = family == "baseline" or family in policy.families
    counts_ok = (
        len(candidate) <= 10_000
        and roles["noise"] <= policy.max_noise_events
        and roles["duplicate"] <= policy.max_duplicates
        and (roles["noise"] == 0 or family == "noise")
        and (roles["duplicate"] == 0 or family == "volume")
    )
    check(
        "DVI-INV-BOUNDS",
        permitted and counts_ok,
        "strategy is declared and additions obey finite bounds",
    )
    # Inspect actual sequence rather than trusting lineage's order.
    candidate_original_order = [event_id for event_id in ids if event_id in original_by_id]
    ordering_ok = candidate_original_order == list(original_by_id) or (
        family == "ordering" and policy.order_independent
    )
    check("DVI-INV-ORDER", ordering_ok, "ordering changes require explicit semantic permission")
    try:
        decisions = evaluate_events(candidate)
    except PolicyError as exc:
        decisions = exc.decisions
    check(
        "DVI-INV-POLICY", not decisions, "post-transformation policy accepts all candidate content"
    )
    return SemanticPreservationResult(checks=tuple(checks))
