"""Seeded, bounded single-family variation planning; no harness execution or I/O."""

import random
from datetime import timedelta
from ipaddress import ip_address

from pydantic import ValidationError

from dvi_sentinel import __version__
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.models import EventSemantics, NetworkEndpoint, RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import digest
from dvi_sentinel.variation_models import (
    CandidateOmission,
    EventLineage,
    Family,
    VariationCase,
    VariationConstraint,
    VariationParameter,
    VariationPlan,
    VariationStrategy,
)


def _replace(event: TelemetryEvent, **changes: object) -> TelemetryEvent:
    return TelemetryEvent.model_validate(event.model_dump() | changes)


def strategies(policy: VariationPolicy) -> tuple[VariationStrategy, ...]:
    changes = {
        "timing": ("timestamp", "observed_at"),
        "ordering": ("event_order",),
        "metadata": ("declared sensor/vendor metadata",),
        "noise": ("benign event additions",),
        "volume": ("duplicate event additions",),
        "dropout": ("declared optional fields",),
    }
    bounds = {
        "timing": ("jitter_ms", -policy.max_jitter_ms, policy.max_jitter_ms),
        "noise": ("noise_count", 0, policy.max_noise_events),
        "volume": ("duplicate_count", 0, policy.max_duplicates),
    }
    result = []
    for family in sorted(policy.families):
        constraint = bounds.get(family)
        result.append(
            VariationStrategy(
                id=f"dvi:{family}:1",
                family=family,
                allowed_changes=changes[family],
                protected_invariants=(
                    "event semantics",
                    "original coverage",
                    "raw payload integrity",
                    "undeclared metadata",
                    "policy safety",
                ),
                constraints=(
                    VariationConstraint(
                        name=constraint[0], minimum=constraint[1], maximum=constraint[2]
                    ),
                )
                if constraint
                else (),
            )
        )
    return tuple(result)


def _transform(
    original: tuple[TelemetryEvent, ...],
    policy: VariationPolicy,
    family: Family,
    rng: random.Random,
) -> tuple[
    tuple[TelemetryEvent, ...], tuple[EventLineage, ...], tuple[VariationParameter, ...], float
]:
    events = list(original)
    lineage = [
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in events
    ]
    params: list[VariationParameter] = []
    distance = 0.0
    if family == "timing":
        for index, event in enumerate(events):
            offset = rng.randint(-policy.max_jitter_ms, policy.max_jitter_ms)
            delta = timedelta(milliseconds=offset)
            events[index] = _replace(
                event,
                timestamp=event.timestamp + delta,
                observed_at=event.observed_at + delta if event.observed_at else None,
            )
            params.append(VariationParameter(name=event.event_id, value=offset))
            distance += abs(offset) / max(1, policy.max_jitter_ms)
    elif family == "ordering":
        rng.shuffle(events)
        params.append(VariationParameter(name="order", value=tuple(e.event_id for e in events)))
        distance = sum(
            left.event_id != right.event_id for left, right in zip(original, events, strict=True)
        ) / max(1, len(events))
    elif family == "metadata":
        fields = [name for name in policy.optional_fields if name in {"sensor", "vendor"}]
        if fields:
            field = rng.choice(fields)
            mode = rng.choice(("upper", "lower", "alias"))
            params.extend(
                (
                    VariationParameter(name="field", value=field),
                    VariationParameter(name="mode", value=mode),
                )
            )
            for index, event in enumerate(events):
                value = getattr(event.raw, field)
                if value is None:
                    continue
                changed = (
                    value.upper()
                    if mode == "upper"
                    else value.lower()
                    if mode == "lower"
                    else "fixture-sensor-alias"
                )
                raw = RawSource.model_validate(event.raw.model_dump() | {field: changed})
                events[index] = _replace(event, raw=raw)
                distance += float(changed != value)
    elif family in {"noise", "volume"}:
        maximum = policy.max_noise_events if family == "noise" else policy.max_duplicates
        count = rng.randint(1, maximum) if maximum else 0
        params.append(VariationParameter(name="count", value=count))
        for index in range(count):
            event_id = (
                f"{family}:"
                + digest({"index": index, "input": [e.event_id for e in original]})[:24]
            )
            if family == "volume":
                before = original[rng.randrange(len(original))]
                params.append(VariationParameter(name=f"duplicate:{index}", value=before.event_id))
                new = _replace(before, event_id=event_id)
                lineage.append(
                    EventLineage(
                        event_id=event_id, original_event_id=before.event_id, role="duplicate"
                    )
                )
            else:
                new = TelemetryEvent(
                    event_id=event_id,
                    timestamp=min(e.timestamp for e in original),
                    semantics=EventSemantics(
                        category="flow",
                        action="background",
                        protocol="udp",
                        source=NetworkEndpoint(address=ip_address("192.0.2.254"), port=55000),
                        destination=NetworkEndpoint(address=ip_address("198.51.100.254"), port=9),
                    ),
                    raw=RawSource.from_payload(
                        {"kind": "benign_background", "index": index}, adapter="synthetic_noise"
                    ),
                    labels=("dvi:background",),
                )
                lineage.append(
                    EventLineage(event_id=event_id, original_event_id=None, role="noise")
                )
            events.append(new)
        distance = float(count)
    elif family == "dropout" and policy.optional_fields:
        field = rng.choice(policy.optional_fields)
        params.append(VariationParameter(name="field", value=field))
        for index, event in enumerate(events):
            if field in {"sensor", "vendor"}:
                raw = RawSource.model_validate(event.raw.model_dump() | {field: None})
                events[index] = _replace(event, raw=raw)
            else:
                events[index] = _replace(
                    event, **{field: () if field in {"labels", "tags"} else None}
                )
            distance += float(events[index] != event)
    return tuple(events), tuple(lineage), tuple(params), distance


def plan_variations(
    scenario_id: str,
    events: tuple[TelemetryEvent, ...],
    policy: VariationPolicy,
    seed: int,
    *,
    event_budget: int = 50_000,
) -> VariationPlan:
    if not events or len(events) > 10_000 or len({e.event_id for e in events}) != len(events):
        raise ValueError("DVI-VAR-INPUT: require 1..10000 uniquely identified events")
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("DVI-VAR-SEED: require an integer in 0..2**63-1")
    if type(event_budget) is not int or not len(events) <= event_budget <= 50_000:
        raise ValueError("DVI-VAR-BUDGET: budget must cover the baseline and be <=50000")
    decisions = evaluate_events(events)
    if decisions:
        raise PolicyError(decisions)
    input_digest = digest([event.model_dump(mode="json") for event in events])
    config_digest = digest({"policy": policy.model_dump(mode="json"), "event_budget": event_budget})
    baseline_lineage = tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in events
    )
    cases = [
        VariationCase(
            id="baseline",
            family="baseline",
            parameters=(),
            events=events,
            lineage=baseline_lineage,
            preservation=check_candidate(events, events, baseline_lineage, policy, "baseline"),
            distance=0.0,
        )
    ]
    declared = strategies(policy)
    seen = {input_digest}
    attempted = skipped_noop = skipped_invalid = 0
    total_events = len(events)
    event_budget_exhausted = False
    omissions: list[CandidateOmission] = []
    # Fixed attempt budget avoids unbounded searches when only a few unique transformations exist.
    for attempt in range(policy.max_variants * 4):
        if not declared or len(cases) >= policy.max_variants:
            break
        family = declared[attempt % len(declared)].family
        attempted += 1
        rng = random.Random(
            int(
                digest(
                    {
                        "seed": seed,
                        "attempt": attempt,
                        "family": family,
                        "input": input_digest,
                        "config": config_digest,
                    }
                ),
                16,
            )
        )
        try:
            candidate, lineage, parameters, distance = _transform(events, policy, family, rng)
        except (OverflowError, ValidationError) as exc:
            skipped_invalid += 1
            omissions.append(
                CandidateOmission(
                    attempt=attempt,
                    family=family,
                    code="DVI-VAR-OVERFLOW"
                    if isinstance(exc, OverflowError)
                    else "DVI-VAR-FIELD-LIMIT",
                )
            )
            continue
        candidate_digest = digest([event.model_dump(mode="json") for event in candidate])
        if candidate_digest in seen:
            skipped_noop += 1
            continue
        if total_events + len(candidate) > event_budget:
            event_budget_exhausted = True
            omissions.append(
                CandidateOmission(attempt=attempt, family=family, code="DVI-VAR-EVENT-BUDGET")
            )
            break
        total_events += len(candidate)
        seen.add(candidate_digest)
        case_id = (
            f"variation:{family}:"
            + digest(
                {
                    "scenario": scenario_id,
                    "input": input_digest,
                    "config": config_digest,
                    "seed": seed,
                    "family": family,
                    "parameters": [p.model_dump(mode="json") for p in parameters],
                    "version": __version__,
                }
            )[:24]
        )
        cases.append(
            VariationCase(
                id=case_id,
                family=family,
                parameters=parameters,
                events=candidate,
                lineage=lineage,
                preservation=check_candidate(events, candidate, lineage, policy, family),
                distance=distance,
            )
        )
    return VariationPlan(
        tool_version=__version__,
        scenario_id=scenario_id,
        seed=seed,
        input_digest=input_digest,
        config_digest=config_digest,
        strategies=declared,
        cases=tuple(cases),
        attempted=attempted,
        skipped_noop=skipped_noop,
        skipped_invalid=skipped_invalid,
        event_budget_exhausted=event_budget_exhausted,
        event_budget=event_budget,
        omissions=tuple(omissions),
    )
