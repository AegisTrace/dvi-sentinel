"""Bounded temporal and correlation predicates over validated local events."""

import re
from collections.abc import Sequence
from datetime import datetime

from pydantic import JsonValue

from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES
from dvi_sentinel.models import DetectionEvent, TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes
from dvi_sentinel.serialization import canonical_json, digest
from dvi_sentinel.temporal_models import (
    CorrelationEvidence,
    CorrelationEvidenceExport,
    SequenceFinding,
    SequenceFindingsExport,
    TemporalCheck,
    TemporalPredicate,
    TemporalState,
    TemporalSummary,
    TemporalTrace,
)

MAX_EVENTS = 128
MAX_WINDOW_MS = 86_400_000
_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,6}))?(?:Z|[+-]\d{2}:?\d{2})"
)
_BENIGN_MARKERS = frozenset({"benign", "benign_context", "control", "allow", "allowed", "expected"})


def _validate_event(event: TelemetryEvent) -> TelemetryEvent:
    event_type = DetectionEvent if isinstance(event, DetectionEvent) else TelemetryEvent
    checked = event_type.model_validate(event.model_dump(mode="json"))
    decisions = evaluate_events((checked,))
    if decisions:
        raise PolicyError(decisions)
    return checked


def _events(
    events: Sequence[TelemetryEvent], *, allow_empty: bool = True
) -> tuple[TelemetryEvent, ...]:
    if len(events) > MAX_EVENTS or (not allow_empty and not events):
        raise ValueError("DVI-TEMPORAL-BOUNDS: require 1..128 events")
    checked = tuple(_validate_event(event) for event in events)
    if len({event.event_id for event in checked}) != len(checked):
        raise ValueError("DVI-TEMPORAL-BOUNDS: event IDs must be unique")
    if sum(len(canonical_json(event).encode("utf-8")) for event in checked) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-TEMPORAL-BOUNDS: combined events exceed 2 MiB")
    return tuple(sorted(checked, key=lambda event: (event.timestamp, event.event_id)))


def _pair(left: TelemetryEvent, right: TelemetryEvent) -> tuple[TelemetryEvent, TelemetryEvent]:
    return _validate_event(left), _validate_event(right)


def _snapshot(value: JsonValue | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        value = value.isoformat().replace("+00:00", "Z")
    return canonical_json(value)


def _precision(event: TelemetryEvent) -> int | None:
    source = event.raw.original_timestamp
    if source is None:
        return None
    match = _TIMESTAMP_RE.fullmatch(source)
    return len(match.group(1) or "") if match else None


def _time_reasons(events: Sequence[TelemetryEvent], required_digits: int) -> tuple[str, ...]:
    if not required_digits:
        return ()
    if any(
        _precision(event) is None or (_precision(event) or 0) < required_digits for event in events
    ):
        return ("timestamp_precision_loss",)
    return ()


def _check(
    predicate: TemporalPredicate,
    events: Sequence[TelemetryEvent],
    outcome: TemporalState,
    explanation: str,
    *,
    expected: JsonValue | None = None,
    observed: JsonValue | None = None,
    reason_codes: tuple[str, ...] = (),
) -> TemporalCheck:
    return TemporalCheck(
        predicate=predicate,
        event_ids=tuple(event.event_id for event in events),
        outcome=outcome,
        reason_codes=reason_codes,
        expected_json=_snapshot(expected),
        observed_json=_snapshot(observed),
        explanation=explanation,
    )


def before(a: TelemetryEvent, b: TelemetryEvent) -> TemporalCheck:
    left, right = _pair(a, b)
    result = left.timestamp < right.timestamp
    return _check(
        "before",
        (left, right),
        "supported" if result else "contradicted",
        "The first normalized UTC timestamp is strictly earlier than the second."
        if result
        else "The first normalized UTC timestamp is not strictly earlier than the second.",
        expected=True,
        observed=result,
    )


def after(a: TelemetryEvent, b: TelemetryEvent) -> TemporalCheck:
    left, right = _pair(a, b)
    result = left.timestamp > right.timestamp
    return _check(
        "after",
        (left, right),
        "supported" if result else "contradicted",
        "The first normalized UTC timestamp is strictly later than the second."
        if result
        else "The first normalized UTC timestamp is not strictly later than the second.",
        expected=True,
        observed=result,
    )


def within(
    a: TelemetryEvent,
    b: TelemetryEvent,
    duration_ms: int,
    *,
    precision_digits: int = 0,
) -> TemporalCheck:
    left, right = _pair(a, b)
    _validate_window(duration_ms)
    _validate_precision(precision_digits)
    reasons = _time_reasons((left, right), precision_digits)
    delta_ms = abs((right.timestamp - left.timestamp).total_seconds() * 1000)
    result = delta_ms <= duration_ms
    outcome: TemporalState = "unknown" if reasons else "supported" if result else "contradicted"
    return _check(
        "within",
        (left, right),
        outcome,
        "The absolute normalized UTC interval is within the finite bound."
        if result and not reasons
        else "The source timestamp precision is below the declared requirement."
        if reasons
        else "The absolute normalized UTC interval exceeds the finite bound.",
        expected={"duration_ms": duration_ms, "precision_digits": precision_digits},
        observed={"delta_ms": delta_ms},
        reason_codes=reasons,
    )


def same_entity(a: TelemetryEvent, b: TelemetryEvent) -> TemporalCheck:
    left, right = _pair(a, b)
    left_entities = {(item.kind, item.value) for item in left.entities}
    right_entities = {(item.kind, item.value) for item in right.entities}
    if not left_entities or not right_entities:
        return _check(
            "same_entity",
            (left, right),
            "unknown",
            "Both events need explicit entity evidence.",
            reason_codes=("entity_evidence_missing",),
        )
    result = bool(left_entities & right_entities)
    shared_entities: list[JsonValue] = [
        [kind, value] for kind, value in sorted(left_entities & right_entities)
    ]
    return _check(
        "same_entity",
        (left, right),
        "supported" if result else "contradicted",
        "The events share an explicit entity reference."
        if result
        else "The events have no shared explicit entity reference.",
        expected=True,
        observed=shared_entities,
    )


def same_flow(a: TelemetryEvent, b: TelemetryEvent) -> TemporalCheck:
    left, right = _pair(a, b)
    values = (
        left.semantics.source,
        left.semantics.destination,
        left.semantics.protocol,
        right.semantics.source,
        right.semantics.destination,
        right.semantics.protocol,
    )
    if any(value is None for value in values):
        return _check(
            "same_flow",
            (left, right),
            "unknown",
            "Both events need source, destination and protocol evidence.",
            reason_codes=("flow_evidence_missing",),
        )
    result = (
        left.semantics.source == right.semantics.source
        and left.semantics.destination == right.semantics.destination
        and left.semantics.protocol == right.semantics.protocol
    )
    return _check(
        "same_flow",
        (left, right),
        "supported" if result else "contradicted",
        "Endpoint roles and protocol agree." if result else "Endpoint roles or protocol differ.",
        expected=True,
        observed=result,
    )


def same_correlation_key(a: TelemetryEvent, b: TelemetryEvent) -> TemporalCheck:
    left, right = _pair(a, b)
    if left.correlation_id is None or right.correlation_id is None:
        return _check(
            "same_correlation_key",
            (left, right),
            "unknown",
            "Both events need an explicit correlation key.",
            reason_codes=("correlation_key_missing",),
        )
    result = left.correlation_id == right.correlation_id
    return _check(
        "same_correlation_key",
        (left, right),
        "supported" if result else "contradicted",
        "Correlation keys are equal." if result else "Correlation keys are different.",
        expected=left.correlation_id,
        observed=right.correlation_id,
    )


def at_least_k_of_n(events: Sequence[TelemetryEvent], k: int, n: int) -> TemporalCheck:
    ordered = _events(events)
    if not 0 <= k <= n <= MAX_EVENTS or n == 0:
        raise ValueError("DVI-TEMPORAL-BOUNDS: require 0 <= k <= n <= 128 with n > 0")
    if len(ordered) != n:
        return _check(
            "at_least_k_of_n",
            ordered,
            "unknown",
            "The finite set is incomplete; missing events cannot be treated as failures.",
            expected={"k": k, "n": n},
            observed=len(ordered),
            reason_codes=("event_evidence_missing",),
        )
    result = len(ordered) >= k
    return _check(
        "at_least_k_of_n",
        ordered or tuple(),
        "supported" if result else "contradicted",
        "The supplied finite set reaches the declared count."
        if result
        else "The supplied finite set does not reach the declared count.",
        expected={"k": k, "n": n},
        observed=len(ordered),
    )


def no_contradictory_context(events: Sequence[TelemetryEvent]) -> TemporalCheck:
    ordered = _events(events)
    if not ordered:
        raise ValueError("DVI-TEMPORAL-EVIDENCE: at least one event is required")
    markers = sorted(
        {
            marker
            for event in ordered
            for marker in (*event.labels, *event.tags)
            if marker.casefold() in _BENIGN_MARKERS
        }
    )
    result = not markers
    marker_values: list[JsonValue] = list(markers)
    return _check(
        "no_contradictory_context",
        ordered,
        "supported" if result else "contradicted",
        "No explicit benign/control context marker was supplied."
        if result
        else "Explicit benign/control context suppresses this finding.",
        expected=[],
        observed=marker_values,
        reason_codes=("contradictory_benign_context",) if markers else (),
    )


def alert_within_window(
    signal: TelemetryEvent, alert: TelemetryEvent, window_ms: int, *, precision_digits: int = 0
) -> TemporalCheck:
    source, candidate = _pair(signal, alert)
    _validate_window(window_ms)
    _validate_precision(precision_digits)
    if not isinstance(candidate, DetectionEvent):
        return _check(
            "alert_within_window",
            (source, candidate),
            "unknown",
            "The second event is not validated detection evidence.",
            reason_codes=("alert_evidence_missing",),
        )
    reasons = _time_reasons((source, candidate), precision_digits)
    delta_ms = (candidate.timestamp - source.timestamp).total_seconds() * 1000
    result = 0 <= delta_ms <= window_ms
    outcome: TemporalState = "unknown" if reasons else "supported" if result else "contradicted"
    return _check(
        "alert_within_window",
        (source, candidate),
        outcome,
        "The validated alert follows the signal within the finite window."
        if result and not reasons
        else "Timestamp precision is below the declared requirement."
        if reasons
        else "The alert is before the signal or outside the finite window.",
        expected={"window_ms": window_ms, "precision_digits": precision_digits},
        observed={"delta_ms": delta_ms},
        reason_codes=reasons,
    )


def _matches(event: TelemetryEvent, token: str) -> bool:
    return token in {event.event_id, event.semantics.category, event.semantics.action}


def sequence_order(
    events: Sequence[TelemetryEvent], pattern: Sequence[str], *, precision_digits: int = 0
) -> TemporalCheck:
    ordered = _events(events)
    pattern_tuple = tuple(pattern)
    if (
        not pattern_tuple
        or len(pattern_tuple) > MAX_EVENTS
        or any(
            not isinstance(token, str) or not token or len(token) > 128 for token in pattern_tuple
        )
    ):
        raise ValueError("DVI-TEMPORAL-PATTERN: require 1..128 pattern tokens")
    _validate_precision(precision_digits)
    if len(ordered) < len(pattern_tuple):
        return _check(
            "sequence_order",
            ordered,
            "unknown",
            "The finite event set is shorter than the declared pattern.",
            expected=list(pattern_tuple),
            observed=[event.event_id for event in ordered],
            reason_codes=("event_evidence_missing",),
        )
    reasons = _time_reasons(ordered, precision_digits)
    cursor = 0
    matched: list[str] = []
    for event in ordered:
        if cursor < len(pattern_tuple) and _matches(event, pattern_tuple[cursor]):
            matched.append(event.event_id)
            cursor += 1
    result = cursor == len(pattern_tuple)
    matched_values: list[JsonValue] = list(matched)
    outcome: TemporalState = "unknown" if reasons else "supported" if result else "contradicted"
    return _check(
        "sequence_order",
        ordered,
        outcome,
        "The normalized event order contains the declared pattern."
        if result and not reasons
        else "Timestamp precision is below the declared requirement."
        if reasons
        else "The normalized event order does not contain the declared pattern.",
        expected=list(pattern_tuple),
        observed=matched_values,
        reason_codes=reasons,
    )


def _validate_window(window_ms: int) -> None:
    if (
        isinstance(window_ms, bool)
        or not isinstance(window_ms, int)
        or not 0 <= window_ms <= MAX_WINDOW_MS
    ):
        raise ValueError("DVI-TEMPORAL-WINDOW: require an integer window from 0 to 86400000 ms")


def _validate_precision(precision_digits: int) -> None:
    if (
        isinstance(precision_digits, bool)
        or not isinstance(precision_digits, int)
        or not 0 <= precision_digits <= 6
    ):
        raise ValueError("DVI-TEMPORAL-PRECISION: require 0..6 fractional digits")


def _trace(
    check: TemporalCheck, index: int, events_by_id: dict[str, TelemetryEvent]
) -> TemporalTrace:
    events = tuple(
        events_by_id[event_id] for event_id in check.event_ids if event_id in events_by_id
    )
    return TemporalTrace(
        trace_id="trace:" + digest({"index": index, "check": canonical_json(check)}),
        sequence_index=index,
        check=check,
        normalized_timestamps=tuple(_snapshot(event.timestamp) or "" for event in events),
        source_precision_digits=tuple(_precision(event) for event in events),
    )


def evaluate_temporal(
    events: Sequence[TelemetryEvent],
    *,
    window_ms: int = 1000,
    pattern: Sequence[str] = (),
    precision_digits: int = 0,
) -> TemporalSummary:
    """Run the ten finite predicates over actual events and retain every decision."""
    ordered = _events(events)
    _validate_precision(precision_digits)
    traces: list[TemporalCheck] = []
    if len(ordered) >= 2:
        left, right = ordered[0], ordered[1]
        traces.extend(
            [
                before(left, right),
                after(left, right),
                within(left, right, window_ms, precision_digits=precision_digits),
                same_entity(left, right),
                same_flow(left, right),
                same_correlation_key(left, right),
            ]
        )
    traces.append(at_least_k_of_n(ordered, 1, len(ordered)))
    if ordered:
        traces.append(no_contradictory_context(ordered))
    else:
        raise ValueError("DVI-TEMPORAL-EVIDENCE: at least one event is required")
    detections = [event for event in ordered if isinstance(event, DetectionEvent)]
    signal = next((event for event in ordered if not isinstance(event, DetectionEvent)), ordered[0])
    alert = detections[0] if detections else ordered[0]
    traces.append(alert_within_window(signal, alert, window_ms, precision_digits=precision_digits))
    traces.append(
        sequence_order(
            ordered, pattern or (ordered[0].semantics.category,), precision_digits=precision_digits
        )
    )
    events_by_id = {event.event_id: event for event in ordered}
    temporal_traces = tuple(
        _trace(check, index, events_by_id) for index, check in enumerate(traces)
    )
    correlation = tuple(
        CorrelationEvidence(
            key="correlation_id",
            event_ids=tuple(event.event_id for event in ordered),
            values_json=tuple(_snapshot(event.correlation_id) for event in ordered),
            outcome=(
                "unknown"
                if any(event.correlation_id is None for event in ordered)
                else "supported"
                if len({event.correlation_id for event in ordered}) == 1
                else "contradicted"
            ),
            explanation="Retained correlation IDs are compared without generating missing keys.",
        )
        for _ in (0,)
    )
    findings = tuple(
        SequenceFinding(
            finding_id="finding:" + digest(check),
            predicate=check.predicate,
            event_ids=check.event_ids,
            outcome=check.outcome,
            reason_codes=check.reason_codes,
            explanation=check.explanation,
        )
        for check in traces
    )
    outcomes = [item.check.outcome for item in temporal_traces]
    state: TemporalState = (
        "unknown"
        if "unknown" in outcomes
        else "contradicted"
        if "contradicted" in outcomes
        else "supported"
    )
    return TemporalSummary(
        input_digest=digest([event.stable_digest() for event in ordered]),
        ordered_event_ids=tuple(event.event_id for event in ordered),
        traces=temporal_traces,
        findings=findings,
        correlation_evidence=correlation,
        state=state,
    )


def temporal_artifacts(
    events: Sequence[TelemetryEvent],
    *,
    window_ms: int = 1000,
    pattern: Sequence[str] = (),
    precision_digits: int = 0,
) -> dict[str, bytes]:
    """Reevaluate actual events and emit four deterministic temporal artifacts."""
    summary = evaluate_temporal(
        events, window_ms=window_ms, pattern=pattern, precision_digits=precision_digits
    )
    artifacts = {
        "temporal_trace.jsonl": jsonl_bytes(item for item in summary.traces),
        "correlation_evidence.json": json_bytes(
            CorrelationEvidenceExport(
                input_digest=summary.input_digest, evidence=summary.correlation_evidence
            )
        ),
        "sequence_findings.json": json_bytes(
            SequenceFindingsExport(input_digest=summary.input_digest, findings=summary.findings)
        ),
        "temporal_summary.json": json_bytes(summary),
    }
    if sum(map(len, artifacts.values())) > MAX_FIXTURE_BYTES * 16:
        raise ValueError("DVI-TEMPORAL-BOUNDS: artifact set exceeds 32 MiB")
    return artifacts
