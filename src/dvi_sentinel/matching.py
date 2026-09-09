"""Conjunctive evidence checks within candidates, existential matching across candidates."""

from pydantic import JsonValue

from dvi_sentinel.harness_models import HarnessResult
from dvi_sentinel.match_models import CandidateMatch, MatchComparison, MatchReason, MatchResult
from dvi_sentinel.models import DetectionEvent, TelemetryEvent
from dvi_sentinel.scenario import DetectionExpectation
from dvi_sentinel.variation_models import SemanticPreservationResult


def _candidate(
    expected: DetectionExpectation,
    detection: DetectionEvent,
    events: tuple[TelemetryEvent, ...],
) -> CandidateMatch:
    checks: list[MatchComparison] = []

    def compare(
        field: str,
        wanted: JsonValue,
        actual: JsonValue,
        passed: bool,
        reason: MatchReason,
        *,
        missing: bool = False,
        unknown: bool = False,
    ) -> None:
        checks.append(
            MatchComparison(
                field=field,
                expected=wanted,
                observed=actual,
                outcome="unknown"
                if unknown
                else "missing"
                if missing
                else "pass"
                if passed
                else "contradiction",
                reason="DVI-MATCH-DETECTED" if passed and not unknown and not missing else reason,
            )
        )

    data = detection.model_dump(mode="json")
    for field in expected.required_fields:
        value = data[field]
        absent = value is None or value == "" or value == [] or (field == "severity" and value == 0)
        compare(
            f"required/{field}",
            "present",
            value,
            not absent,
            "DVI-MATCH-MISSING-FIELD",
            missing=absent,
        )
    compare(
        "detector",
        expected.detector,
        detection.detector,
        detection.detector == expected.detector,
        "DVI-MATCH-SOURCE",
    )
    if expected.source_adapter is not None:
        compare(
            "source_adapter",
            expected.source_adapter,
            detection.raw.adapter,
            detection.raw.adapter == expected.source_adapter,
            "DVI-MATCH-SOURCE",
        )
    if expected.signature is not None:
        compare(
            "signature",
            expected.signature,
            detection.signature,
            expected.signature == detection.signature,
            "DVI-MATCH-SIGNATURE",
        )
    if expected.signature_contains is not None:
        compare(
            "signature_contains",
            expected.signature_contains,
            detection.signature,
            expected.signature_contains in detection.signature,
            "DVI-MATCH-SIGNATURE",
        )
    if expected.title_contains is not None:
        compare(
            "title_contains",
            expected.title_contains,
            detection.title,
            expected.title_contains in detection.title,
            "DVI-MATCH-TITLE",
        )
    compare(
        "severity",
        expected.min_severity,
        int(detection.severity),
        detection.severity >= expected.min_severity,
        "DVI-MATCH-SEVERITY",
    )
    metadata_checks: tuple[tuple[str, MatchReason], ...] = (
        ("labels", "DVI-MATCH-LABEL"),
        ("tags", "DVI-MATCH-TAG"),
        ("techniques", "DVI-MATCH-TECHNIQUE"),
    )
    for metadata_field, reason in metadata_checks:
        wanted = getattr(expected, metadata_field)
        actual = getattr(detection, metadata_field)
        if wanted:
            compare(metadata_field, list(wanted), list(actual), set(wanted) <= set(actual), reason)
    if expected.event_ids:
        compare(
            "event_ids",
            list(expected.event_ids),
            list(detection.related_event_ids),
            set(expected.event_ids) <= set(detection.related_event_ids),
            "DVI-MATCH-EVENT-ID",
            missing=not detection.related_event_ids,
        )
    if expected.correlation_id is not None:
        compare(
            "correlation_id",
            expected.correlation_id,
            detection.correlation_id,
            expected.correlation_id == detection.correlation_id,
            "DVI-MATCH-CORRELATION",
            missing=detection.correlation_id is None,
        )
    reference = expected.reference_time
    if reference is None:
        ids = expected.event_ids or detection.related_event_ids
        indexed = {event.event_id: event for event in events}
        if ids and set(ids) <= indexed.keys():
            reference = max(indexed[event_id].timestamp for event_id in ids)
        elif not ids and len(events) == 1:
            reference = events[0].timestamp
    delay = (detection.timestamp - reference).total_seconds() * 1000 if reference else None
    time_reason: MatchReason = (
        "DVI-MATCH-TIME-REFERENCE"
        if delay is None
        else "DVI-MATCH-EARLY"
        if delay < 0
        else "DVI-MATCH-LATE"
    )
    compare(
        "alert_delay_ms",
        {"min": 0, "max": expected.max_delay_ms},
        delay,
        delay is not None and 0 <= delay <= expected.max_delay_ms,
        time_reason,
        unknown=delay is None,
    )
    failures = [check for check in checks if check.outcome in {"missing", "contradiction"}]
    unknowns = [check for check in checks if check.outcome == "unknown"]
    return CandidateMatch(
        event_id=detection.event_id,
        status="missed" if failures else "unknown" if unknowns else "detected",
        reason=failures[0].reason
        if failures
        else unknowns[0].reason
        if unknowns
        else "DVI-MATCH-DETECTED",
        alert_delay_ms=delay,
        comparisons=tuple(checks),
        missing_evidence=tuple(
            check.field for check in checks if check.outcome in {"missing", "unknown"}
        ),
        contradictory_evidence=tuple(
            check.field for check in failures if check.outcome == "contradiction"
        ),
        evidence_completeness=sum(check.outcome in {"pass", "contradiction"} for check in checks)
        / len(checks),
    )


def match_detection(
    expected: DetectionExpectation,
    observed: HarnessResult,
    events: tuple[TelemetryEvent, ...] = (),
    *,
    parser_success: bool = True,
    preservation: SemanticPreservationResult | None = None,
) -> MatchResult:
    """Unknown guards take precedence over all otherwise matching observations."""

    def unknown(reason: MatchReason, explanation: str) -> MatchResult:
        return MatchResult(
            case_id=observed.case_id, status="unknown", reason=reason, explanation=explanation
        )

    if preservation is not None and not preservation.valid:
        return unknown(
            "DVI-MATCH-INVARIANT", "Semantic invariant failed; observation is ineligible"
        )
    if not parser_success:
        return unknown("DVI-MATCH-NORMALIZATION", "Parsing/normalization is incomplete")
    if observed.status != "complete":
        return unknown("DVI-MATCH-HARNESS", "Harness observation is unavailable or rejected")
    if expected.signature is not None and expected.signature_contains is not None:
        return unknown(
            "DVI-MATCH-AMBIGUOUS-EXPECTATION", "Choose exact signature or containment, not both"
        )
    if any(
        len(set(values)) != len(values)
        for values in (
            expected.labels,
            expected.tags,
            expected.techniques,
            expected.event_ids,
            expected.required_fields,
        )
    ):
        return unknown(
            "DVI-MATCH-AMBIGUOUS-EXPECTATION", "Expectation contains repeated set members"
        )
    if len({d.event_id for d in observed.detections}) != len(observed.detections) or len(
        {event.event_id for event in events}
    ) != len(events):
        return unknown(
            "DVI-MATCH-AMBIGUOUS-OBSERVATION",
            "Repeated event IDs prevent unique evidence attribution",
        )
    candidates = tuple(
        _candidate(expected, detection, events)
        for detection in sorted(observed.detections, key=lambda d: d.event_id)
        if detection.detector == expected.detector
    )
    if not candidates:
        return MatchResult(
            case_id=observed.case_id,
            status="missed",
            reason="DVI-MATCH-NO-CANDIDATE",
            explanation="No observation has the configured detector identity",
        )
    detected = tuple(candidate for candidate in candidates if candidate.status == "detected")
    uncertain = tuple(candidate for candidate in candidates if candidate.status == "unknown")
    # Deterministic representative evidence; no weighted confidence can override any hard check.
    decisive = min(
        detected or uncertain or candidates,
        key=lambda c: (
            len(c.missing_evidence) + len(c.contradictory_evidence),
            c.event_id,
        ),
    )
    delays = [c.alert_delay_ms for c in detected if c.alert_delay_ms is not None]
    return MatchResult(
        case_id=observed.case_id,
        status=decisive.status,
        reason=decisive.reason,
        explanation="At least one candidate passes every configured check"
        if detected
        else "No proven match; at least one candidate lacks decisive evidence"
        if uncertain
        else "Every candidate fails at least one configured check",
        matching_event_ids=tuple(c.event_id for c in detected),
        alert_delay_ms=min(delays) if delays else decisive.alert_delay_ms,
        candidates=candidates,
        missing_evidence=decisive.missing_evidence,
        contradictory_evidence=decisive.contradictory_evidence,
        evidence_completeness=decisive.evidence_completeness,
    )
