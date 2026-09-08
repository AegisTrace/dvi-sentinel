"""Local-only harness implementations; no external detector execution."""

from datetime import timedelta
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from dvi_sentinel.harness_models import (
    FixtureResults,
    HarnessIssue,
    HarnessRequest,
    HarnessResult,
    LocalRule,
    RuleCondition,
    RuleHarnessConfig,
    RuleTrace,
)
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.models import DetectionEvent, EventSemantics, Evidence, RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.serialization import digest, parse_json


class DetectorHarness(Protocol):
    def evaluate(self, request: HarnessRequest) -> HarnessResult:
        """Evaluate local input, returning complete observations or explicit unknown."""
        ...


class HarnessError(ValueError):
    def __init__(self, issue: HarnessIssue) -> None:
        self.issue = issue
        super().__init__(f"{issue.code}: {issue.explanation}")


def _preflight(request: HarnessRequest) -> HarnessResult | None:
    issue: HarnessIssue | None = None
    if request.capability != "local_fixture":
        issue = HarnessIssue(
            code="DVI-HARNESS-UNSUPPORTED", explanation="only local_fixture is supported"
        )
    elif len({event.event_id for event in request.events}) != len(request.events):
        issue = HarnessIssue(
            code="DVI-HARNESS-DUPLICATE-ID", explanation="input event IDs must be unique"
        )
    else:
        try:
            decisions = evaluate_events(request.events)
        except PolicyError as exc:
            decisions = exc.decisions
        if decisions:
            issue = HarnessIssue(
                code="DVI-HARNESS-POLICY", explanation=f"{decisions[0].rule_id} {decisions[0].path}"
            )
    if issue:
        return HarnessResult(case_id=request.case_id, status="unknown", issues=(issue,))
    return None


class FixtureHarness:
    """Explicit case mapping; missing case data never implies a measured miss."""

    def __init__(self, results: FixtureResults) -> None:
        self._results = results

    @classmethod
    def from_file(cls, root: Path, relative: str) -> "FixtureHarness":
        try:
            results = FixtureResults.model_validate(parse_json(read_fixture(root, relative)))
        except PolicyError:
            raise
        except (ValueError, RecursionError) as exc:
            raise HarnessError(
                HarnessIssue(
                    code="DVI-HARNESS-MALFORMED",
                    explanation="detector-result fixture must match FixtureResults schema",
                )
            ) from exc
        return cls(results)

    def evaluate(self, request: HarnessRequest) -> HarnessResult:
        rejected = _preflight(request)
        if rejected:
            return rejected
        for case in self._results.cases:
            if case.case_id == request.case_id:
                rejected = _preflight(
                    HarnessRequest(case_id=request.case_id, events=case.detections)
                )
                if rejected:
                    return rejected
                return HarnessResult(
                    case_id=request.case_id, status="complete", detections=case.detections
                )
        return HarnessResult(
            case_id=request.case_id,
            status="unknown",
            issues=(
                HarnessIssue(
                    code="DVI-HARNESS-NO-FIXTURE", explanation="no observation for requested case"
                ),
            ),
        )


def _field(event: TelemetryEvent, name: str) -> object:
    if name.startswith("raw."):
        value: object = event.raw.payload
        for key in name.split(".")[1:]:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value
    values: dict[str, object] = {
        "category": event.semantics.category,
        "action": event.semantics.action,
        "protocol": event.semantics.protocol,
        "severity": int(event.severity),
        "sensor": event.raw.sensor,
        "vendor": event.raw.vendor,
        "labels": event.labels,
        "tags": event.tags,
        "correlation_id": event.correlation_id,
        "timestamp_text": event.raw.original_timestamp,
    }
    return values[name]


def _condition(event: TelemetryEvent, condition: RuleCondition) -> bool:
    value = _field(event, condition.field)
    expected = condition.value
    match condition.operator:
        case "exists":
            return value is not None
        case "eq":
            return type(value) is type(expected) and value == expected
        case "contains":
            if isinstance(value, str) and isinstance(expected, str):
                return expected in value
            return isinstance(value, tuple | list) and expected in value
        case "gte":
            return (
                not isinstance(value, bool)
                and isinstance(value, int | float)
                and isinstance(expected, int | float)
                and value >= expected
            )


def _rule_result(
    rule: LocalRule, request: HarnessRequest
) -> tuple[DetectionEvent | None, RuleTrace]:
    candidates = tuple(
        event
        for event in request.events
        if all(_condition(event, condition) for condition in rule.conditions)
    )
    count = len(candidates)
    reason: str = "RULE_MATCH"
    if not candidates:
        reason = "RULE_CONDITION_MISS"
    elif (
        count < rule.min_count
        or (rule.max_count is not None and count > rule.max_count)
        or (rule.max_total_events is not None and len(request.events) > rule.max_total_events)
    ):
        reason = "RULE_COUNT_MISS"
    elif rule.require_time_order and list(candidates) != sorted(
        candidates, key=lambda e: e.timestamp
    ):
        reason = "RULE_ORDER_MISS"
    elif (
        rule.window_ms is not None
        and (
            max(e.timestamp for e in candidates) - min(e.timestamp for e in candidates)
        ).total_seconds()
        * 1000
        > rule.window_ms
    ):
        reason = "RULE_WINDOW_MISS"
    trace = RuleTrace.model_validate(
        {"rule_id": rule.id, "candidate_count": count, "reason": reason}
    )
    if reason != "RULE_MATCH":
        return None, trace
    related = tuple(sorted(event.event_id for event in candidates))
    correlation_ids = {event.correlation_id for event in candidates}
    correlation_id = next(iter(correlation_ids)) if len(correlation_ids) == 1 else None
    timestamp = max(event.timestamp for event in candidates) + timedelta(milliseconds=rule.delay_ms)
    detection = DetectionEvent.model_validate(
        {
            "event_id": "detection:"
            + digest({"case": request.case_id, "rule": rule.id, "events": list(related)})[:24],
            "timestamp": timestamp,
            "semantics": EventSemantics(category="alert", action="observed"),
            "raw": RawSource.from_payload(
                {"rule_id": rule.id, "matched_ids": list(related)}, adapter="rule_logic"
            ),
            "severity": rule.severity,
            "detector": rule.detector,
            "signature": rule.signature,
            "title": rule.title,
            "related_event_ids": related,
            "labels": rule.labels,
            "tags": rule.tags,
            "correlation_id": correlation_id,
            "evidence": (
                Evidence(path=f"rules.{rule.id}", description=f"{count} events satisfy local rule"),
            ),
        }
    )
    return detection, trace


class RuleLogicHarness:
    """Small declarative fixture rules, deliberately unsuitable for production detection."""

    def __init__(self, config: RuleHarnessConfig) -> None:
        self._config = config

    def evaluate(self, request: HarnessRequest) -> HarnessResult:
        rejected = _preflight(request)
        if rejected:
            return rejected
        detections: list[DetectionEvent] = []
        traces: list[RuleTrace] = []
        try:
            for rule in sorted(self._config.rules, key=lambda r: r.id):
                detection, trace = _rule_result(rule, request)
                traces.append(trace)
                if detection:
                    detections.append(detection)
            decisions = evaluate_events(tuple(detections))
            if decisions:
                raise PolicyError(decisions)
        except PolicyError as exc:
            return HarnessResult(
                case_id=request.case_id,
                status="unknown",
                issues=(
                    HarnessIssue(code="DVI-HARNESS-POLICY", explanation=exc.decisions[0].rule_id),
                ),
            )
        except (OverflowError, ValidationError) as exc:
            return HarnessResult(
                case_id=request.case_id,
                status="unknown",
                issues=(
                    HarnessIssue(
                        code="DVI-HARNESS-MALFORMED",
                        explanation=f"invalid local rule result: {type(exc).__name__}",
                    ),
                ),
            )
        return HarnessResult(
            case_id=request.case_id,
            status="complete",
            detections=tuple(detections),
            traces=tuple(traces),
        )
