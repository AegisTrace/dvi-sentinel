"""Bounded evidence support analysis for inert local detection declarations."""

import re

from pydantic import JsonValue

from dvi_sentinel.intent_models import (
    DetectionIntent,
    IntentAnalysis,
    IntentAssumption,
    IntentAssumptions,
    IntentCandidate,
    IntentCheck,
    IntentOperator,
    ParsedIntent,
    UnsupportedConditions,
    checks_state,
)
from dvi_sentinel.intent_parsing import check, validate_intent
from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES, MAX_SCENARIO_BYTES
from dvi_sentinel.models import DetectionEvent, TelemetryEvent, utc_timestamp
from dvi_sentinel.ontology import extract_signal
from dvi_sentinel.ontology_models import EvidenceBinding, FieldBinding, OntologyProfile
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.serialization import canonical_json, parse_json


def intent_assumptions(intent: DetectionIntent) -> tuple[IntentAssumption, ...]:
    """Expose cross-event requirements without claiming to evaluate them here."""
    items = list(intent.assumptions)
    if intent.correlation and intent.correlation.same_value_required:
        items.append(
            IntentAssumption(
                assumption_id="pending:correlation-equality",
                explanation="Cross-event key equality requires bounded correlation evaluation.",
                evidence_refs=(intent.correlation.field,),
                detail_json=canonical_json(intent.correlation),
            )
        )
    if intent.time_window:
        items.append(
            IntentAssumption(
                assumption_id="pending:time-window",
                explanation="Window membership and ordering require bounded sequence evaluation.",
                evidence_refs=(intent.time_window.timestamp_field,),
                detail_json=canonical_json(intent.time_window),
            )
        )
    return tuple(items)


def _operator_supported(operator: IntentOperator) -> bool:
    value = parse_json(operator.value_json) if operator.value_json is not None else None
    return (
        operator.name == "exists"
        or (operator.name in {"eq", "contains"} and value is not None)
        or (operator.name == "gte" and type(value) in (int, float))
    )


def _operate(field: str, operator: IntentOperator, observed: JsonValue) -> IntentCheck:
    expected = parse_json(operator.value_json) if operator.value_json is not None else None
    matches: bool | None = None
    if operator.name == "exists":
        matches = True
    elif operator.name == "eq":
        matches = canonical_json(expected) == canonical_json(observed)
    elif operator.name == "contains":
        if isinstance(observed, str) and isinstance(expected, str):
            matches = expected in observed
        elif isinstance(observed, list):
            matches = any(canonical_json(item) == canonical_json(expected) for item in observed)
    elif (
        operator.name == "gte"
        and isinstance(observed, int | float)
        and not isinstance(observed, bool)
        and isinstance(expected, int | float)
        and not isinstance(expected, bool)
    ):
        matches = observed >= expected
    return check(
        field,
        "unsupported_operator" if matches is None else "supported" if matches else "value_mismatch",
        "unknown" if matches is None else "supported" if matches else "contradicted",
        f"Literal {operator.name} comparison; incompatible types remain unknown.",
        expected,
        observed,
    )


def _global_checks(parsed: ParsedIntent) -> tuple[IntentCheck, ...]:
    intent = parsed.intent
    checks = list(parsed.unsupported)
    if intent.condition_shape != "all" or not intent.fields:
        checks.append(
            check(
                "condition_shape",
                "unsupported_condition_shape",
                "unknown",
                "Analysis requires a nonempty conjunction of declared field requirements.",
                "all",
                intent.condition_shape,
            )
        )
    for field in sorted(intent.fields, key=lambda item: item.field):
        for operator in field.operators:
            if not _operator_supported(operator):
                checks.append(
                    check(
                        field.field,
                        "unsupported_operator",
                        "unknown",
                        "Operator name or comparison value is outside the literal subset.",
                        observed=operator.model_dump(mode="json"),
                    )
                )
    checks.extend(
        check(
            assumption.assumption_id,
            "unsupported_condition_shape",
            "unknown",
            assumption.explanation,
            observed=parse_json(assumption.detail_json) if assumption.detail_json else None,
        )
        for assumption in intent_assumptions(intent)
        if assumption.requires_evaluation
    )
    return tuple(checks)


def _source_checks(intent: DetectionIntent, event: TelemetryEvent) -> list[IntentCheck]:
    observed: dict[str, JsonValue] = {
        "category": event.semantics.category,
        "adapter": event.raw.adapter,
        "sensor": event.raw.sensor,
        "vendor": event.raw.vendor,
    }
    source = event.raw.payload.get("logsource")
    for name in ("product", "service"):
        observed[name] = source.get(name) if isinstance(source, dict) else None
    checks = []
    for name, expected in intent.logsource.model_dump(mode="json", exclude_none=True).items():
        actual = observed[name]
        known = isinstance(actual, str) and bool(actual)
        # A non-DVI category needs a declared taxonomy mapping; never guess one.
        if name == "category" and expected not in {"flow", "dns", "http", "alert"}:
            known = False
        matches = known and actual == expected
        checks.append(
            check(
                "logsource." + name,
                "supported" if matches else "logsource_mismatch",
                "supported" if matches else "contradicted" if known else "unknown",
                "Compare explicit source metadata; absent or unmapped source context is unknown.",
                expected,
                actual,
            )
        )
    return checks


def _metadata_checks(intent: DetectionIntent, event: TelemetryEvent) -> list[IntentCheck]:
    checks = []
    detection = isinstance(event, DetectionEvent)
    if intent.severity:
        severity = intent.severity
        known = event.severity != 0 and (severity.scope == "input" or detection)
        matches = known and severity.minimum <= event.severity <= severity.maximum
        checks.append(
            check(
                "severity",
                "supported" if matches else "severity_mismatch",
                "supported" if matches else "contradicted" if known else "unknown",
                "Rule output severity requires detection evidence; zero is an unknown level.",
                severity.model_dump(mode="json"),
                event.severity if known else None,
            )
        )
    scoped = intent.metadata_scope == "input" or detection
    for field, expected, actual in (
        ("labels", intent.context_labels, event.labels),
        ("tags", intent.context_tags, event.tags),
        (
            "techniques",
            intent.technique_tags,
            event.techniques if isinstance(event, DetectionEvent) else event.tags,
        ),
    ):
        if expected:
            matches = scoped and set(expected).issubset(actual)
            checks.append(
                check(
                    field,
                    "supported"
                    if matches
                    else "technique_tag_dropped"
                    if field == "techniques"
                    else "metadata_context_dropped",
                    "supported" if matches else "unknown",
                    "Required context must be retained in the declared input/detection scope.",
                    list(sorted(expected)),
                    list(sorted(actual)) if scoped else None,
                )
            )
    paths = {item.path for item in event.evidence}
    for requirement in intent.evidence:
        present = requirement.path in paths
        checks.append(
            check(
                requirement.path,
                "supported"
                if present
                else "missing_required_field"
                if requirement.required
                else "optional_evidence_absent",
                "supported"
                if present
                else "unknown"
                if requirement.required
                else "optional_absent",
                "Evidence path association only; this does not authenticate source contents.",
                requirement.path,
                requirement.path if present else None,
            )
        )
    return checks


def _time_check(
    intent: DetectionIntent, event: TelemetryEvent, bindings: dict[str, EvidenceBinding]
) -> IntentCheck:
    window = intent.time_window
    assert window is not None
    binding = bindings[window.timestamp_field]
    observable = binding.observable
    value = parse_json(observable.value_json) if observable.value_json is not None else None
    source = value
    paths = binding.specification.paths
    if "timestamp" in paths:
        source = event.raw.original_timestamp if window.precision_digits else value
    elif "observed_at" in paths and window.precision_digits:
        source = None  # V1 has no retained source-resolution record for observation time.
    known = False
    if isinstance(value, str) and isinstance(source, str):
        match = re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,6}))?(?:Z|[+-]\d{2}:?\d{2})",
            source,
        )
        try:
            normalized_source = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", source)
            known = (
                match is not None
                and len(match.group(1) or "") >= window.precision_digits
                and utc_timestamp(value) == utc_timestamp(normalized_source)
            )
        except ValueError:
            pass
    return check(
        window.timestamp_field,
        "supported" if known else "time_window_unrepresentable",
        "supported" if known else "unknown",
        "Timestamp representation and retained fractional digits only; no sequence evaluation.",
        window.model_dump(mode="json"),
        source,
    )


def _candidate(intent: DetectionIntent, event: TelemetryEvent) -> IntentCandidate:
    profile = OntologyProfile(
        profile_id="intent:" + intent.stable_digest(),
        categories=("flow", "dns", "http", "alert"),
        bindings=tuple(item.binding() for item in intent.fields)
        or (FieldBinding(field="timestamp", paths=("timestamp",), required=False),),
    )
    extraction = extract_signal(event, profile)
    bindings = {item.specification.field: item for item in extraction.bindings}
    checks = _source_checks(intent, event) + _metadata_checks(intent, event)
    loss_codes = {
        "ambiguous_field_binding": "field_alias_ambiguity",
        "missing_required_evidence": "missing_required_field",
        "severity_semantic_loss": "severity_mismatch",
    }
    for finding in extraction.findings:
        checks.append(
            check(
                finding.field,
                loss_codes.get(finding.loss_class, "normalization_loss"),
                "unknown",
                finding.explanation,
            )
        )
    losses = {item.field for item in extraction.findings}
    for requirement in sorted(intent.fields, key=lambda item: item.field):
        observable = bindings[requirement.field].observable
        if observable.state == "missing" and not requirement.required:
            checks.append(
                check(
                    requirement.field,
                    "optional_evidence_absent",
                    "optional_absent",
                    "Optional field is absent; no value or match was invented.",
                )
            )
        if observable.state == "known" and requirement.field not in losses:
            assert observable.value_json is not None
            checks.extend(
                _operate(requirement.field, operator, parse_json(observable.value_json))
                for operator in requirement.operators
                if _operator_supported(operator)
            )
    if intent.correlation:
        observable = bindings[intent.correlation.field].observable
        known = observable.state == "known" and intent.correlation.field not in losses
        checks.append(
            check(
                intent.correlation.field,
                "supported" if known else "correlation_key_missing",
                "supported" if known else "unknown",
                "Correlation key availability only; cross-event equality is a separate check.",
                observed=parse_json(observable.value_json) if observable.value_json else None,
            )
        )
    if intent.time_window:
        checks.append(_time_check(intent, event, bindings))
    return IntentCandidate(
        event_id=event.event_id,
        event_digest=event.stable_digest(),
        bindings=extraction.bindings,
        checks=tuple(checks),
        state=checks_state(tuple(checks)),
    )


def analyze_intent(parsed: ParsedIntent, events: tuple[TelemetryEvent, ...]) -> IntentAnalysis:
    """Analyze existential single-event support, with unresolved global constraints blocking it."""
    if len(canonical_json(parsed).encode()) > MAX_SCENARIO_BYTES:
        raise ValueError("DVI-INTENT-BOUNDS: declaration exceeds 128 KiB")
    parsed = ParsedIntent.model_validate(parsed.model_dump())
    validate_intent(parsed.intent)
    if len(events) > 128 or len({item.event_id for item in events}) != len(events):
        raise ValueError("DVI-INTENT-BOUNDS: require 0..128 events with unique IDs")
    if sum(len(canonical_json(item).encode()) for item in events) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-INTENT-BOUNDS: combined events exceed 2 MiB")
    # Preserve and revalidate the concrete event subtype before any metadata checks.
    validated = tuple(
        (DetectionEvent if isinstance(item, DetectionEvent) else TelemetryEvent).model_validate(
            item.model_dump(mode="json")
        )
        for item in events
    )
    candidates = tuple(
        _candidate(parsed.intent, item)
        for item in sorted(validated, key=lambda item: item.event_id)
    )
    global_checks = _global_checks(parsed)
    if not candidates:
        global_checks += (
            check("events", "missing_required_field", "unknown", "No telemetry was supplied."),
        )
    return IntentAnalysis(
        parsed=parsed,
        candidates=candidates,
        global_checks=global_checks,
        state=IntentAnalysis.derive_state(candidates, global_checks),
    )


def intent_artifacts(parsed: ParsedIntent, events: tuple[TelemetryEvent, ...]) -> dict[str, bytes]:
    """Reevaluate actual inputs and export four deterministic, bounded evidence views."""
    analysis = analyze_intent(parsed, events)
    unsupported = tuple(
        item
        for item in (*analysis.global_checks, *(c for r in analysis.candidates for c in r.checks))
        if item.code in {"unsupported_operator", "unsupported_condition_shape"}
    )
    files = {
        "detection_intent.json": json_bytes(analysis.parsed),
        "semantic_loss_report.json": json_bytes(analysis),
        "unsupported_conditions.json": json_bytes(
            UnsupportedConditions(source_digest=analysis.parsed.source_digest, checks=unsupported)
        ),
        "intent_assumptions.json": json_bytes(
            IntentAssumptions(
                intent_id=analysis.parsed.intent.intent_id,
                assumptions=intent_assumptions(analysis.parsed.intent),
            )
        ),
    }
    if sum(map(len, files.values())) > 32 * 1024 * 1024:
        raise ValueError("DVI-INTENT-BOUNDS: artifact set exceeds 32 MiB")
    return files
