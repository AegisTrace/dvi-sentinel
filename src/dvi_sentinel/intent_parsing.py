"""Bounded declarative intent parsing; unsupported expressions remain inert evidence."""

import hashlib
from typing import cast

from pydantic import JsonValue, TypeAdapter

from dvi_sentinel.harness_models import LocalRule
from dvi_sentinel.intent_models import (
    DetectionIntent,
    IntentAssumption,
    IntentCheck,
    IntentFieldRequirement,
    IntentFormat,
    IntentLogsource,
    IntentOperator,
    IntentSeverityExpectation,
    IntentTimeWindow,
    ParsedIntent,
)
from dvi_sentinel.ontology import CANONICAL_PATHS
from dvi_sentinel.policy import PolicyError, inspect_content
from dvi_sentinel.scenario_io import parse_local_yaml
from dvi_sentinel.serialization import canonical_json, digest, parse_json

FIELD_ALIASES = {
    "category": "semantics.category",
    "action": "semantics.action",
    "protocol": "semantics.protocol",
    "sensor": "raw.sensor",
    "vendor": "raw.vendor",
    "timestamp_text": "raw.original_timestamp",
    "dns_name": "semantics.dns_name",
    "http_method": "semantics.http_method",
    "http_path": "semantics.http_path",
    "src_ip": "semantics.source.address",
    "dest_ip": "semantics.destination.address",
}


def check(
    field: str,
    code: str,
    outcome: str,
    explanation: str,
    expected: JsonValue = None,
    observed: JsonValue = None,
) -> IntentCheck:
    return IntentCheck.model_validate(
        {
            "field": field,
            "code": code,
            "outcome": outcome,
            "explanation": explanation,
            "expected_json": canonical_json(expected) if expected is not None else None,
            "observed_json": canonical_json(observed) if observed is not None else None,
        }
    )


def validate_intent(intent: DetectionIntent) -> DetectionIntent:
    intent = DetectionIntent.model_validate(intent.model_dump())
    decisions = list(inspect_content(intent.model_dump(mode="json")))
    for requirement in intent.fields:
        for operator in requirement.operators:
            if operator.value_json is not None:
                value = parse_json(operator.value_json)
                for path in requirement.paths:
                    # Treat network literals as network evidence only when the
                    # selector names an address/host field.  A contains value
                    # such as "example" is an inert scalar, not a hostname.
                    leaf = path.split(".")[-1]
                    key = (
                        leaf
                        if operator.name == "eq"
                        and leaf in {"address", "dns_name", "hostname", "domain", "url", "uri"}
                        else "value"
                    )
                    decisions.extend(inspect_content({key: value}, requirement.field))
    for assumption in intent.assumptions:
        if assumption.detail_json is not None:
            decisions.extend(
                inspect_content(parse_json(assumption.detail_json), assumption.assumption_id)
            )
    if decisions:
        raise PolicyError(tuple(decisions))
    return intent


def _path(field: str) -> str:
    if field in FIELD_ALIASES:
        return FIELD_ALIASES[field]
    if field in CANONICAL_PATHS or field.startswith("raw.payload."):
        return field
    if field.startswith("raw."):
        return "raw.payload." + field.removeprefix("raw.")
    return field  # A syntactically valid unsupported selector stays unknown during binding.


def _group(items: list[tuple[str, IntentOperator]]) -> tuple[IntentFieldRequirement, ...]:
    groups: dict[str, list[IntentOperator]] = {}
    for field, operator in items:
        groups.setdefault(field, []).append(operator)
    return tuple(
        IntentFieldRequirement(field=field, paths=(_path(field),), operators=tuple(operators))
        for field, operators in sorted(groups.items())
    )


def intent_from_rule(rule: LocalRule) -> ParsedIntent:
    rule = LocalRule.model_validate(rule.model_dump())
    decisions = inspect_content(rule.model_dump(mode="json"))
    if decisions:
        raise PolicyError(decisions)
    fields = _group(
        [
            (
                condition.field,
                IntentOperator(
                    name=condition.operator,
                    value_json=canonical_json(condition.value)
                    if condition.operator != "exists"
                    else None,
                ),
            )
            for condition in rule.conditions
        ]
    )
    assumptions = [
        IntentAssumption(
            assumption_id="rule-output-identity",
            requires_evaluation=False,
            explanation="Declared detector output identity; not an input-event source constraint.",
            detail_json=canonical_json({"detector": rule.detector, "signature": rule.signature}),
        )
    ]
    constraints: dict[str, JsonValue] = {}
    for name in ("min_count", "max_count", "max_total_events", "require_time_order", "delay_ms"):
        value = rule.model_dump(mode="json")[name]
        if value not in (None, False, 0) and not (name == "min_count" and value == 1):
            constraints[name] = value
    if constraints:
        assumptions.append(
            IntentAssumption(
                assumption_id="rule-sequence-and-count",
                detail_json=canonical_json(constraints),
                explanation="Count/order/delay constraints require a bounded sequence evaluator.",
            )
        )
    window = None
    if rule.window_ms is not None:
        if not any(field.field == "timestamp" for field in fields):
            fields = (*fields, IntentFieldRequirement(field="timestamp", paths=("timestamp",)))
        window = IntentTimeWindow(
            duration_ms=rule.window_ms,
            timestamp_field="timestamp",
            order_required=rule.require_time_order,
        )
    intent = DetectionIntent(
        intent_id=rule.id,
        title=rule.title,
        fields=fields,
        time_window=window,
        severity=IntentSeverityExpectation(
            minimum=rule.severity, maximum=rule.severity, scope="detection"
        ),
        context_labels=rule.labels,
        context_tags=rule.tags,
        metadata_scope="detection",
        assumptions=tuple(assumptions),
    )
    return ParsedIntent(
        source_format="v1_rule", source_digest=digest(rule), intent=validate_intent(intent)
    )


def _sigma(data: dict[str, JsonValue]) -> tuple[DetectionIntent, tuple[IntentCheck, ...]]:
    unsupported = []
    allowed = {
        "title",
        "id",
        "taxonomy",
        "logsource",
        "detection",
        "level",
        "tags",
        "fields",
        "description",
    }
    for name in sorted(set(data) - allowed):
        unsupported.append(
            check(
                name,
                "metadata_context_dropped",
                "unknown",
                "Metadata has no interpretation in this local subset.",
                observed=data[name],
            )
        )
    taxonomy = data.get("taxonomy", "sigma")
    if taxonomy != "dvi":
        unsupported.append(
            check(
                "taxonomy",
                "unsupported_condition_shape",
                "unknown",
                "Only explicitly declared dvi field taxonomy is interpreted.",
                "dvi",
                taxonomy,
            )
        )
    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        unsupported.append(
            check(
                "logsource",
                "logsource_mismatch",
                "unknown",
                "An explicit logsource object is required.",
            )
        )
        logsource = {}
    supported_source = {
        name: value for name, value in logsource.items() if name in IntentLogsource.model_fields
    }
    for name in sorted(set(logsource) - set(supported_source)):
        unsupported.append(
            check(
                "logsource." + name,
                "metadata_context_dropped",
                "unknown",
                "Unsupported logsource metadata was retained as a diagnostic.",
                observed=logsource[name],
            )
        )
    selection = data.get("detection")
    items: list[tuple[str, IntentOperator]] = []
    condition_supported = False
    if isinstance(selection, dict):
        condition = selection.get("condition")
        candidates = [name for name in selection if name != "condition"]
        if (
            isinstance(condition, str)
            and candidates == [condition]
            and isinstance(selection[condition], dict)
        ):
            condition_supported = True
            for raw_name, value in sorted(cast(dict[str, JsonValue], selection[condition]).items()):
                name, *modifiers = raw_name.split("|")
                if isinstance(value, list | dict) or value is None:
                    unsupported.append(
                        check(
                            raw_name,
                            "unsupported_condition_shape",
                            "unknown",
                            "Only flat non-null scalar selection values are interpreted.",
                            observed=value,
                        )
                    )
                    continue
                operator = (
                    modifiers[0]
                    if len(modifiers) == 1
                    else "eq"
                    if not modifiers
                    else "multiple_modifiers"
                )
                if operator == "exists" and value is not True:
                    operator = "not_exists"
                if (
                    operator == "eq"
                    and isinstance(value, str)
                    and any(c in value for c in ("*", "?"))
                ):
                    operator = "wildcard"
                # Unsupported selector syntax is a diagnostic rather than a dynamic lookup.
                try:
                    item = IntentFieldRequirement(
                        field=name,
                        paths=(_path(name),),
                        operators=(
                            IntentOperator(
                                name=operator,
                                value_json=None if operator == "exists" else canonical_json(value),
                            ),
                        ),
                    )
                except ValueError:
                    unsupported.append(
                        check(
                            raw_name,
                            "unsupported_condition_shape",
                            "unknown",
                            "Field/modifier syntax is outside the local selector contract.",
                            observed=value,
                        )
                    )
                    continue
                items.append((name, item.operators[0]))
    if not condition_supported:
        unsupported.append(
            check(
                "detection.condition",
                "unsupported_condition_shape",
                "unknown",
                "Expected one flat selection and a condition naming only that selection.",
                observed=selection,
            )
        )
    severity = None
    if "level" in data:
        levels = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        level = data["level"]
        if isinstance(level, str) and level in levels:
            severity = IntentSeverityExpectation(
                minimum=levels[level], maximum=levels[level], scope="detection"
            )
        else:
            unsupported.append(
                check(
                    "level",
                    "severity_mismatch",
                    "unknown",
                    "Rule level is outside the declared subset.",
                    observed=level,
                )
            )
    tags = data.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("DVI-INTENT-TAGS: tags must be a string array")
    assumptions = tuple(
        IntentAssumption(
            assumption_id="metadata:" + name,
            requires_evaluation=False,
            explanation="Retained descriptive metadata; not an executable condition.",
            detail_json=canonical_json(data[name]),
        )
        for name in ("description", "fields")
        if name in data
    )
    intent = DetectionIntent.model_validate(
        {
            "intent_id": data.get("id", "intent:" + digest(data)),
            "title": data.get("title"),
            "fields": _group(items),
            "logsource": IntentLogsource.model_validate(supported_source),
            "severity": severity,
            "metadata_scope": "detection",
            "assumptions": assumptions,
            "technique_tags": [
                tag for tag in tags if isinstance(tag, str) and tag.startswith("attack.")
            ],
            "context_tags": [
                tag for tag in tags if isinstance(tag, str) and not tag.startswith("attack.")
            ],
        }
    )
    return intent, tuple(unsupported)


def parse_intent(text: str, source_format: IntentFormat = "dvi") -> ParsedIntent:
    data: JsonValue = TypeAdapter(JsonValue).validate_python(parse_local_yaml(text, kind="intent"))
    if not isinstance(data, dict):
        raise ValueError("DVI-INTENT-SCHEMA: expected an object")
    unsupported: tuple[IntentCheck, ...] = ()
    if source_format == "dvi":
        intent = DetectionIntent.model_validate(data)
    elif source_format == "sigma_metadata":
        intent, unsupported = _sigma(data)
    elif source_format == "v1_rule":
        intent = intent_from_rule(LocalRule.model_validate(data)).intent
    else:
        raise ValueError("DVI-INTENT-FORMAT: unsupported source format")
    return ParsedIntent(
        source_format=source_format,
        source_digest=hashlib.sha256(text.encode()).hexdigest(),
        intent=validate_intent(intent),
        unsupported=unsupported,
    )
