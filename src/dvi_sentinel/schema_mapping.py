"""Pure loss-aware profile projection, normalization and bounded roundtrip evidence."""

from typing import Literal, cast

from pydantic import JsonValue, ValidationError

from dvi_sentinel.adapter_mapping import normalize_record
from dvi_sentinel.fixture_encoding import EncodingError, encode_fixture
from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES
from dvi_sentinel.mapping_codecs import convert
from dvi_sentinel.mapping_models import (
    AliasEdge,
    AliasGraph,
    FieldProjection,
    FieldTrace,
    LossExport,
    LossRecord,
    MappingExport,
    MappingIssue,
    MappingRoundtrip,
    ProfileId,
    ProfileNormalization,
    ProfileProjection,
    RoundtripExport,
    RoundtripSummary,
)
from dvi_sentinel.models import (
    DetectionEvent,
    RawSource,
    TelemetryEvent,
    ValidationWarning,
    utc_timestamp,
)
from dvi_sentinel.ontology import extract_signal, semantic_equivalence
from dvi_sentinel.policy import PolicyError, inspect_content
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.schema_profiles import PROFILE_IDS, schema_profile
from dvi_sentinel.serialization import canonical_json, digest, parse_json

JsonObject = dict[str, JsonValue]
REQUIRED = ("event_id", "timestamp", "semantics.category", "semantics.action")
PROVENANCE = {
    "raw.adapter",
    "raw.payload_json",
    "raw.raw_digest",
    "raw.record_index",
    "raw.original_timestamp",
}


def _get(data: JsonObject, path: tuple[str, ...]) -> JsonValue:
    current: JsonValue = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _put(data: JsonObject, path: tuple[str, ...], value: JsonValue) -> None:
    current = data
    for key in path[:-1]:
        if key not in current:
            current[key] = {}
        child = current[key]
        if not isinstance(child, dict):
            raise ValueError("DVI-MAPPING-PATH: conflicting object structure")
        current = child
    current[path[-1]] = value


def _leaves(data: JsonObject, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], JsonValue]:
    if len(path) > 16:
        raise ValueError("DVI-MAPPING-BOUNDS: object depth exceeds 16")
    result: dict[tuple[str, ...], JsonValue] = {}
    for key, value in sorted(data.items()):
        if isinstance(value, dict) and value:
            result.update(_leaves(value, (*path, key)))
        else:
            result[(*path, key)] = value
        if len(result) > 256:
            raise ValueError("DVI-MAPPING-BOUNDS: at most 256 leaf fields")
    return result


def _issue(code: str, field: str, explanation: str, impact: str = "unknown") -> MappingIssue:
    return MappingIssue.model_validate(
        {"code": code, "field": field, "impact": impact, "explanation": explanation}
    )


def _ordered(issues: list[MappingIssue]) -> tuple[MappingIssue, ...]:
    return tuple(sorted(set(issues), key=lambda item: (item.field, item.code, item.explanation)))


def _event(value: TelemetryEvent) -> TelemetryEvent:
    model = DetectionEvent if isinstance(value, DetectionEvent) else TelemetryEvent
    validated = model.model_validate(value.model_dump())
    extract_signal(validated)  # Existing size, strict model and fixture-policy boundary.
    return validated


def _inventory(event: TelemetryEvent) -> dict[str, JsonValue]:
    data = _leaves(event.model_dump(mode="json"))
    return {
        ".".join(path): value
        for path, value in data.items()
        if ".".join(path) not in PROVENANCE
        and path != ("schema_version",)
        and value is not None
        and value != []
        and value != {}
    }


def _applicable(field: FieldProjection, profile_id: ProfileId, category: JsonValue) -> bool:
    if profile_id != "suricata_eve":
        return True
    name = field.canonical_field
    return not (
        (name == "severity" and category != "alert")
        or (name == "semantics.dns_name" and category != "dns")
        or (name in {"semantics.http_method", "semantics.http_path"} and category != "http")
    )


def project_profile(event: TelemetryEvent, profile_id: ProfileId) -> ProfileProjection:
    source = _event(event)
    profile = schema_profile(profile_id)
    data = source.model_dump(mode="json")
    payload: JsonObject = {}
    traces = []
    issues: list[MappingIssue] = []
    mapped: set[str] = set()
    for field in profile.fields:
        value = _get(data, tuple(field.canonical_field.split(".")))
        if (
            value is None
            or value == []
            or not _applicable(field, profile_id, source.semantics.category)
        ):
            continue
        try:
            target, loss = convert(value, field.codec)
        except ValueError as exc:
            issues.append(_issue("unmapped_field", field.canonical_field, str(exc), "loss"))
            continue
        _put(payload, field.path, target)
        mapped.add(field.canonical_field)
        traces.append(
            FieldTrace(
                canonical_field=field.canonical_field,
                profile_paths=(field.path,),
                source_json=canonical_json(value),
                target_json=canonical_json(target),
                state="lossy" if loss else "mapped",
            )
        )
        if loss:
            issues.append(
                _issue(
                    "timestamp_precision_loss"
                    if field.canonical_field in {"timestamp", "observed_at"}
                    else "severity_mapping_drift",
                    field.canonical_field,
                    "The selected profile cannot retain the original value exactly.",
                    "loss",
                )
            )
    if profile_id == "dvi":
        payload = data  # Preserve the complete canonical event, including original raw evidence.
    else:
        for name, value in _inventory(source).items():
            if name not in mapped and not (name == "severity" and value == 0):
                issues.append(
                    _issue(
                        "unmapped_field", name, "No retained value in this profile subset.", "loss"
                    )
                )
                traces.append(
                    FieldTrace(
                        canonical_field=name,
                        profile_paths=(),
                        source_json=canonical_json(value),
                        target_json=None,
                        state="unmapped",
                    )
                )
    if profile_id == "suricata_eve":
        # Reuse V1's encoder for the representable event subset, with explicit losses above.
        semantics = source.semantics.model_dump()
        if source.semantics.category != "dns":
            semantics["dns_name"] = None
        if source.semantics.category != "http":
            semantics.update(http_method=None, http_path=None)
        narrowed = TelemetryEvent.model_validate(
            {
                key: value
                for key, value in source.model_dump().items()
                if key in TelemetryEvent.model_fields
            }
            | {
                "semantics": semantics,
                "observed_at": None,
                "confidence": None,
                "entities": (),
                "evidence": (),
                "severity": min(int(source.severity), 4)
                if source.semantics.category == "alert"
                else 0,
            }
        )
        try:
            payload = cast(JsonObject, parse_json(encode_fixture((narrowed,), "suricata_eve")))
        except EncodingError:
            # Unknown/informational alert severity has no EVE entry; do not guess a level.
            payload.setdefault("alert", {"action": source.semantics.action})
    if profile.metadata_only:
        issues.append(
            _issue("metadata_only", "profile", "Rule metadata does not identify an observed event.")
        )
    encoded = canonical_json(payload)
    if len(encoded.encode()) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-MAPPING-BOUNDS: profile payload exceeds 2 MiB")
    return ProfileProjection(
        profile_id=profile_id,
        source_digest=source.stable_digest(),
        payload_json=encoded,
        fields=tuple(traces),
        issues=_ordered(issues),
    )


def normalize_profile(content: str | bytes, profile_id: ProfileId) -> ProfileNormalization:
    profile = schema_profile(profile_id)
    if len(content if isinstance(content, bytes) else content.encode()) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-MAPPING-BOUNDS: profile payload exceeds 2 MiB")
    payload = parse_json(content)
    if not isinstance(payload, dict):
        raise ValueError("DVI-MAPPING-PAYLOAD: expected a JSON object")
    leaves = _leaves(payload)
    rejected = inspect_content(payload)
    if rejected:
        raise PolicyError(rejected)
    issues: list[MappingIssue] = []
    traces = []
    data: JsonObject = {}
    consumed: set[tuple[str, ...]] = set()
    for field in profile.fields:
        paths = (field.path, *field.aliases)
        for path in paths:
            consumed.update(leaf for leaf in leaves if leaf[: len(path)] == path)
        values = [(path, _get(payload, path)) for path in paths if _get(payload, path) is not None]
        if not values:
            continue
        for path, candidate_value in values:
            decisions = inspect_content(
                {field.canonical_field.split(".")[-1]: candidate_value}, "/".join(path)
            )
            if decisions:
                raise PolicyError(decisions)
        candidates = {canonical_json(value) for _, value in values}
        if len(candidates) != 1:
            issues.append(
                _issue(
                    "alias_ambiguity",
                    field.canonical_field,
                    "Present aliases disagree before conversion.",
                )
            )
            traces.append(
                FieldTrace(
                    canonical_field=field.canonical_field,
                    profile_paths=tuple(path for path, _ in values),
                    source_json=canonical_json([value for _, value in values]),
                    target_json=None,
                    state="unknown",
                )
            )
            continue
        observed = values[0][1]
        try:
            value, loss = convert(observed, field.codec, inverse=True)
            _put(data, tuple(field.canonical_field.split(".")), value)
            if loss:
                issues.append(
                    _issue(
                        "timestamp_precision_loss",
                        field.canonical_field,
                        "Source timestamp exceeds canonical microsecond precision.",
                        "loss",
                    )
                )
            traces.append(
                FieldTrace(
                    canonical_field=field.canonical_field,
                    profile_paths=tuple(path for path, _ in values),
                    source_json=canonical_json(observed),
                    target_json=canonical_json(value),
                    state="lossy" if loss else "mapped",
                )
            )
        except ValueError as exc:
            issues.append(_issue("invalid_value", field.canonical_field, str(exc)))
            traces.append(
                FieldTrace(
                    canonical_field=field.canonical_field,
                    profile_paths=tuple(path for path, _ in values),
                    source_json=canonical_json(observed),
                    target_json=None,
                    state="unknown",
                )
            )
    for path in sorted(set(leaves) - consumed):
        if profile_id == "suricata_eve" and path == ("flow",) and leaves[path] == {}:
            continue
        issues.append(
            _issue(
                "unsupported_field", "/".join(path), "Field is outside the declared local subset."
            )
        )
    event: TelemetryEvent | None = None
    if profile.metadata_only:
        issues.append(
            _issue(
                "metadata_only", "profile", "Rule metadata cannot reconstruct an observed event."
            )
        )
    if profile_id != "dvi":
        for required_field in REQUIRED:
            if _get(data, tuple(required_field.split("."))) in (None, ""):
                issues.append(
                    _issue(
                        "missing_required_field",
                        required_field,
                        "Canonical event evidence is unavailable.",
                    )
                )
    can_construct = not any(
        i.code in {"alias_ambiguity", "missing_required_field", "invalid_value", "metadata_only"}
        for i in issues
    )
    if can_construct:
        try:
            if profile_id == "dvi":
                model = DetectionEvent if "detector" in payload else TelemetryEvent
                event = _event(model.model_validate(payload))
            elif profile_id == "suricata_eve":
                event = _event(normalize_record(payload, "suricata_eve", 1))
            else:
                original = data.get("timestamp")
                raw_metadata = data.pop("raw", {})
                data["raw"] = RawSource.from_payload(
                    payload,
                    adapter=profile_id,
                    original_timestamp=original if isinstance(original, str) else None,
                    sensor=cast(str | None, raw_metadata.get("sensor"))
                    if isinstance(raw_metadata, dict)
                    else None,
                    vendor=cast(str | None, raw_metadata.get("vendor"))
                    if isinstance(raw_metadata, dict)
                    else None,
                ).model_dump(mode="json")
                event = _event(TelemetryEvent.model_validate(data))
            for finding in extract_signal(event).findings:
                issues.append(_issue("invalid_value", finding.field, finding.explanation))
        except (ValueError, TypeError) as exc:
            if isinstance(exc, PolicyError):
                raise
            explanation = "Canonical validation rejected the projected record."
            if not isinstance(exc, ValidationError):
                explanation = str(exc)[:1024]
            issues.append(_issue("invalid_value", "event", explanation))
            event = None
    if event is not None:
        normalized_data = event.model_dump(mode="json")
        for index, trace in enumerate(traces):
            actual = _get(normalized_data, tuple(trace.canonical_field.split(".")))
            if trace.target_json == canonical_json(actual):
                continue
            time_format_only = (
                trace.canonical_field in {"timestamp", "observed_at"}
                and trace.target_json is not None
                and utc_timestamp(parse_json(trace.target_json)) == utc_timestamp(actual)
            )
            if not time_format_only:
                issues.append(
                    _issue(
                        "value_changed",
                        trace.canonical_field,
                        "Canonical normalization changed the decoded profile value.",
                        "loss",
                    )
                )
            traces[index] = trace.model_copy(
                update={
                    "target_json": canonical_json(actual),
                    "state": trace.state if time_format_only else "lossy",
                }
            )
    if event is not None and profile_id != "dvi" and issues:
        warnings = (
            *event.warnings,
            *(
                ValidationWarning(
                    code="DVI-MAPPING-" + issue.code.upper().replace("_", "-"),
                    path=issue.field,
                    explanation=issue.explanation,
                )
                for issue in _ordered(issues)
            ),
        )
        event = event.model_copy(update={"warnings": warnings})
    ordered = _ordered(issues)
    return ProfileNormalization(
        profile_id=profile_id,
        payload_digest=digest(payload),
        event=event,
        fields=tuple(traces),
        issues=ordered,
        state="known" if event is not None and not ordered else "unknown",
    )


def roundtrip_profile(event: TelemetryEvent, profile_id: ProfileId) -> MappingRoundtrip:
    source = _event(event)
    projection = project_profile(source, profile_id)
    normalized = normalize_profile(projection.payload_json, profile_id)
    candidate = normalized.event
    issues = [*projection.issues, *normalized.issues]
    before = _inventory(source)
    after = _inventory(candidate) if candidate is not None else {}
    changes = []
    for name in sorted(before.keys() | after.keys()):
        original, result = before.get(name), after.get(name)
        if original != result:
            changes.append(
                FieldTrace(
                    canonical_field=name,
                    profile_paths=(),
                    source_json=canonical_json(original),
                    target_json=canonical_json(result),
                    state="unknown" if candidate is None else "lossy",
                )
            )
            code = (
                "value_changed"
                if candidate is None
                else "timestamp_precision_loss"
                if name in {"timestamp", "observed_at"}
                else "severity_mapping_drift"
                if name == "severity"
                else "value_changed"
            )
            issues.append(
                _issue(
                    code,
                    name,
                    "Roundtrip value differs from the canonical source.",
                    "unknown" if candidate is None else "loss",
                )
            )
    provenance_changed = candidate is not None and source.raw != candidate.raw
    if provenance_changed:
        issues.append(
            _issue(
                "source_provenance_changed",
                "raw",
                "Raw evidence describes the profile payload; the original remains in the report.",
                "provenance",
            )
        )
    source_signal = extract_signal(source)
    semantic = (
        semantic_equivalence(source_signal, extract_signal(candidate)).decision
        if candidate is not None
        else "unknown"
    )
    decision: Literal["lossless", "lossy", "unknown"] = (
        "unknown"
        if normalized.state == "unknown" or source_signal.state != "known"
        else "lossy"
        if changes or any(i.impact == "loss" for i in issues)
        else "lossless"
    )
    return MappingRoundtrip(
        source=source,
        projection=projection,
        normalization=normalized,
        changes=tuple(changes),
        issues=_ordered(issues),
        semantic_decision=semantic,
        decision=decision,
        provenance_changed=provenance_changed,
    )


def mapping_artifacts(events: tuple[TelemetryEvent, ...]) -> dict[str, bytes]:
    if not 1 <= len(events) <= 32 or len({event.event_id for event in events}) != len(events):
        raise ValueError("DVI-MAPPING-BOUNDS: require 1..32 uniquely identified events")
    if sum(len(canonical_json(event).encode()) for event in events) > MAX_FIXTURE_BYTES:
        raise ValueError("DVI-MAPPING-BOUNDS: combined source events exceed 2 MiB")
    reports = tuple(
        roundtrip_profile(event, profile_id)
        for event in sorted(events, key=lambda item: item.event_id)
        for profile_id in PROFILE_IDS
    )
    profiles = tuple(schema_profile(profile_id) for profile_id in PROFILE_IDS)
    artifacts = {
        f"schema_profiles/{profile.profile_id}.json": json_bytes(profile) for profile in profiles
    }
    artifacts["mapping_report.json"] = json_bytes(MappingExport(reports=reports))
    artifacts["lossy_fields.json"] = json_bytes(
        LossExport(
            records=tuple(
                LossRecord(
                    event_id=report.source.event_id,
                    profile_id=report.projection.profile_id,
                    issues=report.issues,
                )
                for report in reports
            )
        )
    )
    artifacts["field_alias_graph.json"] = json_bytes(
        AliasGraph(
            edges=tuple(
                AliasEdge(
                    profile_id=profile.profile_id,
                    canonical_field=field.canonical_field,
                    path=path,
                    role="primary" if index == 0 else "alias",
                )
                for profile in profiles
                for field in profile.fields
                for index, path in enumerate((field.path, *field.aliases))
            )
        )
    )
    artifacts["roundtrip_report.json"] = json_bytes(
        RoundtripExport(
            records=tuple(
                RoundtripSummary(
                    event_id=report.source.event_id,
                    profile_id=report.projection.profile_id,
                    source_digest=report.source.stable_digest(),
                    payload_digest=report.normalization.payload_digest,
                    destination_digest=report.normalization.event.stable_digest()
                    if report.normalization.event
                    else None,
                    decision=report.decision,
                    semantic_decision=report.semantic_decision,
                    provenance_changed=report.provenance_changed,
                )
                for report in reports
            )
        )
    )
    return artifacts
