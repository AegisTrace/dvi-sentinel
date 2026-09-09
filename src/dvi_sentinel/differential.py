"""Independent supported-schema round trips with conservative disagreement classification."""

from collections import Counter
from typing import Literal

from pydantic import JsonValue, TypeAdapter, ValidationError

from dvi_sentinel import __version__
from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential_models import (
    DifferenceClass,
    DifferentialCase,
    DifferentialReport,
    FixtureRepresentation,
    SchemaDifference,
)
from dvi_sentinel.fixture_encoding import REPRESENTATIONS, EncodingError, encode_fixture
from dvi_sentinel.harness import DetectorHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.probe_sources import semantic_projection
from dvi_sentinel.serialization import digest

JSON_VALUE: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


def _flatten(value: object, prefix: str = "") -> dict[str, JsonValue]:
    if isinstance(value, dict):
        return {
            path: leaf
            for key, item in value.items()
            for path, leaf in _flatten(item, f"{prefix}/{key}").items()
        }
    # Projection is already Pydantic JSON data; validation keeps this boundary explicit.
    return {prefix: JSON_VALUE.validate_python(value)}


def _classify(path: str, expected: JsonValue, observed: JsonValue) -> DifferenceClass:
    if path in {"/timestamp", "/observed_at"}:
        return "timestamp_precision_drift"
    if path == "/severity":
        return "severity_normalization_drift"
    if path == "/correlation_id":
        return "correlation_key_loss"
    if path in {"/sensor", "/vendor", "/labels", "/tags", "/confidence", "/entities", "/evidence"}:
        return "optional_field_loss"
    if expected is not None and observed is None:
        return "field_mapping_loss"
    return "adapter_disagreement"


def compare_semantics(
    original: tuple[TelemetryEvent, ...], candidate: tuple[TelemetryEvent, ...]
) -> tuple[SchemaDifference, ...]:
    left = {e.event_id: e for e in original}
    right = {e.event_id: e for e in candidate}
    differences = []
    for event_id in sorted(left.keys() | right.keys()):
        if event_id not in left or event_id not in right:
            differences.append(
                SchemaDifference(
                    finding_class="field_mapping_loss",
                    event_id=event_id,
                    path="/event_id",
                    expected=event_id if event_id in left else None,
                    observed=event_id if event_id in right else None,
                    explanation="Logical event coverage differs; alignment is not guessed",
                )
            )
            continue
        before = _flatten(semantic_projection(left[event_id]))
        after = _flatten(semantic_projection(right[event_id]))
        for path in sorted(before.keys() | after.keys()):
            expected, observed = before.get(path), after.get(path)
            if expected != observed:
                differences.append(
                    SchemaDifference(
                        finding_class=_classify(path, expected, observed),
                        event_id=event_id,
                        path=path,
                        expected=expected,
                        observed=observed,
                        explanation="Independently normalized field differs from canonical input",
                    )
                )
    if set(left) == set(right) and [e.event_id for e in original] != [
        e.event_id for e in candidate
    ]:
        differences.append(
            SchemaDifference(
                finding_class="adapter_disagreement",
                path="/event_order",
                expected=[e.event_id for e in original],
                observed=[e.event_id for e in candidate],
                explanation="Sequence order differs without reorder permission",
            )
        )
    return tuple(differences)


def run_differential(
    events: tuple[TelemetryEvent, ...],
    harness: DetectorHarness,
    representations: tuple[FixtureRepresentation, ...] | None = None,
) -> DifferentialReport:
    if not events or len(events) > 10_000 or len({e.event_id for e in events}) != len(events):
        raise ValueError("DVI-DIFFERENTIAL-INPUT: require 1..10000 unique events")
    if representations is not None and (
        not 1 <= len(representations) <= 3
        or len({r.representation for r in representations}) != len(representations)
    ):
        raise ValueError("DVI-DIFFERENTIAL-INPUT: require 1..3 distinct supported representations")
    decisions = evaluate_events(events)
    if decisions:
        raise PolicyError(decisions)
    baseline = harness.evaluate(HarnessRequest(case_id="baseline", events=events))
    baseline_ids = Counter((d.detector, d.signature) for d in baseline.detections)
    input_digest = digest([e.model_dump(mode="json") for e in events])
    supplied = {r.representation: r for r in representations} if representations else {}
    cases = []
    for representation in sorted(supplied) if representations else REPRESENTATIONS:
        case_id = f"schema:{representation}"
        try:
            source = supplied.get(representation) or FixtureRepresentation(
                representation=representation,
                content=encode_fixture(events, representation),
            )
        except (EncodingError, ValidationError) as exc:
            cases.append(
                DifferentialCase(
                    id=case_id,
                    representation=representation,
                    status="unknown",
                    reason=str(exc)[:1000],
                )
            )
            continue
        adapter = "jsonl" if representation == "canonical_jsonl" else representation
        normalized = normalize(source.content.encode("utf-8"), adapter)
        if not normalized.parser_success:
            cases.append(
                DifferentialCase(
                    id=case_id,
                    representation=representation,
                    status="unknown",
                    reason="Parsing or policy failed; partial events are not evaluated",
                    source=source,
                    normalized=normalized,
                    evidence_paths=("#/source", "#/normalized/errors"),
                )
            )
            continue
        differences = list(compare_semantics(events, normalized.events))
        observation = harness.evaluate(HarnessRequest(case_id=case_id, events=normalized.events))
        observed_ids = Counter((d.detector, d.signature) for d in observation.detections)
        measurable = (
            baseline.status == observation.status == "complete"
            and bool(baseline_ids)
            and all(count == 1 for count in (*baseline_ids.values(), *observed_ids.values()))
        )
        if not differences and measurable and baseline_ids != observed_ids:
            differences.append(
                SchemaDifference(
                    finding_class="schema_fragility",
                    path="/observation/detections",
                    expected=[list(pair) for pair in sorted(baseline_ids)],
                    observed=[list(pair) for pair in sorted(observed_ids)],
                    explanation="Equivalent semantics produced different detection identities",
                )
            )
        status: Literal["agree", "disagree", "unknown"] = (
            "disagree" if differences else "agree" if measurable else "unknown"
        )
        cases.append(
            DifferentialCase(
                id=case_id,
                representation=representation,
                status=status,
                reason="Normalized fields or detector identities disagree"
                if differences
                else "Normalized semantics and observed detection identities agree"
                if measurable
                else "Semantics agree; detector evidence is unavailable, empty, or ambiguous",
                source=source,
                normalized=normalized,
                observation=observation,
                differences=tuple(differences),
                evidence_paths=("#/source", "#/normalized", "#/observation", "#/differences"),
            )
        )
    return DifferentialReport(
        tool_version=__version__,
        input_digest=input_digest,
        events=events,
        baseline=baseline,
        cases=tuple(cases),
    )
