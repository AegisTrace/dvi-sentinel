"""Pure bounded comparisons through existing fixture adapters and profile mappings (A)."""

from datetime import datetime
from typing import cast

from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_models import MAX_ARTIFACT_BYTES
from dvi_sentinel.differential import compare_semantics
from dvi_sentinel.differential_models import SchemaDifference
from dvi_sentinel.fixture_encoding import (
    REPRESENTATIONS,
    EncodingError,
    encode_fixture,
)
from dvi_sentinel.mapping_models import MappingIssue, ProfileId
from dvi_sentinel.metamorphic_models import (
    ComparisonState,
    CrossProfileMatrix,
    FindingClass,
    MetamorphicInput,
    MetamorphicReport,
    ProfileComparison,
    RepresentationDiff,
    RepresentationFinding,
    RepresentationId,
    RepresentationInput,
    RepresentationResult,
)
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.ontology import extract_signal, semantic_equivalence
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes
from dvi_sentinel.schema_mapping import normalize_profile, project_profile
from dvi_sentinel.serialization import parse_json


class _Rejected(ValueError):
    """A fixture parser recorded a structural safety rejection."""


def _candidate(row: RepresentationResult) -> TelemetryEvent | None:
    if row.adapter is not None:
        return (
            row.adapter.events[0]
            if row.adapter.parser_success and len(row.adapter.events) == 1
            else None
        )
    return row.profile.event if row.profile is not None else None


def _prepare(request: MetamorphicInput, name: RepresentationId) -> RepresentationResult:
    supplied = next((v for v in request.supplied if v.representation == name), None)
    projection = None
    try:
        if supplied is None:
            if name in REPRESENTATIONS:
                content = encode_fixture((request.source,), name)
            else:
                projection = project_profile(request.source, cast(ProfileId, name))
                content = projection.payload_json
            supplied = RepresentationInput(representation=name, content=content)
        if name in REPRESENTATIONS:
            adapter = normalize(
                supplied.content.encode("utf-8"), "jsonl" if name == "canonical_jsonl" else name
            )
            if any(issue.code == "DVI-ADAPTER-POLICY" for issue in adapter.errors):
                raise _Rejected("Fixture policy rejected a representation.")
            return RepresentationResult(
                representation=name,
                state="unknown",
                source=supplied,
                adapter=adapter,
                failure=None
                if adapter.parser_success and len(adapter.events) == 1
                else "Exactly one event without parser errors is required.",
            )
        normalized = normalize_profile(supplied.content, cast(ProfileId, name))
        return RepresentationResult(
            representation=name,
            state="unknown",
            source=supplied,
            projection=projection,
            profile=normalized,
        )
    except (PolicyError, _Rejected):
        raise
    except (EncodingError, ValueError, RecursionError) as exc:
        # Malformed/unsupported input remains a structured unknown. Unexpected errors propagate.
        return RepresentationResult(
            representation=name,
            state="unknown",
            source=supplied,
            projection=projection,
            failure=f"{type(exc).__name__}: {str(exc)[:900]}",
        )


def _issues(row: RepresentationResult) -> tuple[MappingIssue, ...]:
    return (
        *(row.projection.issues if row.projection else ()),
        *(row.profile.issues if row.profile else ()),
    )


def _measure(source: TelemetryEvent, row: RepresentationResult) -> RepresentationResult:
    candidate = _candidate(row)
    if candidate is None:
        return row
    semantic = semantic_equivalence(extract_signal(source), extract_signal(candidate))
    differences = compare_semantics((source,), (candidate,))
    issues = _issues(row)
    state: ComparisonState = (
        "unknown"
        if row.failure
        or semantic.decision == "unknown"
        or any(i.impact == "unknown" for i in issues)
        else "disagree"
        if differences
        or semantic.decision == "different"
        or any(i.impact == "loss" for i in issues)
        else "agree"
    )
    return RepresentationResult.model_validate(
        row.model_dump(mode="python")
        | {
            "state": state,
            "semantic": semantic,
            "differences": differences,
        }
    )


def _time_class(
    source: TelemetryEvent, candidate: TelemetryEvent, path: str, row: RepresentationResult
) -> FindingClass:
    original = source.timestamp if path == "/timestamp" else source.observed_at
    observed = candidate.timestamp if path == "/timestamp" else candidate.observed_at
    if original is not None and observed is not None:
        if any(
            original.replace(microsecond=(original.microsecond // scale) * scale) == observed
            for scale in (10, 100, 1000, 10_000, 100_000, 1_000_000)
        ):
            return "timestamp_precision_loss"
        if path == "/timestamp":
            try:
                left = datetime.fromisoformat(source.raw.original_timestamp or "")
                spelling = candidate.raw.original_timestamp
                if row.profile is not None:
                    trace = next(
                        (t for t in row.profile.fields if t.canonical_field == "timestamp"), None
                    )
                    value = parse_json(trace.source_json) if trace and trace.source_json else None
                    spelling = value if isinstance(value, str) else None
                right = datetime.fromisoformat(spelling or "")
            except ValueError:
                return "adapter_disagreement"
            if (
                left.utcoffset() is not None
                and right.utcoffset() is not None
                and left.utcoffset() != right.utcoffset()
                and left.replace(tzinfo=None) == right.replace(tzinfo=None)
                and left == original
                and right == observed
            ):
                return "timezone_drift"
    return "adapter_disagreement"


def _field_class(path: str) -> FindingClass:
    if path == "/severity":
        return "severity_mapping_drift"
    if path == "/correlation_id":
        return "correlation_key_loss"
    if path.split("/")[1] in {
        "sensor",
        "vendor",
        "labels",
        "tags",
        "confidence",
        "entities",
        "evidence",
        "warnings",
        "detector",
        "signature",
        "title",
        "techniques",
        "related_event_ids",
        "raw",
    }:
        return "metadata_context_loss"
    return "semantic_loss"


def _issue_class(issue: MappingIssue) -> FindingClass:
    if issue.code == "alias_ambiguity":
        return "field_alias_mismatch"
    if issue.code in {"timestamp_precision_loss", "severity_mapping_drift"}:
        return cast(FindingClass, issue.code)
    if issue.impact == "unknown":
        return "unsupported_profile_feature"
    return _field_class("/" + issue.field.replace(".", "/"))


def _findings(
    source: TelemetryEvent, row: RepresentationResult, index: int, fingerprint: str
) -> tuple[RepresentationFinding, ...]:
    found: list[RepresentationFinding] = []
    base = f"/results/{index}"

    def add(kind: FindingClass, path: str, ref: str, explanation: str) -> None:
        found.append(
            RepresentationFinding(
                input_digest=fingerprint,
                finding_class=kind,
                representation=row.representation,
                field_path=path,
                evidence_ref=base + ref,
                explanation=explanation,
            )
        )

    candidate = _candidate(row)
    for i, difference in enumerate(row.differences):
        path = difference.path
        kind = (
            _time_class(source, candidate, path, row)
            if candidate is not None and path in {"/timestamp", "/observed_at"}
            else _field_class(path)
        )
        add(
            "adapter_disagreement",
            path,
            f"/differences/{i}",
            "The normalized value differs at this field; this does not prove an adapter defect.",
        )
        if kind != "adapter_disagreement":
            add(
                kind,
                path,
                f"/differences/{i}",
                "Measured local difference; expected and observed values are in the evidence.",
            )
    if row.semantic is not None and row.semantic.decision == "different":
        add(
            "semantic_loss",
            "/semantic/meaning",
            "/semantic",
            "The complete ontology projections differ in the linked changed fields.",
        )
    if row.semantic is not None and row.semantic.decision == "unknown":
        add(
            "unsupported_profile_feature",
            "/semantic/meaning",
            "/semantic",
            "Required ontology evidence is unresolved; equal values cannot establish equivalence.",
        )
    for label, owner in (("projection", row.projection), ("profile", row.profile)):
        if owner is None:
            continue
        for i, issue in enumerate(owner.issues):
            if issue.impact != "provenance":
                add(
                    _issue_class(issue),
                    "/"
                    + (
                        issue.field
                        if issue.code == "unsupported_field"
                        else issue.field.replace(".", "/")
                    ),
                    f"/{label}/issues/{i}",
                    issue.explanation,
                )
    if row.adapter is not None:
        for i, error in enumerate(row.adapter.errors):
            add(
                "field_alias_mismatch"
                if "ALIAS-CONFLICT" in error.code
                else "unsupported_profile_feature",
                error.path,
                f"/adapter/errors/{i}",
                error.explanation[:1024],
            )
    if row.failure is not None:
        add("unsupported_profile_feature", "/representation", "/failure", row.failure)
    return tuple(found)


def _pair(
    left: RepresentationResult, right: RepresentationResult, i: int, j: int
) -> ProfileComparison:
    a, b = _candidate(left), _candidate(right)
    semantic = None
    differences: tuple[SchemaDifference, ...] = ()
    state: ComparisonState = "unknown"
    if a is not None and b is not None and left.state != "unknown" and right.state != "unknown":
        semantic = semantic_equivalence(extract_signal(a), extract_signal(b))
        differences = compare_semantics((a,), (b,))
        state = (
            "unknown"
            if semantic.decision == "unknown"
            else "disagree"
            if differences or semantic.decision == "different"
            else "agree"
        )
    return ProfileComparison(
        left=left.representation,
        right=right.representation,
        state=state,
        semantic=semantic,
        differences=differences,
        evidence_refs=(f"/results/{i}", f"/results/{j}"),
    )


def analyze_representations(
    request: MetamorphicInput, *, expected_digest: str | None = None
) -> MetamorphicReport:
    """Remeasure actual input bytes. Agreement never follows from an empty diagnostic list."""
    request = MetamorphicInput.model_validate(request.model_dump(mode="python"))
    fingerprint = request.stable_digest()

    def blocked(unsafe: bool, explanation: str) -> MetamorphicReport:
        return MetamorphicReport(
            input_digest=fingerprint,
            state="unsafe_rejected" if unsafe else "unknown",
            input=None,
            results=(),
            findings=(),
            matrix=(),
            explanation=explanation,
        )

    if expected_digest is None:
        return blocked(
            False, "An externally pinned complete input digest is required before measurement."
        )
    if expected_digest != fingerprint:
        return blocked(True, "The pinned input digest differs from the supplied content.")
    try:
        if evaluate_events((request.source,)):
            return blocked(True, "Source policy rejected consumption.")
        prepared = tuple(_prepare(request, name) for name in request.representations)
    except (PolicyError, _Rejected):
        return blocked(
            True, "Structural fixture policy rejected consumption; no input content is exported."
        )
    results = tuple(_measure(request.source, row) for row in prepared)
    findings = tuple(
        f for i, row in enumerate(results) for f in _findings(request.source, row, i, fingerprint)
    )
    matrix = tuple(
        _pair(left, right, i, j)
        for i, left in enumerate(results)
        for j, right in enumerate(results)
    )
    return MetamorphicReport(
        input_digest=fingerprint,
        input=request,
        results=results,
        findings=findings,
        matrix=matrix,
        state="unknown"
        if any(r.state == "unknown" for r in results)
        else "disagree"
        if any(r.state == "disagree" for r in results)
        else "agree",
        explanation="Measured local fixture/profile comparisons only. "
        "Unknowns override overall agreement; pairwise agreement can share losses relative "
        "to the source. No standard compliance or detector effectiveness is implied.",
    )


def metamorphic_artifacts(
    request: MetamorphicInput, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    report = analyze_representations(request, expected_digest=expected_digest)
    artifacts = {
        "metamorphic_report.json": json_bytes(report),
        "representation_diff.json": json_bytes(
            RepresentationDiff(input_digest=report.input_digest, findings=report.findings)
        ),
        "adapter_disagreement.jsonl": jsonl_bytes(
            tuple(f for f in report.findings if f.finding_class == "adapter_disagreement")
        ),
        "cross_profile_matrix.json": json_bytes(
            CrossProfileMatrix(input_digest=report.input_digest, comparisons=report.matrix)
        ),
    }
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-METAMORPHIC-OUTPUT: combined artifacts exceed 32 MiB")
    return artifacts
