"""Bounded pinned history, baseline registration and uncertainty-aware drift (A)."""

from typing import Literal

from pydantic import TypeAdapter

from dvi_sentinel.confidence import _comparisons, _gates, _verify_observations, analyze_confidence
from dvi_sentinel.confidence_models import ConfidenceInput, SeedComparison
from dvi_sentinel.models import Sha256
from dvi_sentinel.regression_memory_models import (
    BaselineEntry,
    DriftClass,
    DriftComparison,
    DriftGate,
    DriftInput,
    DriftMemory,
    DriftPoint,
    DriftPolicy,
    DriftRecord,
    DriftReport,
    MemoryArtifact,
    MemoryState,
    PinnedRecord,
    ProfileStamp,
    RegistryArtifact,
    UncertaintyArtifact,
)
from dvi_sentinel.schema_profiles import schema_profile
from dvi_sentinel.scoring import outcome
from dvi_sentinel.serialization import canonical_json, digest

INTERPRETATION = (
    "Classes describe observed local fixture transitions, not population resilience or release "
    "readiness. A passing gate means all requested comparisons meet the declared conditional "
    "precision and plausible-drop policy; existing fragility can remain. V1 regressions always "
    "fail. Unknown, incompatible or unresolved confidence never passes. Detector versions and "
    "schema usage are pinned producer declarations, not authenticated execution or inferred "
    "version compatibility. Independent-trial and bootstrap limits from each confidence report "
    "remain in force. History order is an explicit ordinal, not an inferred timestamp."
)


class MemoryIntegrityError(ValueError):
    """A pinned record, baseline reference or authoritative evidence gate failed."""


def _verify_memory(memory: DriftMemory) -> None:
    indexed = {p.record.id: p for p in memory.records}
    if any(p.expected_digest != p.record.stable_digest() for p in memory.records):
        raise MemoryIntegrityError("DVI-MEMORY-PIN: record digest differs")
    for entry in memory.baselines:
        if (
            entry.record_id not in indexed
            or entry.record_digest != indexed[entry.record_id].expected_digest
        ):
            raise MemoryIntegrityError("DVI-MEMORY-BASELINE: baseline target is absent or changed")
    # Complete preflight precedes every matcher/statistical consumer, including old records.
    if any(g.blocking for p in memory.records for g in _gates(p.record.measurement)):
        raise MemoryIntegrityError("DVI-MEMORY-GATE: authoritative evidence gate rejected history")
    for item in memory.records:
        _verify_observations(item.record.measurement)


def _checked_memory(memory: DriftMemory, expected_digest: str) -> DriftMemory:
    memory = DriftMemory.model_validate(memory.model_dump(mode="python"))
    if TypeAdapter(Sha256).validate_python(expected_digest) != memory.stable_digest():
        raise MemoryIntegrityError("DVI-MEMORY-PIN: memory digest differs")
    _verify_memory(memory)
    return memory


def append_record(
    memory: DriftMemory, record: DriftRecord, *, expected_digest: str, expected_record_digest: str
) -> DriftMemory:
    """Return new history; retrying an identical record is idempotent, replacement is rejected."""
    memory = _checked_memory(memory, expected_digest)
    record = DriftRecord.model_validate(record.model_dump(mode="python"))
    pinned = PinnedRecord(record=record, expected_digest=expected_record_digest)
    if pinned.expected_digest != record.stable_digest():
        raise MemoryIntegrityError("DVI-MEMORY-PIN: new record digest differs")
    previous = next((p for p in memory.records if p.record.id == record.id), None)
    if previous is not None:
        if previous != pinned:
            raise ValueError("DVI-MEMORY-APPEND: existing record identity cannot be replaced")
        return memory
    if memory.records and record.sequence <= memory.records[-1].record.sequence:
        raise ValueError("DVI-MEMORY-APPEND: new record must follow the last sequence")
    updated = DriftMemory(records=(*memory.records, pinned), baselines=memory.baselines)
    _verify_memory(updated)
    return updated


def register_baseline(
    memory: DriftMemory, name: str, record_id: str, *, expected_digest: str
) -> DriftMemory:
    """Explicit immutable name binding; no automatic promotion of the latest record."""
    memory = _checked_memory(memory, expected_digest)
    target = next((p for p in memory.records if p.record.id == record_id), None)
    if target is None:
        raise ValueError("DVI-MEMORY-BASELINE: requested record is absent")
    entry = BaselineEntry(name=name, record_id=record_id, record_digest=target.expected_digest)
    previous = next((b for b in memory.baselines if b.name == name), None)
    if previous is not None:
        if previous != entry:
            raise ValueError("DVI-MEMORY-BASELINE: existing baseline binding cannot be replaced")
        return memory
    return DriftMemory(records=memory.records, baselines=(*memory.baselines, entry))


def _prefix(request: DriftInput) -> tuple[DriftRecord, ...]:
    rows = tuple(p.record for p in request.memory.records)
    index = next((i for i, row in enumerate(rows) if row.id == request.current_id), None)
    return rows[: index + 1] if index is not None else ()


def _metadata_reasons(
    left: DriftRecord, right: DriftRecord, memory: DriftMemory
) -> tuple[str, ...]:
    reasons = set()
    if left.detector.detector_id != right.detector.detector_id:
        reasons.add("detector_identity_changed")
    if left.detector.comparison_contract != right.detector.comparison_contract:
        reasons.add("detector_contract_changed")
    for record in (left, right):
        definitions = {
            p.record.detector.definition_digest
            for p in memory.records
            if (p.record.detector.detector_id, p.record.detector.version)
            == (record.detector.detector_id, record.detector.version)
        }
        if len(definitions) > 1:
            reasons.add("detector_version_reused")
        if any(
            stamp != ProfileStamp.from_profile(schema_profile(stamp.profile_id))
            for stamp in record.profiles
        ):
            reasons.add("schema_profile_unsupported")
    if left.profiles != right.profiles:
        reasons.add("schema_profiles_changed")
    if left.measurement.settings != right.measurement.settings:
        reasons.add("statistical_settings_changed")
    if {r.snapshot.seed for r in left.measurement.current} != {
        r.snapshot.seed for r in right.measurement.current
    }:
        reasons.add("seed_sets_changed")
    before = {
        (r.snapshot.seed, p.evidence.subject_id): p.evidence.expected
        for r in left.measurement.current
        for p in r.evidence
    }
    after = {
        (r.snapshot.seed, p.evidence.subject_id): p.evidence.expected
        for r in right.measurement.current
        for p in r.evidence
    }
    if before != after:
        reasons.add("case_expectations_changed")
    return tuple(sorted(reasons))


def _gate(status: Literal["pass", "fail", "unknown"], *reasons: str) -> DriftGate:
    return DriftGate(
        status=status,
        exit_status=0 if status == "pass" else 1 if status == "fail" else 2,
        reasons=tuple(sorted(set(reasons))),
    )


def _observation_reasons(record: DriftRecord) -> set[str]:
    reasons = set()
    for run in record.measurement.current:
        baseline = tuple(r for r in run.snapshot.assessments if r.family == "baseline")
        variants = tuple(r for r in run.snapshot.assessments if r.family != "baseline")
        if not baseline or outcome(baseline[0]) != "detected":
            reasons.add("baseline_control_unresolved")
        if not variants:
            reasons.add("empty_variant_denominator")
        if any(outcome(r) not in {"detected", "missed"} for r in variants):
            reasons.add("case_outcomes_unresolved")
    return reasons


def _classification(
    left: DriftRecord,
    right: DriftRecord,
    points: tuple[DriftPoint, DriftPoint],
    pairs: tuple[SeedComparison, ...],
) -> DriftClass:
    if (
        _observation_reasons(left)
        or _observation_reasons(right)
        or any(p.legacy.status == "unknown" for p in pairs)
    ):
        return "unknown"
    if any(
        g.confidence_class == "unstable_across_seeds"
        for point in points
        for g in point.confidence.groups
        if g.scope != "finding"
    ):
        return "unstable"
    classes: set[DriftClass] = set()
    for pair in pairs:
        effect = next(e for e in pair.effects if e.scope == "run")
        assert pair.legacy.current is not None and pair.legacy.previous is not None
        if effect.lost and effect.recovered:
            classes.add("unstable")
        elif effect.lost:
            classes.add("newly_fragile")
        elif pair.legacy.current.metrics.missed:
            classes.add("still_fragile")
        elif pair.legacy.previous.metrics.missed:
            classes.add("recovered")
        else:
            classes.add("stable_strong")
    return next(iter(classes)) if len(classes) == 1 else "unstable"


def _confidence_gate(
    left: DriftRecord,
    right: DriftRecord,
    points: tuple[DriftPoint, DriftPoint],
    pairs: tuple[SeedComparison, ...],
    classification: DriftClass,
    policy: DriftPolicy,
) -> DriftGate:
    reasons = _observation_reasons(left) | _observation_reasons(right)
    ranks = {"low_confidence": 1, "moderate_confidence": 2, "high_confidence": 3}
    for point in points:
        for group in point.confidence.groups:
            if group.scope == "finding":
                continue
            if ranks.get(group.confidence_class, 0) < ranks[policy.minimum_confidence]:
                reasons.add("confidence_below_floor")
            stability = next(
                s for s in point.confidence.seed_stability if s.key == group.stability_key
            )
            if stability.state != "measured" or stability.score is None or stability.score < 0.8:
                reasons.add("seed_agreement_unresolved")
    if classification == "unstable":
        reasons.add("unstable_observations")
    for pair in pairs:
        if pair.legacy.status == "unknown":
            reasons.add("legacy_gate_unknown")
        for effect in pair.effects:
            if effect.scope == "finding":
                continue
            if effect.unavailable or effect.lower is None:
                reasons.add("paired_effect_unresolved")
            elif effect.lower < -policy.max_plausible_detection_drop:
                reasons.add("plausible_drop_exceeds_limit")
    if any(p.legacy.status == "regressed" for p in pairs):
        return _gate("fail", "legacy_regression", *reasons)
    if reasons:
        return _gate("unknown", *reasons)
    return _gate("pass", "comparison_resolved_within_policy")


def _compare(
    left: DriftRecord,
    right: DriftRecord,
    request: DriftInput,
    points: dict[str, DriftPoint],
    kind: Literal["previous", "baseline"],
) -> DriftComparison:
    reasons = set(_metadata_reasons(left, right, request.memory))
    if left.sequence >= right.sequence:
        reasons.add("reference_not_earlier")
    details: tuple[str, ...] = ()
    pairs: tuple[SeedComparison, ...] = ()
    if not reasons:
        paired = ConfidenceInput(
            previous=left.measurement.current,
            current=right.measurement.current,
            settings=right.measurement.settings,
        )
        pairs, details = _comparisons(paired)
        incompatible = tuple(reason for pair in pairs for reason in pair.effect_reasons)
        if incompatible or details:
            reasons.add("snapshot_incompatible")
            details = tuple(sorted(set((*details, *incompatible))))
            pairs = ()
    if reasons:
        classification: DriftClass = "incompatible"
        gate = _gate("unknown", "comparison_incompatible", *reasons)
    else:
        selected = (points[left.id], points[right.id])
        classification = _classification(left, right, selected, pairs)
        gate = _confidence_gate(left, right, selected, pairs, classification, request.policy)
    return DriftComparison(
        id="drift:"
        + digest(
            [kind, left.stable_digest(), right.stable_digest(), request.policy.stable_digest()]
        )[:24],
        kind=kind,
        previous_id=left.id,
        previous_digest=left.stable_digest(),
        current_id=right.id,
        current_digest=right.stable_digest(),
        classification=classification,
        gate=gate,
        reasons=tuple(sorted(reasons)),
        compatibility_details=details,
        seed_results=pairs,
    )


def _derive(
    request: DriftInput, points: tuple[DriftPoint, ...]
) -> tuple[
    MemoryState,
    tuple[DriftComparison, ...],
    DriftComparison | None,
    DriftClass,
    DriftGate,
    tuple[str, ...],
]:
    records = _prefix(request)
    if not records:
        return (
            "unknown",
            (),
            None,
            "unknown",
            _gate("unknown", "current_record_missing"),
            ("current_record_missing",),
        )
    indexed = {p.record_id: p for p in points}
    trend = tuple(
        _compare(left, right, request, indexed, "previous")
        for left, right in zip(records, records[1:], strict=False)
    )
    missing = set()
    if not trend:
        missing.add("previous_record_missing")
    baseline = None
    if request.named_baseline is not None:
        entry = next(
            (b for b in request.memory.baselines if b.name == request.named_baseline), None
        )
        if entry is None:
            missing.add("named_baseline_missing")
        else:
            left = next(p.record for p in request.memory.records if p.record.id == entry.record_id)
            baseline = _compare(left, records[-1], request, indexed, "baseline")
    required = (*trend[-1:], *((baseline,) if baseline is not None else ()))
    reasons = {
        reason
        for comparison in required
        if comparison.gate.status != "pass"
        for reason in comparison.gate.reasons
    } | missing
    if any(c.gate.status == "fail" for c in required):
        gate = _gate("fail", *reasons)
    elif missing or any(c.gate.status == "unknown" for c in required):
        gate = _gate("unknown", *reasons)
    else:
        gate = _gate("pass", "all_required_comparisons_resolved")
    classification = (
        "unknown"
        if missing
        else "incompatible"
        if any(c.classification == "incompatible" for c in required)
        else "unknown"
        if any(c.classification == "unknown" for c in required)
        else "unstable"
        if any(c.classification == "unstable" for c in required)
        else trend[-1].classification
    )
    return (
        "unknown" if missing else "evaluated",
        trend,
        baseline,
        classification,
        gate,
        tuple(sorted(missing)),
    )


def analyze_drift(request: DriftInput, *, expected_digest: str | None = None) -> DriftReport:
    request = DriftInput.model_validate(request.model_dump(mode="python"))
    pinned = (
        TypeAdapter(Sha256).validate_python(expected_digest)
        if expected_digest is not None
        else None
    )
    blocked = (
        "input_pin_missing"
        if pinned is None
        else "input_pin_mismatch"
        if pinned != request.stable_digest()
        else None
    )
    if blocked is None:
        try:
            _verify_memory(request.memory)
        except MemoryIntegrityError:
            blocked = "history_integrity_rejected"
    if blocked is not None:
        return DriftReport(
            input_digest=request.stable_digest(),
            input=None,
            state="unknown" if pinned is None else "unsafe_rejected",
            classification="unknown",
            gate=_gate("unknown" if pinned is None else "fail", blocked),
            reasons=(blocked,),
            interpretation=INTERPRETATION,
        )
    points = tuple(
        DriftPoint(
            record_id=record.id,
            record_digest=record.stable_digest(),
            confidence=analyze_confidence(
                record.measurement, expected_digest=record.measurement.stable_digest()
            ),
        )
        for record in _prefix(request)
    )
    state, trend, baseline, classification, gate, reasons = _derive(request, points)
    return DriftReport(
        input_digest=request.stable_digest(),
        input=request,
        state=state,
        points=points,
        trend=trend,
        baseline_comparison=baseline,
        classification=classification,
        gate=gate,
        reasons=reasons,
        interpretation=INTERPRETATION,
    )


def regression_memory_artifacts(
    request: DriftInput, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    report = analyze_drift(request, expected_digest=expected_digest)
    memory = report.input.memory if report.input is not None else None
    memory_digest = memory.stable_digest() if memory is not None else None
    views = {
        "trend_report.json": report,
        "regression_memory.json": MemoryArtifact(
            input_digest=report.input_digest,
            state=report.state,
            memory=memory,
            memory_digest=memory_digest,
        ),
        "baseline_registry.json": RegistryArtifact(
            input_digest=report.input_digest,
            state=report.state,
            memory_digest=memory_digest,
            entries=memory.baselines if memory is not None else (),
        ),
        "comparison_with_uncertainty.json": UncertaintyArtifact(
            input_digest=report.input_digest,
            state=report.state,
            trend=report.trend,
            baseline_comparison=report.baseline_comparison,
            classification=report.classification,
            gate=report.gate,
            interpretation=report.interpretation,
        ),
    }
    artifacts = {
        name: (canonical_json(value) + "\n").encode("utf-8") for name, value in views.items()
    }
    if sum(map(len, artifacts.values())) > 32 * 1024 * 1024:
        raise ValueError("DVI-MEMORY-BOUNDS: combined artifacts exceed 32 MiB")
    return artifacts
