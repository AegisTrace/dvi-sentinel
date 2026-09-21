"""Derive discovery tokens from actual bounded analyses, then retain novelty (A)."""

from collections.abc import Iterable, Sequence

from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_models import MAX_ARTIFACT_BYTES
from dvi_sentinel.coverage_models import (
    DIMENSIONS,
    AdapterMeasurement,
    CaseCoverage,
    CoverageCaseInput,
    CoverageEvidenceGate,
    CoverageGrowth,
    CoverageMeasurements,
    CoverageRetention,
    CoverageToken,
    Dimension,
    DimensionObservation,
    GateState,
    GrowthPoint,
    RetentionDecision,
    RetentionReason,
    SemanticCoverage,
    State,
)
from dvi_sentinel.differential import compare_semantics
from dvi_sentinel.matching import match_detection
from dvi_sentinel.ontology import extract_signal, semantic_equivalence
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_consensus import build_consensus
from dvi_sentinel.oracle_models import GATE_IDS
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes
from dvi_sentinel.schema_mapping import roundtrip_profile
from dvi_sentinel.serialization import digest
from dvi_sentinel.taxonomy import SCHEMA_CLASSES


def _observation(
    dimension: Dimension,
    values: Iterable[str],
    known: bool,
    *refs: str,
) -> DimensionObservation:
    ordered = tuple(sorted(set(values)))
    return DimensionObservation(
        dimension=dimension,
        state="known" if known and ordered else "unknown",
        values=ordered,
        evidence_refs=tuple(refs),
        explanation="Measured states/paths from the linked local analysis."
        if known and ordered
        else "Required analysis is absent or unresolved; values do not add coverage.",
    )


def _unavailable(case: CoverageCaseInput, state: State, reason: str) -> CaseCoverage:
    return CaseCoverage(
        case_id=case.evidence.subject_id,
        input_digest=case.stable_digest(),
        state=state,
        input=None,
        measurements=None,
        observations=tuple(
            DimensionObservation(
                dimension=name,
                state=state,
                values=(),
                evidence_refs=(),
                explanation=reason,
            )
            for name in DIMENSIONS
        ),
    )


def measure_case(case: CoverageCaseInput) -> CaseCoverage:
    """Run authoritative gates before any coverage consumer touches supplied evidence."""
    case = CoverageCaseInput.model_validate(case.model_dump(mode="python"))
    case = case.model_copy(update={"profiles": tuple(sorted(case.profiles))})
    evidence = case.evidence
    rows = evaluate_oracles(evidence, expected_digest=case.expected_digest)
    if any(row.blocking for row in rows):
        return _unavailable(
            case, "unsafe_rejected", "Safety or pinned evidence integrity blocked consumption."
        )
    try:
        rejected = evaluate_events(case.reference_events)
    except PolicyError as exc:
        rejected = exc.decisions
    if rejected:
        return _unavailable(case, "unsafe_rejected", "Reference event policy rejected consumption.")
    reference_digest = digest([e.model_dump(mode="json") for e in case.reference_events])
    if case.reference_digest is not None and case.reference_digest != reference_digest:
        return _unavailable(
            case, "unsafe_rejected", "Pinned reference digest differs from supplied content."
        )
    if case.expected_digest is None or case.reference_digest is None:
        return _unavailable(
            case,
            "unknown",
            "Pinned input and reference digests are required for coverage consumption.",
        )
    signals = tuple(extract_signal(event) for event in evidence.events)
    reference = {e.event_id: e for e in case.reference_events}
    invariants = tuple(
        semantic_equivalence(extract_signal(reference[e.event_id]), signal)
        for e, signal in zip(evidence.events, signals, strict=True)
        if e.event_id in reference
    )
    adapters = tuple(
        AdapterMeasurement(
            representation=representation.representation,
            normalized=(
                normalized := normalize(
                    representation.content.encode("utf-8"),
                    "jsonl"
                    if representation.representation == "canonical_jsonl"
                    else representation.representation,
                )
            ),
            differences=compare_semantics(evidence.events, normalized.events)
            if normalized.parser_success
            else (),
        )
        for representation in sorted(evidence.representations, key=lambda r: r.representation)
    )
    mappings = tuple(
        roundtrip_profile(event, profile) for profile in case.profiles for event in evidence.events
    )
    match = (
        match_detection(evidence.expected, evidence.observation, evidence.events)
        if evidence.expected is not None and evidence.observation is not None
        else None
    )
    consensus = build_consensus(rows)
    measurements = CoverageMeasurements(
        signals=signals,
        invariants=invariants,
        adapters=adapters,
        mappings=mappings,
        match=match,
        oracles=rows,
        consensus=consensus,
    )
    by_id = {row.oracle_id: row for row in rows}
    observations = []
    observations.append(
        _observation(
            "semantic_signal",
            (s.signal.semantic_digest for s in signals),
            bool(signals) and all(s.state == "known" for s in signals),
            "/measurements/signals",
        )
    )
    observations.append(
        _observation(
            "invariant_state",
            (r.decision for r in invariants),
            bool(invariants)
            and len(invariants) == len(evidence.events) == len(reference)
            and all(r.decision != "unknown" for r in invariants),
            "/measurements/invariants",
            "/input/reference_events",
        )
    )
    branches = (
        []
        if match is None
        else [
            match.reason,
            *[
                f"{comparison.field}:{comparison.outcome}:{comparison.reason}"
                for candidate in match.candidates
                for comparison in candidate.comparisons
            ],
        ]
    )
    observations.append(
        _observation(
            "matcher_branch",
            branches,
            match is not None and match.status != "unknown",
            "/measurements/match",
        )
    )
    observations.append(
        _observation(
            "adapter_path",
            (
                f"{a.representation}->{a.normalized.adapter}:parsed"
                for a in adapters
                if a.normalized.parser_success
            ),
            bool(adapters) and all(a.normalized.parser_success for a in adapters),
            "/measurements/adapters",
        )
    )
    mapping_known = bool(mappings) and all(m.decision != "unknown" for m in mappings)
    observations.append(
        _observation(
            "schema_profile_path",
            (f"{m.projection.profile_id}:{m.decision}:{m.semantic_decision}" for m in mappings),
            mapping_known,
            "/measurements/mappings",
        )
    )
    observations.append(
        _observation(
            "field_mapping_path",
            (
                f"{m.projection.profile_id}:{field.canonical_field}:{'/'.join(path)}:{field.state}"
                for m in mappings
                for field in m.projection.fields
                for path in field.profile_paths
            ),
            mapping_known,
            "/measurements/mappings",
        )
    )
    losses = [
        f"{m.projection.profile_id}:{issue.field}:{issue.code}"
        for m in mappings
        for issue in m.issues
        if issue.impact != "provenance"
    ]
    losses += [
        f"{a.representation}:{difference.path}:{difference.finding_class}"
        for a in adapters
        for difference in a.differences
    ]
    observations.append(
        _observation(
            "normalization_loss_path",
            losses or ("no_observed_loss",),
            bool(adapters)
            and all(a.normalized.parser_success for a in adapters)
            and (
                mapping_known
                or (
                    bool(losses)
                    and bool(mappings)
                    and all(issue.impact != "unknown" for m in mappings for issue in m.issues)
                )
            ),
            "/measurements/mappings",
            "/measurements/adapters",
        )
    )
    temporal = by_id["temporal"]
    observations.append(
        _observation(
            "temporal_relation_state",
            (
                f"{temporal.decision}:{reason}"
                for reason in temporal.reason_codes or ("resolved_window",)
            ),
            temporal.decision in {"pass", "fail", "warn"},
            "/measurements/oracles",
        )
    )
    diagnostic = tuple(f"{name}:{by_id[name].decision}" for name in consensus.disagreements)
    observations.append(
        _observation(
            "oracle_disagreement_class",
            ("|".join(diagnostic),) if diagnostic else ("no_disagreement:" + consensus.state,),
            consensus.state in {"confirmed", "probable", "ambiguous", "suppressed_false_positive"},
            "/measurements/consensus",
        )
    )
    fragility = []
    if (
        consensus.state in {"confirmed", "probable"}
        and match is not None
        and match.status == "missed"
    ):
        fragility.append(
            {
                "DVI-MATCH-LATE": "timestamp_timezone",
                "DVI-MATCH-EARLY": "timestamp_timezone",
                "DVI-MATCH-CORRELATION": "correlation_key_dependency",
            }.get(match.reason, "unclassified_detection_gap")
        )
    if consensus.state == "suppressed_false_positive":
        fragility.append("no_confirmed_gap")
    fragility.extend(SCHEMA_CLASSES[d.finding_class] for a in adapters for d in a.differences)
    observations.append(
        _observation(
            "fragility_class",
            fragility,
            bool(fragility),
            "/measurements/consensus",
            "/measurements/match",
            "/measurements/adapters",
        )
    )
    correlations: list[str] = (
        []
        if match is None
        else [
            comparison.outcome
            for candidate in match.candidates
            for comparison in candidate.comparisons
            if comparison.field == "correlation_id"
        ]
    )
    if evidence.expected is not None and evidence.expected.correlation_id is None:
        correlations = ["not_requested"]
    observations.append(
        _observation(
            "correlation_path",
            correlations,
            bool(correlations) and all(v not in {"unknown", "missing"} for v in correlations),
            "/measurements/match",
            "/input/evidence/expected",
        )
    )
    observations.append(
        _observation(
            "evidence_quality_state",
            (f"{row.oracle_id}:{row.decision}" for row in rows if row.oracle_id in GATE_IDS),
            all(row.decision == "pass" for row in rows if row.oracle_id in GATE_IDS),
            "/measurements/oracles",
        )
    )
    ordered = tuple(sorted(observations, key=lambda row: row.dimension))
    return CaseCoverage(
        case_id=evidence.subject_id,
        input_digest=case.stable_digest(),
        input=case,
        measurements=measurements,
        state="known" if all(row.state == "known" for row in ordered) else "unknown",
        observations=ordered,
    )


def _coverage_evidence_gate(cases: Sequence[CaseCoverage]) -> CoverageEvidenceGate:
    """Unknown skipped cases cannot turn into passing release-input evidence."""
    if len(cases) > 16:
        raise ValueError("DVI-COVERAGE-BOUNDS: at most 16 cases")
    checked = tuple(CaseCoverage.model_validate(case.model_dump(mode="python")) for case in cases)
    unresolved = tuple(sorted(case.case_id for case in checked if case.state != "known"))
    state: GateState = (
        "unsafe_rejected"
        if any(case.state == "unsafe_rejected" for case in checked)
        else "unknown"
        if not checked or unresolved
        else "pass"
    )
    return CoverageEvidenceGate(
        state=state,
        passed=state == "pass",
        unresolved_cases=unresolved,
        explanation="This gate checks resolution of supplied coverage evidence only; "
        "it does not certify a release or security completeness.",
    )


def analyze_coverage(inputs: Sequence[CoverageCaseInput], *, seed: int = 0) -> SemanticCoverage:
    if not 1 <= len(inputs) <= 16:
        raise ValueError("DVI-COVERAGE-BOUNDS: require 1..16 input cases")
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("DVI-COVERAGE-SEED: require an integer in 0..2**63-1")
    checked = tuple(
        CoverageCaseInput.model_validate(case.model_dump(mode="python")) for case in inputs
    )
    if len({case.evidence.subject_id for case in checked}) != len(checked):
        raise ValueError("DVI-COVERAGE-IDENTITY: input case IDs must be unique")
    measured = tuple(measure_case(case) for case in checked)
    cases = tuple(
        sorted(measured, key=lambda case: digest({"seed": seed, "input": case.input_digest}))
    )
    seen: set[tuple[Dimension, str]] = set()
    retention = []
    growth = []
    for case in cases:
        known = {
            (row.dimension, value)
            for row in case.observations
            if row.state == "known"
            for value in row.values
        }
        added = known - seen
        seen.update(known)
        reason: RetentionReason = (
            "new_coverage"
            if added
            else "unsafe_rejected"
            if case.state == "unsafe_rejected"
            else "unknown_coverage"
            if case.state == "unknown"
            else "duplicate_coverage"
        )
        retention.append(
            RetentionDecision(
                case_id=case.case_id,
                input_digest=case.input_digest,
                retained=bool(added),
                reason=reason,
                new_tokens=tuple(CoverageToken(dimension=d, value=v) for d, v in sorted(added)),
                explanation=f"Added {len(added)} distinct resolved observations; "
                "unresolved dimensions never inflate the count.",
            )
        )
        growth.append(GrowthPoint(case_id=case.case_id, added=len(added), cumulative=len(seen)))
    return SemanticCoverage(
        seed=seed,
        cases=cases,
        tokens=tuple(CoverageToken(dimension=d, value=v) for d, v in sorted(seen)),
        retention=tuple(retention),
        growth=tuple(growth),
        evidence_gate=_coverage_evidence_gate(cases),
    )


def coverage_evidence_gate(inputs: Sequence[CoverageCaseInput]) -> CoverageEvidenceGate:
    """Recompute the evidence gate from inputs; never trust a supplied coverage total."""
    return analyze_coverage(inputs).evidence_gate if inputs else _coverage_evidence_gate(())


def coverage_artifacts(inputs: Sequence[CoverageCaseInput], *, seed: int = 0) -> dict[str, bytes]:
    report = analyze_coverage(inputs, seed=seed)
    artifacts = {
        "semantic_coverage.json": json_bytes(report),
        "coverage_growth.json": json_bytes(
            CoverageGrowth(seed=seed, points=report.growth, final_count=len(report.tokens))
        ),
        "discovery_queue.jsonl": jsonl_bytes(report.retention),
        "coverage_retention.json": json_bytes(
            CoverageRetention(
                seed=seed, decisions=report.retention, evidence_gate=report.evidence_gate
            )
        ),
    }
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-COVERAGE-OUTPUT: combined artifacts exceed 32 MiB")
    return artifacts
