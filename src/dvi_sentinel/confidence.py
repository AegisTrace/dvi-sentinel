"""Conditional statistics over pinned local observations; no I/O or execution (A)."""

from itertools import combinations
from typing import Literal

from pydantic import TypeAdapter

from dvi_sentinel.comparison import compare_snapshots
from dvi_sentinel.confidence_math import bootstrap_latency, latency_points, paired_difference_bounds
from dvi_sentinel.confidence_models import (
    ConfidenceClass,
    ConfidenceInput,
    ConfidenceReport,
    ConfidenceRun,
    ConfidenceSettings,
    DistributionExport,
    GroupConfidence,
    LatencyBootstrap,
    LatencyEstimate,
    PairedEffect,
    RateInterval,
    Scope,
    SeedComparison,
    SeedRate,
    SeedStability,
    Side,
    StabilityExport,
    StatisticalWarning,
    WarningExport,
)
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import Sha256
from dvi_sentinel.oracle import ProvenanceOracle, SafetyOracle
from dvi_sentinel.oracle_models import OracleResult
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.scoring import _metrics, outcome, percentile, summarize
from dvi_sentinel.serialization import canonical_json, digest

CALIBRATION = (
    "Conditional descriptive estimates for the supplied finite fixtures. Wilson and paired "
    "Wilson bounds are approximate; percentile bootstrap intervals are pointwise, uncorrected "
    "and may under-cover, especially for small, dependent or degenerate samples. Independent "
    "trials, when declared, are an unverified modeling assumption. Confidence classes describe "
    "estimator precision under that assumption, not finding truth, causality, authenticity or "
    "release readiness. No empirical coverage calibration has been established. Unknown outcomes "
    "are excluded from resolved denominators; latency is conditional on detected alerts. "
    "Statistics never override safety, provenance or V1 regression decisions."
)
WARNINGS = {
    "small_sample": "Fewer than 20 resolved cases; precision is insufficient.",
    "empty_denominator": "No resolved cases; no detection or miss confidence interval exists.",
    "missing_outcomes": "Unknowns are excluded; identification bounds retain their uncertainty.",
    "invalid_cases": "Semantically invalid cases are excluded from statistical denominators.",
    "dependent_fixtures": "Finite fixtures have no established independent sampling mechanism.",
    "iid_assumption_unverified": "Independent trials were declared, not verified by this analyzer.",
    "duplicate_inputs": "Repeated case input digests can overstate the effective sample size.",
    "seed_stability_unknown": "Seed agreement is unavailable or incomplete; precision is capped.",
    "unstable_seeds": "Resolved case agreement across seeds is below 0.8.",
    "latency_selection": "Detected-alert latency excludes missed/unknown alerts.",
    "latency_small_sample": "Fewer than two observed delays; no bootstrap interval is produced.",
    "latency_degenerate": "Constant delays give degenerate bootstrap bounds, not certainty.",
}
Rows = tuple[CaseAssessment, ...]
Cohort = tuple[Scope, str, Rows]


def _unit(run: ConfidenceRun, row: CaseAssessment) -> str:
    return digest([row.family, row.distance, run.snapshot.case_input_digests[row.case_id]])


def _cohorts(run: ConfidenceRun) -> tuple[Cohort, ...]:
    rows = tuple(r for r in run.snapshot.assessments if r.family != "baseline")
    result: list[Cohort] = [("run", "all", rows)]
    result.extend(
        ("family", f, tuple(r for r in rows if r.family == f))
        for f in sorted({r.family for r in rows})
    )
    indexed = {r.case_id: r for r in rows}
    result.extend(
        ("finding", f.id, (indexed[f.case_id],))
        for f in summarize(run.snapshot.assessments).findings
        if f.case_id is not None
    )
    return tuple(result)


def _stability_key(side: Side, scope: Scope, identity: str) -> str:
    return f"{side}:{scope}:{identity}"


def _configuration(run: ConfidenceRun) -> tuple[str, ...]:
    s = run.snapshot
    indexed = {p.evidence.subject_id: p.evidence for p in run.evidence}
    expectations = tuple(
        sorted(
            _unit(run, r)
            + ":"
            + (digest(indexed[r.case_id].expected) if indexed[r.case_id].expected else "missing")
            for r in s.assessments
        )
    )
    return (
        s.tool_version,
        s.scenario_id,
        s.scenario_digest,
        s.input_digest,
        s.config_digest,
        s.detector_digest,
        *expectations,
    )


def _stability(
    runs: tuple[ConfidenceRun, ...], side: Side, scope: Scope, identity: str
) -> SeedStability:
    members = []
    maps = []
    reasons = set()
    for run in runs:
        rows = tuple(
            r
            for r in run.snapshot.assessments
            if r.family != "baseline"
            and (
                scope == "run"
                or (scope == "family" and r.family == identity)
                or (scope == "finding" and _unit(run, r) == identity)
            )
        )
        members.append(rows)
        mapped = {_unit(run, r): outcome(r) for r in rows}
        maps.append(mapped)
        if len(mapped) != len(rows):
            reasons.add("duplicate_units")
    if len(runs) < 2:
        reasons.add("one_seed")
    if len({_configuration(run) for run in runs}) != 1:
        reasons.add("seed_configuration_mismatch")
    if any(set(m) != set(maps[0]) for m in maps[1:]):
        reasons.add("seed_cohort_mismatch")
    if not any(maps):
        reasons.add("empty_cohort")
    resolved = agreeing = possible = 0
    if not reasons:
        possible = len(maps[0]) * len(runs) * (len(runs) - 1) // 2
        for left, right in combinations(maps, 2):
            for unit in left:
                if left[unit] in {"detected", "missed"} and right[unit] in {"detected", "missed"}:
                    resolved += 1
                    agreeing += left[unit] == right[unit]
        if resolved < possible:
            reasons.add("unresolved_seed_pairs")
    state: Literal["measured", "partial", "unknown"] = (
        "unknown" if not resolved else "partial" if reasons else "measured"
    )
    rates = []
    for run, rows in zip(runs, members, strict=True):
        m = _metrics(rows)
        rates.append(
            SeedRate(
                seed=run.snapshot.seed,
                detected=m.detected,
                missed=m.missed,
                unknown=m.unknown,
                invalid=m.invalid,
                detection_rate=m.measured_detection_rate.value,
            )
        )
    return SeedStability(
        key=_stability_key(side, scope, identity),
        side=side,
        rates=tuple(rates),
        possible_pairs=possible,
        resolved_pairs=resolved,
        agreeing_pairs=agreeing,
        unavailable_pairs=possible - resolved,
        score=agreeing / resolved if resolved else None,
        state=state,
        reasons=tuple(sorted(reasons)),
    )


def _latency(rows: Rows, settings: ConfidenceSettings) -> LatencyBootstrap:
    samples = tuple(
        sorted(
            r.match.alert_delay_ms
            for r in rows
            if outcome(r) == "detected"
            and r.match is not None
            and r.match.alert_delay_ms is not None
        )
    )
    points = latency_points(samples)
    replicates = bootstrap_latency(
        samples, seed=settings.bootstrap_seed, resamples=settings.bootstrap_resamples
    )
    alpha = (1 - settings.confidence_level) / 2
    names: tuple[Literal["mean", "p50", "p95"], ...] = ("mean", "p50", "p95")
    estimates = tuple(
        LatencyEstimate(
            metric=name,
            estimate=point,
            lower=percentile(list(values), alpha),
            upper=percentile(list(values), 1 - alpha),
            resampled_estimates=values,
        )
        for name, point, values in zip(names, points, replicates, strict=True)
    )
    return LatencyBootstrap(
        samples_ms=samples,
        seed=settings.bootstrap_seed,
        requested_resamples=settings.bootstrap_resamples,
        confidence_level=settings.confidence_level,
        estimates=(estimates[0], estimates[1], estimates[2]),
    )


def _classification(
    known: int, interval: RateInterval, stability: SeedStability, capped: bool
) -> ConfidenceClass:
    if not known:
        return "unknown"
    if stability.score is not None and stability.score < 0.8:
        return "unstable_across_seeds"
    if known < 20:
        return "insufficient_sample"
    if capped or stability.state != "measured":
        return "low_confidence"
    assert interval.upper is not None and interval.lower is not None
    width = interval.upper - interval.lower
    assert stability.score is not None
    if known >= 100 and width <= 0.2 and len(stability.rates) >= 3 and stability.score >= 0.9:
        return "high_confidence"
    if known >= 30 and width <= 0.35 and stability.score >= 0.8:
        return "moderate_confidence"
    return "low_confidence"


def _group(
    run: ConfidenceRun,
    side: Side,
    cohort: Cohort,
    stability: SeedStability,
    settings: ConfidenceSettings,
) -> GroupConfidence:
    scope, identity, rows = cohort
    m = _metrics(rows)
    known = m.detected + m.missed
    eligible = known + m.unknown
    interval = RateInterval.from_counts(m.detected, known, settings.confidence_level)
    latency = _latency(rows, settings)
    duplicate = len({run.snapshot.case_input_digests[r.case_id] for r in rows}) < len(rows)
    flags = {
        "small_sample": known < 20,
        "empty_denominator": not known,
        "missing_outcomes": bool(m.unknown),
        "invalid_cases": bool(m.invalid),
        "dependent_fixtures": not settings.independent_trials_assumed,
        "iid_assumption_unverified": settings.independent_trials_assumed,
        "duplicate_inputs": duplicate,
        "seed_stability_unknown": stability.state != "measured",
        "unstable_seeds": stability.score is not None and stability.score < 0.8,
        "latency_selection": True,
        "latency_small_sample": len(latency.samples_ms) < 2,
        "latency_degenerate": len(latency.samples_ms) >= 2 and len(set(latency.samples_ms)) == 1,
    }
    return GroupConfidence(
        key=f"{side}:{run.snapshot.seed}:{scope}:{identity}",
        side=side,
        seed=run.snapshot.seed,
        scope=scope,
        scope_id=identity,
        case_ids=tuple(r.case_id for r in rows),
        metrics=m,
        detection_interval=interval,
        miss_interval=RateInterval.from_counts(m.missed, known, settings.confidence_level),
        detection_identification_bounds=(m.detected / eligible, (m.detected + m.unknown) / eligible)
        if eligible
        else (None, None),
        latency=latency,
        stability_key=stability.key,
        confidence_class=_classification(
            known,
            interval,
            stability,
            bool(m.unknown or m.invalid or duplicate or not settings.independent_trials_assumed),
        ),
        warnings=tuple(sorted(code for code, enabled in flags.items() if enabled)),
    )


def _effect(
    previous: Rows, current: Rows, scope: Scope, identity: str, settings: ConfidenceSettings
) -> PairedEffect:
    prior = {r.case_id: outcome(r) for r in previous}
    recovered = lost = unchanged = unavailable = 0
    for row in current:
        left, right = prior[row.case_id], outcome(row)
        if left not in {"detected", "missed"} or right not in {"detected", "missed"}:
            unavailable += 1
        elif left == right:
            unchanged += 1
        elif right == "detected":
            recovered += 1
        else:
            lost += 1
    n = recovered + lost + unchanged
    lower, upper = paired_difference_bounds(recovered, lost, n, settings.confidence_level)
    return PairedEffect(
        scope=scope,
        scope_id=identity,
        paired_cases=len(current),
        recovered=recovered,
        lost=lost,
        unchanged=unchanged,
        unavailable=unavailable,
        delta=(recovered - lost) / n if n else None,
        lower=lower,
        upper=upper,
        confidence_level=settings.confidence_level,
        direction="unknown"
        if not n
        else "negative_interval"
        if upper is not None and upper < 0
        else "positive_interval"
        if lower is not None and lower > 0
        else "includes_zero",
    )


def _comparisons(request: ConfidenceInput) -> tuple[tuple[SeedComparison, ...], tuple[str, ...]]:
    if not request.previous:
        return (), ()
    if {r.snapshot.seed for r in request.previous} != {r.snapshot.seed for r in request.current}:
        return (), ("Seed sets differ; no paired historical estimates were computed.",)
    comparisons = []
    for previous, current in zip(request.previous, request.current, strict=True):
        legacy = compare_snapshots(previous.snapshot, current.snapshot)
        effects = []
        expectations_equal = {
            p.evidence.subject_id: p.evidence.expected for p in previous.evidence
        } == {p.evidence.subject_id: p.evidence.expected for p in current.evidence}
        reasons = (
            legacy.reasons
            if legacy.status == "incompatible"
            else (
                ()
                if expectations_equal
                else ("Detection expectations differ; effects are not comparable.",)
            )
        )
        if not reasons:
            old = {r.case_id: r for r in previous.snapshot.assessments}
            for scope, identity, rows in _cohorts(current):
                effects.append(
                    _effect(
                        tuple(old[r.case_id] for r in rows), rows, scope, identity, request.settings
                    )
                )
        comparisons.append(
            SeedComparison(
                seed=current.snapshot.seed,
                legacy=legacy,
                effects=tuple(effects),
                effect_reasons=reasons,
            )
        )
    return tuple(comparisons), ()


def _gates(request: ConfidenceInput) -> tuple[OracleResult, ...]:
    return tuple(
        gate
        for run in (*request.previous, *request.current)
        for proof in run.evidence
        for gate in (
            SafetyOracle.evaluate(proof.evidence),
            ProvenanceOracle.evaluate(proof.evidence, proof.expected_digest),
        )
    )


def _verify_observations(request: ConfidenceInput) -> None:
    for run in (*request.previous, *request.current):
        proofs = {p.evidence.subject_id: p.evidence for p in run.evidence}
        for row in run.snapshot.assessments:
            proof = proofs[row.case_id]
            if run.snapshot.case_input_digests[row.case_id] != digest(
                [e.model_dump(mode="json") for e in proof.events]
            ):
                raise ValueError("DVI-CONFIDENCE-INPUT: case event digest differs from evidence")
            if proof.observation is None:
                if row.match is not None:
                    raise ValueError("DVI-CONFIDENCE-MATCH: result lacks its observation")
            elif proof.expected is None or row.match != match_detection(
                proof.expected,
                proof.observation,
                proof.events,
                parser_success=row.parser_success is True,
                preservation=row.preservation,
            ):
                raise ValueError("DVI-CONFIDENCE-MATCH: assessment differs from actual observation")


def _derive(
    request: ConfidenceInput,
) -> tuple[
    tuple[GroupConfidence, ...],
    tuple[SeedStability, ...],
    tuple[SeedComparison, ...],
    tuple[str, ...],
    tuple[StatisticalWarning, ...],
]:
    """Only call after authoritative gates; also used to validate exported reports."""
    _verify_observations(request)
    groups = []
    stability = {}
    sides: tuple[tuple[Side, tuple[ConfidenceRun, ...]], ...] = (
        ("previous", request.previous),
        ("current", request.current),
    )
    for side, runs in sides:
        for run in runs:
            for cohort in _cohorts(run):
                scope, identity, rows = cohort
                stability_id = _unit(run, rows[0]) if scope == "finding" else identity
                key = _stability_key(side, scope, stability_id)
                if key not in stability:
                    stability[key] = _stability(runs, side, scope, stability_id)
                groups.append(_group(run, side, cohort, stability[key], request.settings))
    comparisons, reasons = _comparisons(request)
    warnings = tuple(
        StatisticalWarning(group=g.key, code=code, explanation=WARNINGS[code])
        for g in groups
        for code in g.warnings
    )
    return (
        tuple(groups),
        tuple(stability[k] for k in sorted(stability)),
        comparisons,
        reasons,
        warnings,
    )


def analyze_confidence(
    request: ConfidenceInput, *, expected_digest: str | None = None
) -> ConfidenceReport:
    request = ConfidenceInput.model_validate(request.model_dump(mode="python"))
    input_digest = request.stable_digest()
    pinned = (
        TypeAdapter(Sha256).validate_python(expected_digest)
        if expected_digest is not None
        else None
    )
    gates = () if pinned != input_digest else _gates(request)
    if pinned != input_digest or any(g.blocking for g in gates):
        code = "input_pin_missing" if pinned is None else "authoritative_gate_rejected"
        return ConfidenceReport(
            input_digest=input_digest,
            input=None,
            state="unknown" if pinned is None else "unsafe_rejected",
            gates=gates,
            warnings=(
                StatisticalWarning(
                    group="input",
                    code=code,
                    explanation="Pinned safe evidence is required before statistics.",
                ),
            ),
            calibration_note=CALIBRATION,
        )
    groups, stability, comparisons, reasons, warnings = _derive(request)
    return ConfidenceReport(
        input_digest=input_digest,
        input=request,
        state="measured",
        gates=gates,
        groups=groups,
        seed_stability=stability,
        comparisons=comparisons,
        comparison_reasons=reasons,
        warnings=warnings,
        calibration_note=CALIBRATION,
    )


def confidence_artifacts(
    request: ConfidenceInput, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    report = analyze_confidence(request, expected_digest=expected_digest)
    views = {
        "confidence.json": report,
        "seed_stability.json": StabilityExport(
            input_digest=report.input_digest, records=report.seed_stability
        ),
        "score_distribution.json": DistributionExport(
            input_digest=report.input_digest, groups=report.groups
        ),
        "statistical_warnings.json": WarningExport(
            input_digest=report.input_digest,
            warnings=report.warnings,
            calibration_note=report.calibration_note,
        ),
    }
    artifacts = {
        name: (canonical_json(value) + "\n").encode("utf-8") for name, value in views.items()
    }
    if sum(map(len, artifacts.values())) > 32 * 1024 * 1024:
        raise ValueError("DVI-CONFIDENCE-BOUNDS: combined artifacts exceed 32 MiB")
    return artifacts
