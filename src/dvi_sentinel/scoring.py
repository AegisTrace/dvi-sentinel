"""Descriptive resilience components with explicit unknowns and no weighted score."""

import math

from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.match_models import MatchComparison
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.score_models import (
    BoundaryCase,
    CaseAssessment,
    FamilyFrontier,
    Ratio,
    ResilienceFrontier,
    VariantMetrics,
)
from dvi_sentinel.taxonomy import classify_findings


def ratio(numerator: int, denominator: int) -> Ratio:
    return Ratio(
        numerator=numerator,
        denominator=denominator,
        value=numerator / denominator if denominator else None,
    )


def percentile(values: list[float], fraction: float) -> float | None:
    """Linear interpolation at (n-1)*fraction, including single-sample endpoints."""
    if not 0 <= fraction <= 1 or any(not math.isfinite(value) for value in values):
        raise ValueError("finite values and fraction in [0,1] required")
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def outcome(row: CaseAssessment) -> str:
    if not row.preservation.valid:
        return "invalid"
    if row.parser_success is not True or row.match is None:
        return "unknown"
    return row.match.status


def _metrics(rows: tuple[CaseAssessment, ...]) -> VariantMetrics:
    valid = [row for row in rows if row.preservation.valid]
    counts = {
        status: sum(outcome(row) == status for row in rows)
        for status in ("detected", "missed", "unknown")
    }
    checks = [check for row in rows for check in row.preservation.checks]
    delays = [
        row.match.alert_delay_ms
        for row in rows
        if outcome(row) == "detected"
        and row.match is not None
        and row.match.alert_delay_ms is not None
    ]
    evidence: list[MatchComparison] = []
    evidence_cases = 0
    for row in rows:
        if (
            row.preservation.valid
            and row.parser_success is True
            and row.match
            and row.match.candidates
        ):
            candidates = [
                candidate
                for candidate in row.match.candidates
                if candidate.status == row.match.status
            ]
            if candidates:
                decisive = min(
                    candidates,
                    key=lambda c: (
                        len(c.missing_evidence) + len(c.contradictory_evidence),
                        c.event_id,
                    ),
                )
                evidence.extend(decisive.comparisons)
                evidence_cases += 1
    return VariantMetrics(
        total=len(rows),
        tested=sum(row.match is not None for row in rows),
        semantically_valid=len(valid),
        invalid=len(rows) - len(valid),
        detected=counts["detected"],
        missed=counts["missed"],
        unknown=counts["unknown"],
        detection_rate=ratio(counts["detected"], len(valid)),
        miss_rate=ratio(counts["missed"], len(valid)),
        unknown_rate=ratio(counts["unknown"], len(valid)),
        measured_detection_rate=ratio(counts["detected"], counts["detected"] + counts["missed"]),
        invariant_pass_rate=ratio(sum(check.passed for check in checks), len(checks)),
        semantic_preservation_rate=ratio(len(valid), len(rows)),
        parser_success_rate=ratio(
            sum(row.parser_success is True for row in rows),
            sum(row.parser_success is not None for row in rows),
        ),
        parser_unknown=sum(row.parser_success is None for row in rows),
        evidence_completeness=ratio(
            sum(check.outcome in {"pass", "contradiction"} for check in evidence), len(evidence)
        ),
        evidence_cases=evidence_cases,
        latency_samples=len(delays),
        latency_p50_ms=percentile(delays, 0.5),
        latency_p95_ms=percentile(delays, 0.95),
    )


def summarize(
    assessments: tuple[CaseAssessment, ...],
    *,
    probes: tuple[AssumptionProbe, ...] = (),
    differential: DifferentialReport | None = None,
) -> ResilienceFrontier:
    if len({row.case_id for row in assessments}) != len(assessments):
        raise ValueError("DVI-SCORE-DUPLICATE: assessment IDs must be unique")
    baselines = [row for row in assessments if row.family == "baseline"]
    if len(baselines) > 1:
        raise ValueError("DVI-SCORE-BASELINE: at most one baseline is allowed")
    baseline = baselines[0] if baselines else None
    baseline_detected = bool(baselines and outcome(baselines[0]) == "detected")
    rows = tuple(row for row in assessments if row.family != "baseline")
    families = []
    for family in sorted({row.family for row in rows}):
        members = tuple(row for row in rows if row.family == family)
        detected = [row for row in members if outcome(row) == "detected"]
        missed = [row for row in members if outcome(row) == "missed"]
        hardest = min(detected, key=lambda row: (-row.distance, row.case_id)) if detected else None
        easiest = min(missed, key=lambda row: (row.distance, row.case_id)) if missed else None
        families.append(
            FamilyFrontier(
                family=family,
                metrics=_metrics(members),
                minimal_miss_distance=easiest.distance if easiest else None,
                hardest_safe_detected=BoundaryCase(
                    case_id=hardest.case_id, distance=hardest.distance
                )
                if hardest
                else None,
                easiest_safe_missed=BoundaryCase(case_id=easiest.case_id, distance=easiest.distance)
                if easiest
                else None,
            )
        )
    cases = differential.cases if differential else ()
    return ResilienceFrontier(
        baseline=baseline,
        metrics=_metrics(rows),
        families=tuple(families),
        adapter_disagreement_rate=ratio(
            sum(case.status == "disagree" for case in cases),
            sum(case.status != "unknown" for case in cases),
        ),
        adapter_unknown=sum(case.status == "unknown" for case in cases),
        findings=classify_findings(rows, baseline_detected, probes, differential),
    )
