"""Evaluate declared run thresholds without hiding unavailable or invalid measurements."""

import math

from dvi_sentinel.artifact_models import RunRecord
from dvi_sentinel.score_models import ResilienceFrontier
from dvi_sentinel.scoring import outcome
from dvi_sentinel.workflow_models import GateDecision, GateResult


def check_run(
    record: RunRecord,
    frontier: ResilienceFrontier,
    *,
    threshold: float | None = None,
    max_unknown: float | None = None,
) -> GateResult:
    detection_floor = (
        record.configuration.scoring.min_detection_rate if threshold is None else threshold
    )
    unknown_ceiling = (
        record.configuration.scoring.max_unknown_rate if max_unknown is None else max_unknown
    )
    if any(
        not math.isfinite(value) or not 0 <= value <= 1
        for value in (detection_floor, unknown_ceiling)
    ):
        raise ValueError("DVI-CI-THRESHOLD: thresholds must be finite ratios in [0,1]")
    metrics = frontier.metrics
    baseline = outcome(frontier.baseline) if frontier.baseline else "unknown"
    decisions = [
        GateDecision(
            name="baseline",
            status="pass"
            if baseline == "detected"
            else "fail"
            if baseline in {"missed", "invalid"}
            else "unknown",
            observed=baseline,
            explanation="The original fixture must establish the expected detection.",
        ),
        GateDecision(
            name="semantic_validity",
            status="pass" if metrics.invalid == 0 else "fail",
            observed=float(metrics.invalid),
            threshold=0.0,
            explanation="Invalid transformations cannot support a passing resilience gate.",
        ),
        GateDecision(
            name="measured_variants",
            status="pass" if metrics.detected + metrics.missed else "unknown",
            observed=float(metrics.detected + metrics.missed),
            explanation="At least one variant needs a measured detection decision.",
        ),
        GateDecision(
            name="planning_budget",
            status="unknown" if record.planning.get("event_budget_exhausted") else "pass",
            observed=str(record.planning.get("event_budget_exhausted")),
            explanation="A truncated plan leaves requested coverage incomplete.",
        ),
    ]
    for name, ratio, limit, minimum in (
        ("detection_rate", metrics.detection_rate.value, detection_floor, True),
        ("unknown_rate", metrics.unknown_rate.value, unknown_ceiling, False),
    ):
        satisfied = ratio is not None and (ratio >= limit if minimum else ratio <= limit)
        decisions.append(
            GateDecision(
                name=name,
                status="unknown" if ratio is None else "pass" if satisfied else "fail",
                observed=ratio,
                threshold=limit,
                explanation="Inclusive threshold over valid variants; baseline excluded.",
            )
        )
    failed = any(d.status == "fail" for d in decisions)
    unknown = any(d.status == "unknown" for d in decisions)
    return GateResult(
        run_id=record.run_id,
        status="failed" if failed else "unknown" if unknown else "passed",
        exit_status=1 if failed else 2 if unknown else 0,
        decisions=tuple(decisions),
    )
