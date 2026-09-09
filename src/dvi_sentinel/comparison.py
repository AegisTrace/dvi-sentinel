"""Deterministic comparison of declared, compatible local run snapshots."""

from decimal import Decimal

from dvi_sentinel.comparison_models import (
    ComparisonResult,
    ComparisonSnapshot,
    ComparisonThresholds,
    FamilyDelta,
    MetricDelta,
    ThresholdDecision,
)
from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.score_models import CaseAssessment, ResilienceFrontier, VariantMetrics
from dvi_sentinel.scoring import outcome, summarize
from dvi_sentinel.serialization import digest
from dvi_sentinel.variation_models import VariationPlan


def snapshot_from_plan(
    plan: VariationPlan,
    assessments: tuple[CaseAssessment, ...],
    *,
    scenario_digest: str,
    detector_digest: str,
    probes: tuple[AssumptionProbe, ...] = (),
    differential: DifferentialReport | None = None,
) -> ComparisonSnapshot:
    return ComparisonSnapshot(
        tool_version=plan.tool_version,
        scenario_id=plan.scenario_id,
        scenario_digest=scenario_digest,
        input_digest=plan.input_digest,
        config_digest=plan.config_digest,
        detector_digest=detector_digest,
        seed=plan.seed,
        case_input_digests={
            case.id: digest([e.model_dump(mode="json") for e in case.events]) for case in plan.cases
        },
        assessments=assessments,
        probes=probes,
        differential=differential,
    )


def _values(metrics: VariantMetrics) -> dict[str, float | None]:
    return {
        "total": float(metrics.total),
        "tested": float(metrics.tested),
        "semantically_valid": float(metrics.semantically_valid),
        "detected": float(metrics.detected),
        "missed": float(metrics.missed),
        "unknown": float(metrics.unknown),
        "detection_rate": metrics.detection_rate.value,
        "miss_rate": metrics.miss_rate.value,
        "unknown_rate": metrics.unknown_rate.value,
        "measured_detection_rate": metrics.measured_detection_rate.value,
        "invariant_pass_rate": metrics.invariant_pass_rate.value,
        "semantic_preservation_rate": metrics.semantic_preservation_rate.value,
        "parser_success_rate": metrics.parser_success_rate.value,
        "evidence_completeness": metrics.evidence_completeness.value,
        "latency_p50_ms": metrics.latency_p50_ms,
        "latency_p95_ms": metrics.latency_p95_ms,
    }


def _deltas(
    before: dict[str, float | None], after: dict[str, float | None]
) -> tuple[MetricDelta, ...]:
    return tuple(
        MetricDelta(
            metric=name,
            previous=before[name],
            current=after[name],
            delta=float(Decimal(str(after[name])) - Decimal(str(before[name])))
            if before[name] is not None and after[name] is not None
            else None,
        )
        for name in sorted(before)
    )


def _frontier(snapshot: ComparisonSnapshot) -> ResilienceFrontier:
    return summarize(
        snapshot.assessments, probes=snapshot.probes, differential=snapshot.differential
    )


def compare_snapshots(
    previous: ComparisonSnapshot,
    current: ComparisonSnapshot,
    thresholds: ComparisonThresholds | None = None,
) -> ComparisonResult:
    limits = thresholds or ComparisonThresholds()
    incompatible = []
    if previous.schema_version != "1" or current.schema_version != "1":
        incompatible.append("DVI-COMPARE-SCHEMA: only comparison schema 1 is supported")
    for field in (
        "tool_version",
        "scenario_id",
        "scenario_digest",
        "input_digest",
        "config_digest",
        "seed",
    ):
        if getattr(previous, field) != getattr(current, field):
            incompatible.append(f"DVI-COMPARE-CONFIG: {field} differs")
    left = {row.case_id: row for row in previous.assessments}
    right = {row.case_id: row for row in current.assessments}
    if set(left) != set(right):
        incompatible.append(
            "DVI-COMPARE-CASES: missing or additional cases prevent paired comparison"
        )
    if {probe.id for probe in previous.probes} != {probe.id for probe in current.probes}:
        incompatible.append("DVI-COMPARE-PROBES: probe coverage differs")
    prior_schema = (
        {case.id for case in previous.differential.cases} if previous.differential else set()
    )
    current_schema = (
        {case.id for case in current.differential.cases} if current.differential else set()
    )
    if prior_schema != current_schema:
        incompatible.append("DVI-COMPARE-SCHEMAS: representation coverage differs")
    for case_id in sorted(left.keys() & right.keys()):
        if previous.case_input_digests[case_id] != current.case_input_digests[case_id] or (
            left[case_id].family,
            left[case_id].distance,
        ) != (right[case_id].family, right[case_id].distance):
            incompatible.append(f"DVI-COMPARE-CASE: {case_id} input or variation identity differs")
    if incompatible:
        return ComparisonResult(status="incompatible", exit_status=2, reasons=tuple(incompatible))
    before, after = _frontier(previous), _frontier(current)
    newly_missed = tuple(
        case_id
        for case_id in sorted(left)
        if outcome(left[case_id]) != "missed" and outcome(right[case_id]) == "missed"
    )
    recovered = tuple(
        case_id
        for case_id in sorted(left)
        if outcome(left[case_id]) == "missed" and outcome(right[case_id]) == "detected"
    )
    unchanged = tuple(
        case_id
        for case_id in sorted(left)
        if outcome(left[case_id]) == outcome(right[case_id]) == "missed"
    )
    prior_values, current_values = _values(before.metrics), _values(after.metrics)
    prior_values["adapter_disagreement_rate"] = before.adapter_disagreement_rate.value
    current_values["adapter_disagreement_rate"] = after.adapter_disagreement_rate.value
    deltas = _deltas(prior_values, current_values)
    checks = []
    for metric, allowed, direction in (
        ("detection_rate", limits.max_detection_rate_drop, -1),
        ("unknown_rate", limits.max_unknown_rate_increase, 1),
        ("semantic_preservation_rate", limits.max_semantic_preservation_drop, -1),
        ("adapter_disagreement_rate", limits.max_adapter_disagreement_increase, 1),
    ):
        change = next(d for d in deltas if d.metric == metric)
        # Optional differential analysis absent on both sides is outside this gate.
        if (
            metric == "adapter_disagreement_rate"
            and previous.differential is None
            and current.differential is None
        ):
            continue
        deterioration = direction * change.delta if change.delta is not None else None
        checks.append(
            ThresholdDecision(
                metric=metric,
                deterioration=deterioration,
                allowed=allowed,
                status="unknown"
                if deterioration is None
                else "fail"
                if Decimal(str(deterioration)) > Decimal(str(allowed))
                else "pass",
            )
        )
    checks.append(
        ThresholdDecision(
            metric="newly_missed",
            deterioration=float(len(newly_missed)),
            allowed=float(limits.max_new_misses),
            status="fail" if len(newly_missed) > limits.max_new_misses else "pass",
        )
    )
    prior_families = {family.family: family for family in before.families}
    current_families = {family.family: family for family in after.families}
    before_classes = {finding.finding_class for finding in before.findings}
    after_classes = {finding.finding_class for finding in after.findings}
    failed = any(check.status == "fail" for check in checks)
    unknown = any(check.status == "unknown" for check in checks)
    return ComparisonResult(
        status="regressed" if failed else "unknown" if unknown else "passed",
        exit_status=1 if failed else 2 if unknown else 0,
        reasons=tuple(
            f"{check.metric}: {check.status}" for check in checks if check.status != "pass"
        )
        or ("All configured regression thresholds passed",),
        previous=before,
        current=after,
        metrics=deltas,
        families=tuple(
            FamilyDelta(
                family=family,
                metrics=_deltas(
                    _values(prior_families[family].metrics),
                    _values(current_families[family].metrics),
                ),
            )
            for family in sorted(prior_families)
        ),
        newly_missed=newly_missed,
        recovered=recovered,
        unchanged_misses=unchanged,
        new_fragility_classes=tuple(sorted(after_classes - before_classes)),
        removed_fragility_classes=tuple(sorted(before_classes - after_classes)),
        thresholds=tuple(checks),
    )
