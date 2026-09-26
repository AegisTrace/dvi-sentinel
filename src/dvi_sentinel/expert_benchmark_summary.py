"""Derive benchmark summaries from native evidence, without acceptance declarations (A)."""

from datetime import timedelta

from dvi_sentinel.benchmark_models import MinimalExpectation
from dvi_sentinel.expert_benchmark_models import (
    MeasuredScore,
    MeasuredSummary,
    MinimumResult,
    NativeEvidence,
    ScoreMetric,
)
from dvi_sentinel.score_models import Ratio
from dvi_sentinel.shrinking_models import MinimalCounterexample


def _minimum(
    result: MinimalCounterexample | None, *, analysis: bool = False, resolved: bool = True
) -> MinimumResult:
    if not analysis and not resolved:
        return MinimumResult(status="unavailable", reason="unresolved")
    if result is None:
        return MinimumResult(
            status="not_applicable", reason="analysis_only" if analysis else "no_detection_failure"
        )
    if (
        result.status != "minimized"
        or not result.preservation.valid
        or (
            result.baseline is None
            or result.baseline.status != "detected"
            or result.final is None
            or result.final.status != "missed"
        )
    ):
        return MinimumResult(status="unavailable", reason="unresolved")
    original = {e.event_id: e for e in result.original_events}
    positions = {e.event_id: i for i, e in enumerate(result.original_events)}
    order = [positions[e.event_id] for e in result.events if e.event_id in positions]
    return MinimumResult(
        status="minimized",
        reason="verified_local_minimum",
        maximum_time_shift_us=max(
            (
                abs((e.timestamp - original[e.event_id].timestamp) // timedelta(microseconds=1))
                for e in result.events
                if e.event_id in original
            ),
            default=0,
        ),
        value=MinimalExpectation(
            event_count=len(result.events),
            changed_originals=sum(
                e.event_id in original and e != original[e.event_id] for e in result.events
            ),
            added_events=sum(e.event_id not in original for e in result.events),
            order_inversions=sum(a > b for i, a in enumerate(order) for b in order[i + 1 :]),
        ),
    )


def _score(
    metric: ScoreMetric, numerator: int, denominator: int, scope: str, unknown: int = 0
) -> MeasuredScore:
    return MeasuredScore(
        metric=metric,
        ratio=Ratio(
            numerator=numerator,
            denominator=denominator,
            value=numerator / denominator if denominator else None,
        ),
        unknown=unknown,
        scope=scope,
    )


def summarize_expert(evidence: NativeEvidence) -> MeasuredSummary:
    """Expected findings, labels and score bounds never participate in this projection."""
    no_minimum = _minimum(None, analysis=True)
    state: str
    findings: tuple[str, ...]
    if evidence.kind == "legacy":
        result = evidence.result
        findings = tuple(sorted({f.finding_class for f in result.frontier.findings}))
        metrics = result.frontier.metrics
        if result.differential is not None:
            state = result.differential.cases[0].status
            ratio = result.frontier.adapter_disagreement_rate
            score = MeasuredScore(
                metric="adapter_disagreement_rate",
                ratio=ratio,
                unknown=result.frontier.adapter_unknown,
                scope="V1 adapter comparison cases",
            )
        else:
            target = next(p for p in result.probes if p.spec.name == result.case.probe_name)
            state = target.observed_result
            score = MeasuredScore(
                metric="detection_rate",
                ratio=metrics.detection_rate,
                unknown=metrics.unknown,
                scope="V1 planned variants; target probe is separate",
            )
        baseline = result.frontier.baseline
        if (
            baseline is None
            or baseline.match is None
            or baseline.match.status != "detected"
            or metrics.invalid
            or metrics.unknown
            or result.plan.event_budget_exhausted
            or any(p.observed_result in {"invalid", "unknown"} for p in result.probes)
        ):
            state = "incomplete"
        return MeasuredSummary(
            findings=tuple(sorted(findings)),
            state=state,
            minimum=_minimum(
                result.minimum,
                analysis=result.differential is not None,
                resolved=state in {"fragile", "robust"}
                and (state != "fragile" or result.minimum is not None),
            ),
            score=score,
        )
    if evidence.kind == "sequence":
        known = evidence.match.status in {"detected", "missed"}
        findings = (
            ("sequence_window_fragility",)
            if (
                evidence.match.status == "missed"
                and evidence.window.outcome == "contradicted"
                and evidence.baseline.status == "detected"
                and evidence.candidate.preservation.valid
            )
            else ()
        )
        state = (
            "baseline_failed"
            if evidence.baseline.status != "detected"
            else ("unknown" if evidence.window.outcome == "unknown" else evidence.match.status)
        )
        return MeasuredSummary(
            findings=findings,
            state=state,
            minimum=_minimum(evidence.minimum, resolved=state in {"detected", "missed"}),
            score=_score(
                "detection_rate",
                int(evidence.match.status == "detected"),
                int(known),
                "One preserved timing counterfactual; baseline is a separate eligibility check",
                int(not known),
            ),
        )
    if evidence.kind == "mapping":
        report = evidence.report
        return MeasuredSummary(
            findings=tuple(sorted({f.finding_class for f in report.findings})),
            state=report.state,
            minimum=no_minimum,
            score=_score(
                "agreement_rate",
                sum(r.state == "agree" for r in report.results),
                sum(r.state != "unknown" for r in report.results),
                "Known source-to-representation comparisons; unknown comparisons excluded",
                sum(r.state == "unknown" for r in report.results),
            ),
        )
    if evidence.kind == "intent":
        analysis = evidence.report
        checks = (*analysis.global_checks, *(c for row in analysis.candidates for c in row.checks))
        return MeasuredSummary(
            findings=tuple(sorted({c.code for c in checks if c.code != "supported"})),
            state=analysis.state,
            minimum=no_minimum,
            score=_score(
                "intent_support_rate",
                sum(c.state == "supported" for c in analysis.candidates),
                sum(c.state != "unknown" for c in analysis.candidates),
                "Known single-event support for the declared intent; unknown candidates excluded",
                sum(c.state == "unknown" for c in analysis.candidates),
            ),
        )
    if evidence.kind == "oracle":
        consensus = evidence.report
        decision = next(d for d in consensus.decisions if d.oracle_id == "detection")
        return MeasuredSummary(
            findings=("oracle_disagreement",) if consensus.disagreements else (),
            state=consensus.state,
            minimum=no_minimum,
            score=_score(
                "detection_rate",
                int(decision.decision == "pass"),
                int(decision.decision in {"pass", "fail"}),
                "Primary local detector contract",
                int(decision.decision not in {"pass", "fail"}),
            ),
            oracle_consensus=consensus.state,
            oracle_scope="Nine checks; primary observation and three local deterministic replays",
        )
    if evidence.kind == "statistical":
        group = next((g for g in evidence.report.groups if g.scope == "run"), None)
        if group is None:
            return MeasuredSummary(
                findings=("unresolved_statistics",),
                state=evidence.report.state,
                minimum=no_minimum,
                score=_score("detection_rate", 0, 0, "No resolved cohort"),
                confidence_class="unknown",
                confidence_scope="Statistical gates did not resolve",
            )
        return MeasuredSummary(
            findings=group.warnings,
            state=evidence.report.state,
            minimum=no_minimum,
            score=MeasuredScore(
                metric="detection_rate",
                ratio=group.metrics.measured_detection_rate,
                unknown=group.metrics.unknown,
                scope="Single-seed local fixture trials excluding baseline; no IID assumption",
            ),
            confidence_class=group.confidence_class,
            confidence_scope="Local run confidence; no population or seed-stability claim",
        )
    integrity = evidence.integrity
    findings = tuple(sorted({i.code for i in integrity.issues}))
    if evidence.bundle_issues and integrity.valid:
        findings = (*findings, "bundle_contract_changed")
    return MeasuredSummary(
        findings=findings,
        state="intact" if integrity.valid and not evidence.bundle_issues else "tampered",
        minimum=no_minimum,
        score=_score(
            "integrity_rate",
            len(evidence.dag.nodes) - len(integrity.invalidated),
            len(evidence.dag.nodes),
            "DAG artifacts without direct or inherited byte-integrity failures",
        ),
    )
