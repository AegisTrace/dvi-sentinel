"""Evaluate bounded local benchmark declarations; expectations never drive the detector."""

import hashlib
from pathlib import Path

from pydantic import JsonValue

from dvi_sentinel import __version__
from dvi_sentinel.benchmark_models import (
    BenchmarkCase,
    BenchmarkCheck,
    BenchmarkReport,
    BenchmarkResult,
    BenchmarkSuite,
)
from dvi_sentinel.differential import run_differential
from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.matching import match_detection
from dvi_sentinel.probes import run_probes
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.scoring import summarize
from dvi_sentinel.serialization import canonical_json, digest, parse_json
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.variation_models import VariationCase
from dvi_sentinel.variations import plan_variations
from dvi_sentinel.workflow import prepare_scenario


def run_benchmark_case(root: Path, suite: BenchmarkSuite, case: BenchmarkCase) -> BenchmarkResult:
    """Evaluate one declared V1 case, retaining evidence independently of its checks."""
    scenario_bytes = read_fixture(root, case.scenario)
    prepared = prepare_scenario(root / case.scenario)
    scenario, events, harness = prepared.scenario, prepared.events, prepared.harness
    sources = {case.scenario: hashlib.sha256(scenario_bytes).hexdigest()}
    for capture in prepared.fixtures:
        path = (Path(case.scenario).parent / capture.specification.path).as_posix()
        sources[path] = hashlib.sha256(capture.content).hexdigest()
    if prepared.harness_fixture is not None and scenario.harness.kind == "fixture":
        path = (Path(case.scenario).parent / scenario.harness.path).as_posix()
        sources[path] = hashlib.sha256(prepared.harness_fixture).hexdigest()
    plan = plan_variations(
        scenario.metadata.id,
        events,
        scenario.variations,
        suite.seed,
        event_budget=suite.event_budget,
    )
    assessments = tuple(
        CaseAssessment(
            case_id=c.id,
            family=c.family,
            distance=c.distance,
            preservation=c.preservation,
            parser_success=True,
            match=match_detection(
                scenario.expected,
                harness.evaluate(HarnessRequest(case_id=c.id, events=c.events)),
                c.events,
                preservation=c.preservation,
            ),
        )
        for c in plan.cases
    )
    probes = (
        run_probes(
            events,
            scenario.variations,
            harness,
            expected=scenario.expected,
            event_budget=suite.event_budget,
        )
        if case.probe_name
        else ()
    )
    differential = None
    minimum = None
    target_status: str
    if case.comparison_fixture:
        source = read_fixture(root, case.comparison_fixture)
        sources[case.comparison_fixture] = hashlib.sha256(source).hexdigest()
        differential = run_differential(
            events,
            harness,
            (FixtureRepresentation(representation="csv", content=source.decode("utf-8")),),
            expected=scenario.expected,
        )
        target_status = differential.cases[0].status
        target_match = differential.cases[0].match
    else:
        target = next((p for p in probes if p.spec.name == case.probe_name), None)
        if target is None:
            raise ValueError(f"DVI-BENCHMARK-PROBE: unknown target {case.probe_name}")
        target_status = target.observed_result
        target_match = target.candidate_match
        if target.observed_result == "fragile" and target.preservation and case.shrink_family:
            candidate = VariationCase(
                id=target.id,
                family=case.shrink_family,
                parameters=(),
                events=target.events,
                lineage=target.lineage,
                preservation=target.preservation,
                distance=0.0,
            )
            minimum = FailureShrinker(harness).shrink(
                events, candidate, scenario.variations, scenario.expected, probe=target.spec
            )
    frontier = summarize(assessments, probes=probes, differential=differential)
    checks: list[BenchmarkCheck] = []

    def check(name: str, observed: JsonValue, expected: JsonValue) -> None:
        checks.append(
            BenchmarkCheck(
                name=name,
                passed=observed == expected,
                expected=canonical_json(expected),
                observed=canonical_json(observed),
            )
        )

    check("baseline", assessments[0].match.status if assessments[0].match else None, "detected")
    check("target_outcome", target_status, case.target_status)
    check("reason_code", target_match.reason if target_match else None, case.reason_code)
    check(
        "finding_classes",
        ",".join(sorted({f.finding_class for f in frontier.findings})),
        ",".join(sorted(case.finding_classes)),
    )
    check("invalid_variants", frontier.metrics.invalid, 0)
    check("unknown_variants", frontier.metrics.unknown, 0)
    check("budget_exhausted", plan.event_budget_exhausted, False)
    check(
        "invalid_or_unknown_probes",
        sum(p.observed_result in {"invalid", "unknown"} for p in probes),
        0,
    )
    if case.control:
        check("control_findings", len(frontier.findings), 0)
    for metric in case.metrics:
        value = (
            frontier.metrics.detection_rate.value
            if metric.metric == "detection_rate"
            else frontier.adapter_disagreement_rate.value
        )
        passed = (
            value is None
            if metric.minimum is None
            else value is not None
            and metric.maximum is not None
            and metric.minimum <= value <= metric.maximum
        )
        checks.append(
            BenchmarkCheck(
                name=metric.metric,
                passed=passed,
                expected=canonical_json([metric.minimum, metric.maximum]),
                observed=canonical_json(value),
            )
        )
    if case.minimum is None:
        check("minimum", minimum.status if minimum else None, None)
    else:
        check("minimum_status", minimum.status if minimum else None, "minimized")
        if minimum:
            original_by_id = {e.event_id: e for e in events}
            positions = {e.event_id: index for index, e in enumerate(events)}
            original_order = [
                positions[e.event_id] for e in minimum.events if e.event_id in positions
            ]
            check("minimum_event_count", len(minimum.events), case.minimum.event_count)
            check(
                "minimum_changed_originals",
                sum(
                    e.event_id in original_by_id and e != original_by_id[e.event_id]
                    for e in minimum.events
                ),
                case.minimum.changed_originals,
            )
            check(
                "minimum_added_events",
                sum(e.event_id not in original_by_id for e in minimum.events),
                case.minimum.added_events,
            )
            check(
                "minimum_order_inversions",
                sum(a > b for i, a in enumerate(original_order) for b in original_order[i + 1 :]),
                case.minimum.order_inversions,
            )
            check("minimum_semantics", minimum.preservation.valid, True)
            check(
                "minimum_reason", minimum.final.reason if minimum.final else None, case.reason_code
            )
            check("minimum_class", minimum.finding_class in case.finding_classes, True)
    return BenchmarkResult(
        case=case,
        plan=plan,
        assessments=assessments,
        source_digests=dict(sorted(sources.items())),
        checks=tuple(checks),
        frontier=frontier,
        probes=probes,
        differential=differential,
        minimum=minimum,
    )


def run_benchmarks(root: Path) -> BenchmarkReport:
    """Load suite.json and its confined synthetic fixtures; return deterministic evidence."""
    suite = BenchmarkSuite.model_validate(parse_json(read_fixture(root, "suite.json")))
    return BenchmarkReport(
        tool_version=__version__,
        suite_digest=digest(suite),
        seed=suite.seed,
        results=tuple(
            run_benchmark_case(root, suite, case)
            for case in sorted(suite.cases, key=lambda c: c.id)
        ),
    )
