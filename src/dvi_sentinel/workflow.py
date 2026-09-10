"""Bounded orchestration of the existing local engines; no subprocess or network access."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_store import write_artifacts
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import DetectorHarness, FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import FixtureResults, HarnessRequest, HarnessResult
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import PolicyDecision, PolicyError, evaluate_events
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.probes import run_probes
from dvi_sentinel.reports import build_reports
from dvi_sentinel.run_artifacts import FixtureCapture, RunEvidence, build_run_artifacts
from dvi_sentinel.scenario import Scenario
from dvi_sentinel.scenario_io import load_scenario
from dvi_sentinel.score_models import ResilienceFrontier
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.shrinking_models import MinimalCounterexample
from dvi_sentinel.variation_models import Family, VariationCase
from dvi_sentinel.variations import plan_variations
from dvi_sentinel.workflow_models import RunSummary


@dataclass(frozen=True)
class PreparedScenario:
    scenario: Scenario
    fixtures: tuple[FixtureCapture, ...]
    events: tuple[TelemetryEvent, ...]
    harness: DetectorHarness
    harness_fixture: bytes | None
    policy: tuple[PolicyDecision, ...]


def prepare_scenario(path: Path) -> PreparedScenario:
    scenario, policy = load_scenario(path)
    captures = tuple(
        FixtureCapture(source, read_fixture(path.parent, source.path)) for source in scenario.inputs
    )
    events: list[TelemetryEvent] = []
    for capture in captures:
        parsed = normalize(capture.content, capture.specification.format)
        if not parsed.parser_success:
            detail = "; ".join(
                f"{e.code} record {e.record_index}: {e.explanation}" for e in parsed.errors[:5]
            )
            raise ValueError(f"DVI-RUN-NORMALIZATION: {capture.specification.path}: {detail}")
        events.extend(parsed.events)
    if not 1 <= len(events) <= 10_000 or len({e.event_id for e in events}) != len(events):
        raise ValueError("DVI-RUN-INPUT: require 1..10000 unique event IDs across all fixtures")
    source = None
    detector: DetectorHarness
    if scenario.harness.kind == "fixture":
        source = read_fixture(path.parent, scenario.harness.path)
        results = FixtureResults.model_validate(parse_json(source))
        for case in results.cases:
            rejected = evaluate_events(case.detections)
            if rejected:
                raise PolicyError(rejected)
        detector = FixtureHarness(results)
    else:
        detector = RuleLogicHarness(scenario.harness)
    return PreparedScenario(scenario, captures, tuple(events), detector, source, policy)


def _probe_family(probe: AssumptionProbe) -> Family:
    name = probe.spec.name
    if name in {"timestamp_precision", "timezone"}:
        return "timing"
    if name.startswith("drop:"):
        return "dropout"
    if name in {"duplicates", "bounded_volume"}:
        return "volume"
    if name == "benign_noise":
        return "noise"
    return "ordering" if name == "ordering" else "metadata"


def _shrink(
    prepared: PreparedScenario,
    cases: tuple[VariationCase, ...],
    observations: tuple[HarnessResult, ...],
    probes: tuple[AssumptionProbe, ...],
) -> MinimalCounterexample | None:
    original, scenario, detector = prepared.events, prepared.scenario, prepared.harness
    indexed = {o.case_id: o for o in observations}
    if match_detection(scenario.expected, indexed[cases[0].id], original).status != "detected":
        return None
    # Stable family order, then within-family distance. No global distance ranking.
    for case in sorted(cases, key=lambda c: (c.family, c.distance, c.id)):
        if case.family == "baseline" or not case.preservation.valid:
            continue
        observed = indexed[case.id]
        if (
            match_detection(
                scenario.expected, observed, case.events, preservation=case.preservation
            ).status
            == "missed"
        ):
            return FailureShrinker(detector).shrink(
                original, case, scenario.variations, scenario.expected
            )
    for probe in sorted(probes, key=lambda p: p.spec.name):
        if probe.observed_result == "fragile" and probe.preservation is not None:
            case = VariationCase(
                id=probe.id,
                family=_probe_family(probe),
                parameters=(),
                events=probe.events,
                lineage=probe.lineage,
                preservation=probe.preservation,
                distance=0.0,
            )
            return FailureShrinker(detector).shrink(
                original, case, scenario.variations, scenario.expected, probe=probe.spec
            )
    return None


def git_commit(directory: Path) -> str | None:
    """Read ordinary checkout metadata only; worktree indirection remains unavailable."""
    for root in (directory, *directory.parents):
        if not (root / ".git").is_dir():
            continue
        try:
            head = read_fixture(root, ".git/HEAD", limit=4096).decode("ascii").strip()
            if head.startswith("ref: "):
                reference = head[5:]
                try:
                    head = (
                        read_fixture(root, f".git/{reference}", limit=4096).decode("ascii").strip()
                    )
                except ValueError:
                    packed = read_fixture(root, ".git/packed-refs", limit=1024 * 1024).decode(
                        "ascii"
                    )
                    head = next(
                        (
                            line.split(" ")[0]
                            for line in packed.splitlines()
                            if line.endswith(" " + reference)
                        ),
                        "",
                    )
            return head if len(head) == 40 and all(c in "0123456789abcdef" for c in head) else None
        except (ValueError, OSError):
            return None
    return None


def run_scenario(
    path: Path,
    output: Path,
    *,
    seed: int,
    overwrite: bool = False,
    probes: bool = True,
    differential: bool = True,
    shrink: bool = True,
    event_budget: int = 50_000,
    command: tuple[str, ...],
) -> RunSummary:
    started = datetime.now(UTC)
    prepared = prepare_scenario(path)
    scenario, detector = prepared.scenario, prepared.harness
    plan = plan_variations(
        scenario.metadata.id, prepared.events, scenario.variations, seed, event_budget=event_budget
    )
    observations = tuple(
        detector.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
    )
    counterfactuals = (
        run_probes(
            prepared.events,
            scenario.variations,
            detector,
            expected=scenario.expected,
            event_budget=event_budget,
        )
        if probes
        else ()
    )
    schemas = (
        run_differential(prepared.events, detector, expected=scenario.expected)
        if differential
        else None
    )
    minimal = _shrink(prepared, plan.cases, observations, counterfactuals) if shrink else None
    evidence = RunEvidence(
        scenario=scenario,
        fixtures=prepared.fixtures,
        plan=plan,
        observations=observations,
        probes=counterfactuals,
        differential=schemas,
        minimal=minimal,
        harness_fixture=prepared.harness_fixture,
    )
    contents = build_run_artifacts(
        evidence,
        started_at=started,
        finished_at=datetime.now(UTC),
        command=command,
        git_commit=git_commit(Path.cwd()),
    )
    # TemporaryDirectory owns only its generated local directory. The requested
    # destination is touched once, after all report generation has succeeded.
    with TemporaryDirectory(prefix="dvi-report-") as temporary:
        stage = Path(temporary) / "bundle"
        write_artifacts(stage, contents)
        contents.update(build_reports(stage))
    verified = write_artifacts(output, contents, overwrite=overwrite)
    score = ResilienceFrontier.model_validate(parse_json(contents["score.json"]))
    metrics = score.metrics
    return RunSummary.model_validate(
        {
            "run_id": verified.run_id,
            "output": str(output.resolve()),
            "manifest_digest": verified.manifest_digest,
            "report": str(output.resolve() / "report.html"),
            "detected": metrics.detected,
            "missed": metrics.missed,
            "unknown": metrics.unknown,
            "invalid": metrics.invalid,
            "findings": len(score.findings),
        }
    )
