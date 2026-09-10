"""Shared real engine evidence for artifact and reporting integration tests."""

from pathlib import Path

import pytest

from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.probes import run_probes
from dvi_sentinel.run_artifacts import FixtureCapture, RunEvidence
from dvi_sentinel.scenario_io import load_scenario
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.variations import plan_variations


@pytest.fixture(scope="module")
def evidence():
    root = Path(__file__).parents[1] / "examples"
    scenario, _ = load_scenario(root / "artifact_scenario.yaml")
    capture = FixtureCapture(scenario.inputs[0], (root / scenario.inputs[0].path).read_bytes())
    events = normalize(capture.content, "jsonl").events
    detector = RuleLogicHarness(scenario.harness)
    plan = plan_variations(scenario.metadata.id, events, scenario.variations, 42)
    return RunEvidence(
        scenario=scenario,
        fixtures=(capture,),
        plan=plan,
        observations=tuple(
            detector.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
        ),
        probes=run_probes(events, scenario.variations, detector, expected=scenario.expected),
        differential=run_differential(events, detector, expected=scenario.expected),
        minimal=FailureShrinker(detector).shrink(
            events,
            max(plan.cases, key=lambda c: len(c.events)),
            scenario.variations,
            scenario.expected,
        ),
    )
