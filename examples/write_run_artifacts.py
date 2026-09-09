"""Create and verify a complete local run bundle from real engine observations."""

from datetime import UTC, datetime
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_store import verify_artifacts, write_artifacts
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.probes import run_probes
from dvi_sentinel.run_artifacts import FixtureCapture, RunEvidence, build_run_artifacts
from dvi_sentinel.scenario_io import load_scenario
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.variations import plan_variations


def main() -> None:
    root = Path(__file__).parent
    started = datetime.now(UTC)
    scenario, _ = load_scenario(root / "artifact_scenario.yaml")
    assert scenario.harness.kind == "rule_logic"
    capture = FixtureCapture(scenario.inputs[0], read_fixture(root, scenario.inputs[0].path))
    events = normalize(capture.content, capture.specification.format).events
    harness = RuleLogicHarness(scenario.harness)
    plan = plan_variations(scenario.metadata.id, events, scenario.variations, 42)
    evidence = RunEvidence(
        scenario=scenario,
        fixtures=(capture,),
        plan=plan,
        observations=tuple(
            harness.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
        ),
        probes=run_probes(events, scenario.variations, harness, expected=scenario.expected),
        differential=run_differential(events, harness, expected=scenario.expected),
        minimal=FailureShrinker(harness).shrink(
            events,
            max(plan.cases, key=lambda c: len(c.events)),
            scenario.variations,
            scenario.expected,
        ),
    )
    files = build_run_artifacts(evidence, started_at=started, finished_at=datetime.now(UTC))
    output = root.parent / "runs/artifact-proof"
    written = write_artifacts(output, files, overwrite=True)
    verified = verify_artifacts(output, expected_manifest_digest=written.manifest_digest)
    if not verified.valid:
        raise ValueError(verified.issues)
    print(
        f"{verified.run_id}: {len(files)} artifacts verified; manifest {verified.manifest_digest}"
    )


if __name__ == "__main__":
    main()
