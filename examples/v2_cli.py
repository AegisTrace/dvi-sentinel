"""Create synthetic inputs and exercise all ten installed V2 CLI commands."""

import argparse
from contextlib import redirect_stdout
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

from dvi_sentinel.cli.analysis_io import destination
from dvi_sentinel.cli.analysis_models import EventInput, ExplorationInput, TemporalInput
from dvi_sentinel.cli.main import app
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.confidence_models import ConfidenceEvidence, ConfidenceInput, ConfidenceRun
from dvi_sentinel.constraint_models import Parameter, ParameterSpace
from dvi_sentinel.counterfactual_models import CounterfactualDimension, CounterfactualInput
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.run_artifacts import RunEvidence, build_run_artifacts, json_bytes
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.variations import plan_variations
from dvi_sentinel.workflow import prepare_scenario

COMMANDS = (
    "ontology",
    "map-schema",
    "analyze-rule",
    "temporal",
    "oracles",
    "explore",
    "explain",
    "confidence",
    "graph",
    "benchmark",
)


def fixture_inputs() -> dict[str, bytes]:
    prepared = prepare_scenario(Path(__file__).parent / "artifact_scenario.yaml")
    scenario, events = prepared.scenario, prepared.events
    assert scenario.harness.kind == "rule_logic"
    plan = plan_variations(scenario.metadata.id, events, scenario.variations, 42)
    observations = tuple(
        prepared.harness.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
    )
    proofs = tuple(
        OracleEvidence(subject_id=c.id, events=c.events, expected=scenario.expected, observation=o)
        for c, o in zip(plan.cases, observations, strict=True)
    )
    when = datetime(2026, 10, 1, tzinfo=UTC)
    artifacts = build_run_artifacts(
        RunEvidence(
            scenario=scenario, fixtures=prepared.fixtures, plan=plan, observations=observations
        ),
        started_at=when,
        finished_at=when,
        command=("python", "examples/v2_cli.py"),
    )
    confidence = ConfidenceInput(
        current=(
            ConfidenceRun(
                snapshot=ComparisonSnapshot.model_validate_json(artifacts["comparison.json"]),
                evidence=tuple(
                    ConfidenceEvidence(evidence=p, expected_digest=p.stable_digest())
                    for p in proofs
                ),
            ),
        )
    )
    request = CounterfactualInput(
        events=events,
        dimensions=(CounterfactualDimension(name="volume", operation="bounded_volume"),),
        policy=scenario.variations,
        expected=scenario.expected,
        harness=scenario.harness,
        seed=42,
    )
    exploration = ExplorationInput(
        events=events,
        policy=scenario.variations,
        space=ParameterSpace(
            parameters=(
                Parameter(name="volume", options=("none", "bounded_volume")),
                Parameter(name="order", options=("none", "ordering")),
            )
        ),
    )
    return {
        "events.json": json_bytes(EventInput(events=events)),
        "rule.json": json_bytes(scenario.harness.rules[0]),
        "temporal.json": json_bytes(
            TemporalInput(
                events=events + observations[0].detections,
                pattern=("flow", "alert"),
                window_ms=1000,
            )
        ),
        "oracles.json": json_bytes(proofs[-1]),
        "explore.json": json_bytes(exploration),
        "explain.json": json_bytes(request),
        "confidence.json": json_bytes(confidence),
    }


def arguments(command: str, inputs: Path, output: Path, benchmark_root: Path) -> list[str]:
    if command in {"ontology", "map-schema"}:
        return [command, str(inputs / "events.json")]
    if command == "analyze-rule":
        return [
            command,
            str(inputs / "rule.json"),
            "--events",
            str(inputs / "events.json"),
            "--format",
            "v1_rule",
        ]
    if command == "graph":
        return [command, str(output / "explain/counterfactual_summary.json")]
    if command == "benchmark":
        return [command, str(benchmark_root), "--case", "sequence_window_fragility-control"]
    return [command, str(inputs / (command + ".json"))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--benchmark-root", type=Path, default=Path(__file__).resolve().parents[1] / "benchmarks"
    )
    args = parser.parse_args()
    root = destination(args.out)
    assert root is not None
    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=False)
    for name, content in fixture_inputs().items():
        (inputs / name).write_bytes(content)
    for command in COMMANDS:
        argv = arguments(command, inputs, root, args.benchmark_root)
        text = StringIO()
        with redirect_stdout(text):
            code = app(
                [*argv, "--out", str(root / command), "--json"],
                prog_name="dvi",
                standalone_mode=False,
            )
        assert code in (None, 0), text.getvalue()
        result = parse_json(text.getvalue())
        assert result["command"] == command and result["exit_status"] == 0
        assert (root / command / "command_result.json").read_text(
            encoding="utf-8"
        ) == text.getvalue()
        print(f"{command}: {result['summary']}")
    print(f"Verified {len(COMMANDS)} commands: {root}")


if __name__ == "__main__":
    main()
