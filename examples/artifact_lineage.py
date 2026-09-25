"""Build a real local run, oracle decisions and V1 benchmark evidence with a verified DAG."""

import argparse
from datetime import UTC, datetime
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_store import verify_artifacts, write_artifacts
from dvi_sentinel.benchmarks import run_benchmarks
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.lineage_models import LineageSpec
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.probes import run_probes
from dvi_sentinel.provenance_bundle import with_artifact_lineage
from dvi_sentinel.reports import write_reports
from dvi_sentinel.run_artifacts import (
    FixtureCapture,
    RunEvidence,
    build_run_artifacts,
    json_bytes,
    jsonl_bytes,
)
from dvi_sentinel.scenario_io import load_scenario
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.variations import plan_variations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/artifact-lineage-proof"))
    output = parser.parse_args().out
    root = Path(__file__).resolve().parent
    scenario, _ = load_scenario(root / "artifact_scenario.yaml")
    assert scenario.harness.kind == "rule_logic"
    capture = FixtureCapture(scenario.inputs[0], read_fixture(root, scenario.inputs[0].path))
    events = normalize(capture.content, capture.specification.format).events
    harness = RuleLogicHarness(scenario.harness)
    plan = plan_variations(scenario.metadata.id, events, scenario.variations, 42)
    observations = tuple(
        harness.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
    )
    evidence = RunEvidence(
        scenario=scenario,
        fixtures=(capture,),
        plan=plan,
        observations=observations,
        probes=run_probes(events, scenario.variations, harness, expected=scenario.expected),
        differential=run_differential(events, harness, expected=scenario.expected),
        minimal=FailureShrinker(harness).shrink(
            events,
            max(plan.cases, key=lambda c: len(c.events)),
            scenario.variations,
            scenario.expected,
        ),
    )
    when = datetime(2026, 9, 25, tzinfo=UTC)
    files = build_run_artifacts(
        evidence,
        started_at=when,
        finished_at=when,
        command=("python", "examples/artifact_lineage.py"),
    )
    oracle_input = OracleEvidence(
        subject_id=plan.cases[-1].id,
        events=plan.cases[-1].events,
        expected=scenario.expected,
        observation=observations[-1],
    )
    files["oracle_decisions.jsonl"] = jsonl_bytes(
        evaluate_oracles(oracle_input, expected_digest=oracle_input.stable_digest())
    )
    declarations = [
        LineageSpec(
            path="oracle_decisions.jsonl",
            kind="oracle_decision",
            parents=("observations.jsonl", "scenario.json", "variations.jsonl"),
        )
    ]
    benchmark_root = root.parent / "benchmarks"
    benchmark = run_benchmarks(benchmark_root)
    assert benchmark.passed
    source_paths = {"suite.json"} | {p for r in benchmark.results for p in r.source_digests}
    for path in sorted(source_paths):
        captured = read_fixture(benchmark_root, path)
        assert all(
            byte_digest(captured) == r.source_digests[path]
            for r in benchmark.results
            if path in r.source_digests
        )
        name = "benchmark_sources/" + path
        files[name] = captured
        declarations.append(LineageSpec(path=name, kind="input_fixture", source=True))
    files["benchmark_result.json"] = json_bytes(benchmark)
    declarations.append(
        LineageSpec(
            path="benchmark_result.json",
            kind="benchmark_result",
            parents=tuple(sorted("benchmark_sources/" + p for p in source_paths)),
        )
    )
    write_artifacts(output, with_artifact_lineage(files, declarations=tuple(declarations)))
    anchor = write_reports(output)
    verified = verify_artifacts(output, expected_manifest_digest=anchor.manifest_digest)
    assert verified.valid
    print(f"{verified.run_id}: lineage verified; final manifest {verified.manifest_digest}")


if __name__ == "__main__":
    main()
