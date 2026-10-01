"""Generate a verified advanced report from real, deterministic synthetic engine evidence."""

import argparse
from datetime import UTC, datetime
from pathlib import Path

from dvi_sentinel.artifact_store import verify_artifacts, write_artifacts
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.confidence import confidence_artifacts
from dvi_sentinel.confidence_models import ConfidenceEvidence, ConfidenceInput, ConfidenceRun
from dvi_sentinel.consensus_shrinking import oracle_shrink_artifacts
from dvi_sentinel.consensus_shrinking_models import OracleShrinkInput
from dvi_sentinel.counterfactual_models import (
    CounterfactualDimension,
    CounterfactualInput,
    CounterfactualSummary,
)
from dvi_sentinel.counterfactuals import counterfactual_artifacts
from dvi_sentinel.detection_intent import intent_artifacts
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.intent_parsing import intent_from_rule
from dvi_sentinel.knowledge_graph import graph_artifacts
from dvi_sentinel.lineage_models import ArtifactKind, LineageSpec
from dvi_sentinel.metamorphic import metamorphic_artifacts
from dvi_sentinel.metamorphic_models import MetamorphicInput
from dvi_sentinel.oracle_consensus import oracle_artifacts
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.provenance_bundle import with_artifact_lineage
from dvi_sentinel.reports import write_reports
from dvi_sentinel.run_artifacts import RunEvidence, build_run_artifacts
from dvi_sentinel.temporal import temporal_artifacts
from dvi_sentinel.variations import plan_variations
from dvi_sentinel.workflow import prepare_scenario


def fixture_bundle(*, optional: bool = True) -> dict[str, bytes]:
    prepared = prepare_scenario(Path(__file__).parent / "artifact_scenario.yaml")
    scenario, events = prepared.scenario, prepared.events
    assert scenario.harness.kind == "rule_logic"
    plan = plan_variations(scenario.metadata.id, events, scenario.variations, 42)
    observations = tuple(
        prepared.harness.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
    )
    evidence = RunEvidence(
        scenario=scenario, fixtures=prepared.fixtures, plan=plan, observations=observations
    )
    when = datetime(2026, 9, 27, tzinfo=UTC)
    files = build_run_artifacts(
        evidence,
        started_at=when,
        finished_at=when,
        command=("python", "examples/advanced_report.py")
        + (() if optional else ("--without-optional",)),
    )
    specs: list[LineageSpec] = []

    def add(
        group: dict[str, bytes],
        primary: str,
        kind: ArtifactKind,
        parents: tuple[str, ...] = ("normalized_events.jsonl", "scenario.json"),
    ) -> None:
        files.update(group)
        specs.extend(
            LineageSpec(
                path=p, kind=kind, parents=tuple(sorted(parents if p == primary else (primary,)))
            )
            for p in sorted(group)
        )

    if optional:
        add(
            intent_artifacts(intent_from_rule(scenario.harness.rules[0]), events),
            "semantic_loss_report.json",
            "analysis",
        )
        request_map = MetamorphicInput(
            source=events[0], representations=("canonical_jsonl", "ecs_like", "zeek_like")
        )
        add(
            metamorphic_artifacts(request_map, expected_digest=request_map.stable_digest()),
            "metamorphic_report.json",
            "schema_projection",
        )
        add(temporal_artifacts(events), "temporal_summary.json", "analysis")
        proofs = tuple(
            OracleEvidence(
                subject_id=c.id, events=c.events, expected=scenario.expected, observation=o
            )
            for c, o in zip(plan.cases, observations, strict=True)
        )
        add(
            oracle_artifacts(proofs[-1], expected_digest=proofs[-1].stable_digest()),
            "oracle_consensus.json",
            "oracle_decision",
            ("observations.jsonl", "scenario.json", "variations.jsonl"),
        )
        request_cf = CounterfactualInput(
            events=events,
            dimensions=(CounterfactualDimension(name="volume", operation="bounded_volume"),),
            policy=scenario.variations,
            expected=scenario.expected,
            harness=scenario.harness,
            seed=42,
        )
        cf_files = counterfactual_artifacts(request_cf, expected_digest=request_cf.stable_digest())
        add(cf_files, "counterfactual_summary.json", "counterfactual_result")
        cf = CounterfactualSummary.model_validate_json(cf_files["counterfactual_summary.json"])
        add(
            graph_artifacts(cf, expected_digest=cf.stable_digest()),
            "detection_graph.json",
            "analysis",
            ("counterfactual_summary.json",),
        )
        request_conf = ConfidenceInput(
            current=(
                ConfidenceRun(
                    snapshot=ComparisonSnapshot.model_validate_json(files["comparison.json"]),
                    evidence=tuple(
                        ConfidenceEvidence(evidence=p, expected_digest=p.stable_digest())
                        for p in proofs
                    ),
                ),
            )
        )
        add(
            confidence_artifacts(request_conf, expected_digest=request_conf.stable_digest()),
            "confidence.json",
            "score_result",
            ("comparison.json", "observations.jsonl", "variations.jsonl"),
        )
        request_min = OracleShrinkInput(
            original=events,
            case=plan.cases[-1],
            policy=scenario.variations,
            expected=scenario.expected,
            harness=scenario.harness,
            protected_event_ids=tuple(e.event_id for e in events),
        )
        minimum = oracle_shrink_artifacts(request_min, expected_digest=request_min.stable_digest())
        # The legacy trace name belongs to minimal_case.json; retain the V2 trace separately.
        minimum["oracle_shrinking_trace.jsonl"] = minimum.pop("shrinking_trace.jsonl")
        add(
            minimum,
            "shrunk_case.json",
            "shrunk_case",
            ("observations.jsonl", "scenario.json", "variations.jsonl"),
        )
    return with_artifact_lineage(files, declarations=tuple(specs))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/advanced-report-proof"))
    parser.add_argument("--without-optional", action="store_true")
    args = parser.parse_args()
    write_artifacts(args.out, fixture_bundle(optional=not args.without_optional))
    anchor = write_reports(args.out, advanced=True)
    assert verify_artifacts(args.out, expected_manifest_digest=anchor.manifest_digest).valid
    print(f"Verified advanced report: {args.out / 'report.html'}")
    print(f"Manifest SHA-256: {anchor.manifest_digest}")


if __name__ == "__main__":
    main()
