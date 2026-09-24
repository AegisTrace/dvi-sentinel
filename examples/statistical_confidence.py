"""Measure conditional uncertainty for a synthetic local detector regression."""

import argparse
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.confidence import confidence_artifacts
from dvi_sentinel.confidence_models import ConfidenceEvidence, ConfidenceInput, ConfidenceRun
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest, LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.serialization import canonical_json, digest
from dvi_sentinel.variation_models import EventLineage, Family


def fixture_run(seed: int, *, fragile: bool = False, count: int = 32) -> ConfidenceRun:
    config = RuleHarnessConfig(
        kind="rule_logic",
        rules=tuple(
            LocalRule(
                id=f"fixture:rule:{bucket}",
                detector="fixture:detector",
                signature="fixture:signal",
                title="Synthetic local observation",
                delay_ms=bucket + 1,
                conditions=(RuleCondition(field="raw.bucket", operator="eq", value=bucket),)
                + (
                    (RuleCondition(field="sensor", operator="eq", value="fixture:sensor"),)
                    if fragile
                    else ()
                ),
            )
            for bucket in range(8)
        ),
    )
    harness = RuleLogicHarness(config)
    expected = DetectionExpectation(
        detector="fixture:detector", signature="fixture:signal", max_delay_ms=10
    )
    policy = VariationPolicy(families=("metadata",), optional_fields=("sensor",))
    assessments = []
    proofs = []
    inputs = {}
    for i in range(-1, count):
        original = normalize(
            (
                canonical_json(
                    {
                        "event_id": f"fixture:event:{i + 1}",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "category": "flow",
                        "action": "observed",
                        "protocol": "tcp",
                        "src_ip": "192.0.2.1",
                        "dst_ip": "198.51.100.2",
                        "sensor": "fixture:sensor",
                        "bucket": (i + 1) % 8,
                    }
                )
                + "\n"
            ).encode("utf-8"),
            "jsonl",
        ).events
        events = (
            tuple(
                TelemetryEvent.model_validate(
                    e.model_dump()
                    | {
                        "raw": RawSource.model_validate(
                            e.raw.model_dump() | {"sensor": "FIXTURE:SENSOR"}
                        )
                    }
                )
                for e in original
            )
            if i >= 0 and i % 2 == 0
            else original
        )
        family: Family = "baseline" if i < 0 else "metadata"
        lineage = tuple(
            EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
            for e in original
        )
        preservation = check_candidate(original, events, lineage, policy, family)
        assert preservation.valid
        case_id = f"fixture:seed:{seed}:case:{i + 1}"
        observation = harness.evaluate(HarnessRequest(case_id=case_id, events=events))
        evidence = OracleEvidence(
            subject_id=case_id, events=events, expected=expected, observation=observation
        )
        proofs.append(
            ConfidenceEvidence(evidence=evidence, expected_digest=evidence.stable_digest())
        )
        inputs[case_id] = digest([e.model_dump(mode="json") for e in events])
        assessments.append(
            CaseAssessment(
                case_id=case_id,
                family=family,
                distance=1.0 if events != original else 0.0,
                preservation=preservation,
                parser_success=True,
                match=match_detection(expected, observation, events, preservation=preservation),
            )
        )
    return ConfidenceRun(
        snapshot=ComparisonSnapshot(
            tool_version="2.0.0.dev0",
            scenario_id="fixture:confidence",
            scenario_digest=digest({"scenario": "conditional-statistics"}),
            input_digest=digest({"trials": count}),
            config_digest=policy.stable_digest(),
            detector_digest=config.stable_digest(),
            seed=seed,
            case_input_digests=inputs,
            assessments=tuple(assessments),
        ),
        evidence=tuple(proofs),
    )


def fixture() -> ConfidenceInput:
    return ConfidenceInput(
        previous=tuple(fixture_run(seed) for seed in (11, 22, 33)),
        current=tuple(fixture_run(seed, fragile=True) for seed in (11, 22, 33)),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/confidence-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    request = fixture()
    artifacts = confidence_artifacts(request, expected_digest=request.stable_digest())
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in artifacts.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    print("Three seeds, 32 variants per seed, four statistical artifacts; " + str(destination))


if __name__ == "__main__":
    main()
