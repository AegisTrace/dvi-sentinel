"""Measure timely, late and duplicate observations through the local discovery queue."""

import argparse
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.coverage_models import CoverageCaseInput, SemanticCoverage
from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.fixture_encoding import encode_fixture
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest, LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.scenario import DetectionExpectation
from dvi_sentinel.semantic_coverage import coverage_artifacts
from dvi_sentinel.serialization import canonical_json, digest, parse_json


def fixture(case_id: str, delay_ms: int) -> CoverageCaseInput:
    record = {
        "event_id": "fixture:flow",
        "timestamp": "2026-01-01T00:00:00Z",
        "category": "flow",
        "action": "observed",
        "protocol": "tcp",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.2",
        "correlation_id": "flow:1",
    }
    normalized = normalize(canonical_json(record).encode(), "jsonl")
    assert normalized.parser_success
    events = normalized.events
    harness = RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic",
            rules=(
                LocalRule(
                    id="fixture:rule",
                    detector="fixture:detector",
                    signature="fixture:signal",
                    title="Synthetic flow observation",
                    delay_ms=delay_ms,
                    conditions=(RuleCondition(field="category", operator="eq", value="flow"),),
                ),
            ),
        )
    )
    evidence = OracleEvidence(
        subject_id=case_id,
        events=events,
        expected=DetectionExpectation(
            detector="fixture:detector",
            signature="fixture:signal",
            correlation_id="flow:1",
            max_delay_ms=1000,
        ),
        observation=harness.evaluate(HarnessRequest(case_id=case_id, events=events)),
        repetitions=tuple(
            harness.evaluate(HarnessRequest(case_id=f"repeat:{index}", events=events))
            for index in range(3)
        ),
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl", content=encode_fixture(events, "canonical_jsonl")
            ),
        ),
    )
    return CoverageCaseInput(
        evidence=evidence,
        expected_digest=evidence.stable_digest(),
        reference_events=events,
        reference_digest=digest([e.model_dump(mode="json") for e in events]),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/coverage-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    inputs = (
        fixture("coverage:timely", 500),
        fixture("coverage:late", 2000),
        fixture("coverage:duplicate", 500),
    )
    artifacts = coverage_artifacts(inputs, seed=42)
    report = SemanticCoverage.model_validate(parse_json(artifacts["semantic_coverage.json"]))
    assert report.evidence_gate.passed
    assert sum(row.retained for row in report.retention) == 2
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in artifacts.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    print(
        f"Cases={len(report.cases)}; retained=2; measured tokens={len(report.tokens)}; "
        f"evidence gate={report.evidence_gate.state}"
    )
    print(destination)


if __name__ == "__main__":
    main()
