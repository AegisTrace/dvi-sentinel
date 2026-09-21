"""Compare delayed and timely local alerts using nine evidence checks."""

import argparse
from pathlib import Path

from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.fixture_encoding import encode_fixture
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest, LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.oracle_consensus import oracle_artifacts
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.scenario import DetectionExpectation


def fixture(delay_ms: int, *, repetitions: int = 3) -> OracleEvidence:
    event = TelemetryEvent.model_validate(
        {
            "event_id": "fixture:flow",
            "timestamp": "2026-01-01T00:00:00Z",
            "semantics": {
                "category": "flow",
                "action": "observed",
                "protocol": "tcp",
                "source": {"address": "192.0.2.1", "port": 40000},
                "destination": {"address": "198.51.100.2", "port": 443},
            },
            "raw": RawSource.from_payload(
                {"kind": "synthetic_flow"},
                adapter="jsonl",
                original_timestamp="2026-01-01T00:00:00Z",
            ),
            "correlation_id": "flow:1",
        }
    )
    harness = RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic",
            rules=(
                LocalRule(
                    id="fixture:rule",
                    detector="fixture:detector",
                    signature="fixture:signature",
                    title="Synthetic flow observation",
                    delay_ms=delay_ms,
                    conditions=(RuleCondition(field="category", operator="eq", value="flow"),),
                ),
            ),
        )
    )
    subject_id = "fixture:delayed" if delay_ms > 1000 else "fixture:timely"
    return OracleEvidence(
        subject_id=subject_id,
        events=(event,),
        expected=DetectionExpectation(
            detector="fixture:detector",
            signature="fixture:signature",
            correlation_id="flow:1",
            max_delay_ms=1000,
        ),
        observation=harness.evaluate(HarnessRequest(case_id=subject_id, events=(event,))),
        repetitions=tuple(
            harness.evaluate(HarnessRequest(case_id=f"repeat:{index}", events=(event,)))
            for index in range(repetitions)
        ),
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl",
                content=encode_fixture((event,), "canonical_jsonl"),
            ),
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/oracle-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        part.is_symlink() or part.is_junction() for part in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    outputs = {}
    for delay in (2000, 500):
        evidence = fixture(delay)
        # Pin the producer's complete evidence before consumers revalidate and hash it.
        outputs["delayed" if delay > 1000 else "timely"] = oracle_artifacts(
            evidence,
            expected_digest=evidence.stable_digest(),
        )
    destination.mkdir(parents=True, exist_ok=False)
    for case, artifacts in outputs.items():
        (destination / case).mkdir()
        for name, content in artifacts.items():
            with (destination / case / name).open("xb") as stream:
                stream.write(content)
    print("Two local cases, four artifacts each; " + str(destination))


if __name__ == "__main__":
    main()
