"""Shrink four synthetic local failures while retaining measured oracle consensus."""

import argparse
from datetime import timedelta
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.consensus_shrinking import oracle_shrink_artifacts
from dvi_sentinel.consensus_shrinking_models import OracleShrinkInput, OracleShrinkReport
from dvi_sentinel.harness_models import LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.probe_transforms import specifications, transform
from dvi_sentinel.reductions import validate_reduction
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.variation_models import EventLineage, Family, VariationCase


def fixture(mode: str = "metadata", count: int = 6) -> OracleShrinkInput:
    records = [
        {
            "event_id": f"fixture:{i}",
            "timestamp": "2026-01-01T00:00:00Z",
            "category": "flow",
            "action": "observed",
            "protocol": "tcp",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.2",
            "sensor": "fixture:sensor",
            "vendor": "FixtureLab",
            "correlation_id": "flow:1",
        }
        for i in range(count)
    ]
    original = normalize(
        "".join(canonical_json(record) + "\n" for record in records).encode("utf-8"), "jsonl"
    ).events
    family: Family = (
        "timing" if mode == "timing" else "dropout" if mode == "correlation" else "metadata"
    )
    policy = VariationPolicy(
        families=(family,),
        optional_fields=("sensor", "vendor", "correlation_id"),
        max_jitter_ms=100,
    )
    refs = tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in original
    )
    probe = None
    if mode in {"alias", "correlation"}:
        name = "schema_alias" if mode == "alias" else "drop:correlation_id"
        probe = next(spec for spec in specifications() if spec.name == name)
        events, refs, _ = transform(probe, original, policy)
    elif mode == "timing":
        events = tuple(
            TelemetryEvent.model_validate(
                e.model_dump() | {"timestamp": e.timestamp + timedelta(milliseconds=100)}
            )
            for e in original
        )
    else:
        events = tuple(
            TelemetryEvent.model_validate(
                e.model_dump()
                | {
                    "raw": RawSource.model_validate(
                        e.raw.model_dump() | {"sensor": "FIXTURE:SENSOR", "vendor": "FIXTURELAB"}
                    )
                }
            )
            for e in original
        )
    condition = (
        RuleCondition(field="category", operator="eq", value="flow")
        if mode == "timing"
        else RuleCondition(field="raw.src_ip", operator="exists")
        if mode == "alias"
        else RuleCondition(field="correlation_id", operator="eq", value="flow:1")
        if mode == "correlation"
        else RuleCondition(field="sensor", operator="eq", value="fixture:sensor")
    )
    timely = LocalRule(
        id="fixture:timely",
        detector="fixture:detector",
        signature="fixture:signal",
        title="Synthetic local observation",
        conditions=(condition,),
    )
    late = timely.model_copy(
        update={
            "id": "fixture:late",
            "delay_ms": 11,
            "conditions": (RuleCondition(field="category", operator="eq", value="flow"),),
        }
    )
    return OracleShrinkInput(
        original=original,
        case=VariationCase(
            id="fixture:changed",
            family=family,
            parameters=(),
            events=events,
            lineage=refs,
            preservation=validate_reduction(original, events, refs, policy, family, probe),
            distance=float(count),
        ),
        policy=policy,
        expected=DetectionExpectation(
            detector="fixture:detector",
            signature="fixture:signal",
            max_delay_ms=10,
            reference_time=original[0].timestamp if mode == "timing" else None,
        ),
        harness=RuleHarnessConfig(
            kind="rule_logic", rules=(timely,) if mode == "timing" else (timely, late)
        ),
        protected_event_ids=(original[0].event_id,),
        probe=probe,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/oracle-shrinking-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    produced = {}
    for mode in ("metadata", "timing", "alias", "correlation"):
        request = fixture(mode)
        artifacts = oracle_shrink_artifacts(request, expected_digest=request.stable_digest())
        report = OracleShrinkReport.model_validate_json(artifacts["shrunk_case.json"])
        assert report.state == "minimized" and report.final is not None
        assert len(report.final.events) == 1 and report.final.consensus.state == "confirmed"
        produced[mode] = artifacts
    destination.mkdir(parents=True, exist_ok=False)
    for mode, artifacts in produced.items():
        (destination / mode).mkdir()
        for name, content in artifacts.items():
            with (destination / mode / name).open("xb") as stream:
                stream.write(content)
    print("Four local controls, four artifacts each; " + str(destination))


if __name__ == "__main__":
    main()
