"""Measure single, combined and absent local failure contributions using declarative controls."""

import argparse
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.counterfactual_models import (
    CounterfactualDimension,
    CounterfactualInput,
    CounterfactualSummary,
)
from dvi_sentinel.counterfactuals import counterfactual_artifacts
from dvi_sentinel.harness_models import LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json, parse_json


def fixture(mode: str = "combination") -> CounterfactualInput:
    record = {
        "event_id": "fixture:flow",
        "timestamp": "2026-01-01T00:00:00Z",
        "category": "flow",
        "action": "observed",
        "protocol": "tcp",
        "severity": 0,
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.2",
        "correlation_id": "flow:1",
        "sensor": "fixture:sensor",
        "vendor": "FixtureLab",
        "tags": ["synthetic"],
    }
    parsed = normalize(canonical_json(record).encode("utf-8"), "jsonl")
    assert parsed.parser_success
    fields = {"single": ("sensor",), "combination": ("sensor", "vendor"), "robust": ("category",)}[
        mode
    ]
    values = {"sensor": "fixture:sensor", "vendor": "FixtureLab", "category": "flow"}
    return CounterfactualInput(
        events=parsed.events,
        dimensions=(
            CounterfactualDimension(name="sensor", operation="drop:sensor"),
            CounterfactualDimension(name="vendor", operation="drop:vendor"),
            CounterfactualDimension(name="tags", operation="drop:tags"),
        ),
        policy=VariationPolicy(families=("dropout",), optional_fields=("sensor", "vendor", "tags")),
        expected=DetectionExpectation(
            detector="fixture:detector", signature="fixture:signal", correlation_id="flow:1"
        ),
        harness=RuleHarnessConfig(
            kind="rule_logic",
            rules=tuple(
                LocalRule(
                    id="fixture:" + field,
                    detector="fixture:detector",
                    signature="fixture:signal",
                    title="Synthetic counterfactual control",
                    conditions=(RuleCondition(field=field, operator="eq", value=values[field]),),
                )
                for field in fields
            ),
        ),
        seed=42,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/counterfactual-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    produced = {}
    for mode, expected in (
        ("single", ("sensor",)),
        ("combination", ("sensor", "vendor")),
        ("robust", None),
    ):
        request = fixture(mode)
        artifacts = counterfactual_artifacts(request, expected_digest=request.stable_digest())
        report = CounterfactualSummary.model_validate(
            parse_json(artifacts["counterfactual_summary.json"])
        )
        assert tuple(f.necessary_dimensions for f in report.findings) == (
            () if expected is None else (expected,)
        )
        produced[mode] = artifacts
        print(f"{mode}: {report.state}; evaluations={report.evaluations}; minimal={expected}")
    destination.mkdir(parents=True, exist_ok=False)
    for mode, artifacts in produced.items():
        directory = destination / mode
        directory.mkdir()
        for name, content in artifacts.items():
            with (directory / name).open("xb") as stream:
                stream.write(content)
    print(destination)


if __name__ == "__main__":
    main()
