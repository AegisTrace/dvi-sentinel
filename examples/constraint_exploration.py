"""Cover safe fixture interactions and execute selected cases against local controls."""

import argparse
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.constraint_models import (
    Binding,
    Constraint,
    ExplorationPlan,
    Parameter,
    ParameterSpace,
)
from dvi_sentinel.exploration import exploration_artifacts
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest, LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import canonical_json, parse_json


def fixture() -> tuple[tuple[TelemetryEvent, ...], ParameterSpace, VariationPolicy]:
    records = [
        {
            "event_id": f"fixture:flow:{index}",
            "category": "flow",
            "action": "observed",
            "timestamp": f"2026-01-01T00:00:0{index}Z",
            "protocol": "tcp",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.2",
            "sensor": "lab-sensor",
        }
        for index in range(2)
    ]
    parsed = normalize(("\n".join(canonical_json(row) for row in records) + "\n").encode(), "jsonl")
    assert parsed.parser_success
    space = ParameterSpace(
        parameters=(
            Parameter(name="order", options=("none", "ordering")),
            Parameter(name="metadata", options=("none", "name:sensor")),
            Parameter(name="volume", options=("none", "duplicates")),
            Parameter(name="noise", options=("none", "benign_noise")),
        ),
        constraints=(
            Constraint(
                id="fixture:separate-additions",
                forbidden=(
                    Binding(parameter="volume", option="duplicates"),
                    Binding(parameter="noise", option="benign_noise"),
                ),
                explanation="Evaluate background additions and duplication separately.",
            ),
        ),
    )
    policy = VariationPolicy(
        families=("ordering", "metadata", "volume", "noise"),
        order_independent=True,
        max_duplicates=2,
        max_noise_events=1,
        optional_fields=("sensor",),
    )
    return parsed.events, space, policy


def check_controls(plan: ExplorationPlan) -> dict[str, int]:
    counts = {}
    for name, conditions in (
        ("robust", (RuleCondition(field="category", operator="eq", value="flow"),)),
        ("sensor-dependent", (RuleCondition(field="sensor", operator="eq", value="lab-sensor"),)),
    ):
        harness = RuleLogicHarness(
            RuleHarnessConfig(
                kind="rule_logic",
                rules=(
                    LocalRule(
                        id="fixture:" + name,
                        detector="fixture:detector",
                        signature="fixture:signature",
                        title="Local exploration control",
                        conditions=conditions,
                    ),
                ),
            )
        )
        results = [
            harness.evaluate(HarnessRequest(case_id=case.id, events=case.events))
            for case in plan.cases
        ]
        assert all(result.status == "complete" for result in results)
        counts[name] = sum(bool(result.detections) for result in results)
    assert counts["robust"] == len(plan.cases)
    assert 0 < counts["sensor-dependent"] < len(plan.cases)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/exploration-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    events, space, policy = fixture()
    artifacts = exploration_artifacts(events, space, policy, seed=42)
    plan = ExplorationPlan.model_validate(parse_json(artifacts["constraint_plan.json"]))
    counts = check_controls(plan)
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in artifacts.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    print(f"Coverage: {plan.covering.state}; selected={len(plan.cases)}; controls={counts}")
    print(destination)


if __name__ == "__main__":
    main()
