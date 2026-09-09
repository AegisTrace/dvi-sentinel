"""Reproduce the bounded-volume failure and write all reduction evidence."""

from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import RuleHarnessConfig
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.shrinking import FailureShrinker, shrink_artifacts
from dvi_sentinel.variations import plan_variations


def main() -> None:
    root = Path(__file__).parent
    parsed = normalize((root / "probes/events.jsonl").read_bytes(), "jsonl")
    if not parsed.parser_success:
        raise ValueError(parsed.errors)
    rules = RuleHarnessConfig.model_validate(parse_json((root / "probes/rules.json").read_bytes()))
    detector = RuleLogicHarness(
        RuleHarnessConfig(
            kind="rule_logic", rules=tuple(r for r in rules.rules if r.id == "volume")
        )
    )
    policy = VariationPolicy(families=("volume",), max_duplicates=6, max_variants=40)
    plan = plan_variations("shrink-proof", parsed.events, policy, 42)
    initial = max(plan.cases, key=lambda case: len(case.events))
    result = FailureShrinker(detector).shrink(
        parsed.events, initial, policy, DetectionExpectation(detector="lab", signature="volume")
    )
    output = root.parent / "runs/shrinking-proof"
    output.mkdir(parents=True, exist_ok=True)
    for name, contents in shrink_artifacts(result).items():
        (output / name).write_text(contents, encoding="utf-8", newline="\n")
    print(
        f"{result.status}: {len(initial.events)} -> {len(result.events)} events; "
        f"{len(result.trace)} attempts"
    )


if __name__ == "__main__":
    main()
