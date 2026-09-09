"""Write independently normalized schema evidence for robust and fragile local rules."""

from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.serialization import canonical_json


def main() -> None:
    root = Path(__file__).parent
    parsed = normalize((root / "telemetry/generic.jsonl").read_bytes(), "jsonl")
    if not parsed.parser_success:
        raise ValueError(parsed.errors)
    for name, condition in (
        ("robust", RuleCondition(field="category", operator="eq", value="alert")),
        ("fragile", RuleCondition(field="raw.category", operator="exists")),
    ):
        harness = RuleLogicHarness(
            RuleHarnessConfig(
                kind="rule_logic",
                rules=(
                    LocalRule(
                        id=name,
                        detector="lab",
                        signature=name,
                        title="Schema fixture observation",
                        conditions=(condition,),
                    ),
                ),
            )
        )
        result = run_differential(parsed.events, harness)
        output = root.parent / "runs/differential-proof" / name
        output.mkdir(parents=True, exist_ok=True)
        (output / "differential_schema_report.json").write_text(
            canonical_json(result) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(name, {case.representation: case.status for case in result.cases})


if __name__ == "__main__":
    main()
