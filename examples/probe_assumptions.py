"""Reproduce the explicit assumption fixtures and write local proof artifacts."""

from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import RuleHarnessConfig
from dvi_sentinel.probes import probes_jsonl, probes_markdown, run_probes
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import parse_json


def main() -> None:
    root = Path(__file__).parent
    events = normalize((root / "probes/events.jsonl").read_bytes(), "jsonl")
    if not events.parser_success:
        raise ValueError(events.errors)
    rules = RuleHarnessConfig.model_validate(parse_json((root / "probes/rules.json").read_bytes()))
    policy = VariationPolicy(
        families=("timing", "ordering", "metadata", "dropout", "noise", "volume"),
        order_independent=True,
        max_duplicates=3,
        max_noise_events=1,
        optional_fields=("sensor", "vendor", "confidence", "correlation_id", "labels", "tags"),
    )
    probes = run_probes(events.events, policy, RuleLogicHarness(rules))
    output = root.parent / "runs/assumption-proof"
    output.mkdir(parents=True, exist_ok=True)
    (output / "assumption_probes.jsonl").write_text(
        probes_jsonl(probes), encoding="utf-8", newline="\n"
    )
    (output / "assumption_probes.md").write_text(
        probes_markdown(probes), encoding="utf-8", newline="\n"
    )
    print(probes_markdown(probes))


if __name__ == "__main__":
    main()
