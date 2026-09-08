"""Run a deterministic local plan and print a compact proof summary."""

from collections import Counter
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.variations import plan_variations

inputs = normalize(
    Path(__file__).with_name("telemetry").joinpath("generic.jsonl").read_bytes(), "jsonl"
)
if not inputs.parser_success:
    raise SystemExit("fixture normalization failed")
policy = VariationPolicy(
    families=("timing", "ordering", "metadata", "noise", "volume", "dropout"),
    max_variants=16,
    max_jitter_ms=20,
    max_noise_events=3,
    max_duplicates=3,
    order_independent=True,
    optional_fields=("sensor", "vendor"),
)
plan = plan_variations("example:planner", inputs.events, policy, seed=42)
print(
    canonical_json(
        {
            "plan_digest": plan.stable_digest(),
            "input_digest": plan.input_digest,
            "cases": len(plan.cases),
            "valid_cases": len(plan.valid_cases),
            "families": dict(sorted(Counter(case.family for case in plan.cases).items())),
            "omissions": [item.model_dump(mode="json") for item in plan.omissions],
        }
    )
)
