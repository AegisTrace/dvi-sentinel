"""Evaluate semantic relations for a synthetic DNS fixture with missing evidence."""

import argparse
from pathlib import Path

from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.ontology import extract_signal
from dvi_sentinel.semantic_algebra import (
    algebra_artifacts,
    bind_invariant,
    bind_transform,
    evaluate_plan,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/algebra-proof"))
    args = parser.parse_args()
    destination: Path = args.out
    if str(destination).startswith(("\\\\", "//")) or any(
        part.is_symlink() or part.is_junction() for part in (destination, *destination.parents)
    ):
        parser.error("output must use a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination == destination.parent or destination.exists():
        parser.error("output must be a new local directory; existing files are never replaced")
    event = TelemetryEvent.model_validate(
        {
            "event_id": "fixture:dns",
            "timestamp": "2026-01-01T00:00:00Z",
            "semantics": {"category": "dns", "action": "query", "dns_name": "demo.example"},
            "raw": RawSource.from_payload({"kind": "synthetic_dns"}, adapter="jsonl"),
        }
    )
    incomplete = TelemetryEvent.model_validate(
        event.model_dump()
        | {
            "event_id": "fixture:missing-question",
            "semantics": event.semantics.model_dump() | {"dns_name": None},
        }
    )
    source, candidate = extract_signal(event), extract_signal(incomplete)
    plan = evaluate_plan(
        bind_transform(source, candidate), bind_invariant(source, ("action", "evidence.dns_name"))
    )
    files = algebra_artifacts(plan)
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    weakening = next(item for item in plan.decisions if item.relation.operation == "weakens")
    print(f"support={weakening.confidence_before.value} -> {weakening.confidence_after.value}")
    print({item.relation.operation: item.truth for item in plan.decisions})


if __name__ == "__main__":
    main()
