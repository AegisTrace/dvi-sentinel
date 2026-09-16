"""Evaluate a bounded flow-to-alert sequence over synthetic local events."""

import argparse
from pathlib import Path

from dvi_sentinel.models import DetectionEvent, RawSource, TelemetryEvent
from dvi_sentinel.temporal import temporal_artifacts


def _flow() -> TelemetryEvent:
    return TelemetryEvent.model_validate(
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
            "entities": [{"kind": "host", "value": "demo.example"}],
        }
    )


def _alert() -> DetectionEvent:
    return DetectionEvent.model_validate(
        {
            "event_id": "fixture:alert",
            "timestamp": "2026-01-01T00:00:02Z",
            "semantics": {"category": "alert", "action": "match"},
            "raw": RawSource.from_payload(
                {"kind": "synthetic_alert"},
                adapter="jsonl",
                original_timestamp="2026-01-01T00:00:02Z",
            ),
            "severity": 4,
            "correlation_id": "flow:1",
            "entities": [{"kind": "host", "value": "demo.example"}],
            "detector": "fixture:detector",
            "signature": "fixture:signature",
            "title": "Fixture alert",
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/temporal-proof"))
    args = parser.parse_args()
    destination: Path = args.out
    if str(destination).startswith(("\\\\", "//")) or any(
        part.is_symlink() or part.is_junction() for part in (destination, *destination.parents)
    ):
        parser.error("output must use a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination == destination.parent or destination.exists():
        parser.error("output must be a new local directory; existing files are never replaced")

    files = temporal_artifacts((_alert(), _flow()), window_ms=5_000, pattern=("flow", "alert"))
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    print(f"artifacts={len(files)}; {destination}")


if __name__ == "__main__":
    main()
