"""Analyze a small local intent against two synthetic DNS events."""

import argparse
from pathlib import Path

from dvi_sentinel.detection_intent import analyze_intent, intent_artifacts
from dvi_sentinel.intent_parsing import parse_intent
from dvi_sentinel.models import RawSource, TelemetryEvent

INTENT = """
intent_id: fixture:dns-intent
title: DNS lookup
condition_shape: all
fields:
  - field: category
    paths: [semantics.category]
    operators:
      - name: eq
        value_json: '\"dns\"'
  - field: dns_name
    paths: [semantics.dns_name]
    operators:
      - name: contains
        value_json: '\"example\"'
"""


def _event(event_id: str, dns_name: str | None) -> TelemetryEvent:
    semantics: dict[str, object] = {"category": "dns", "action": "query"}
    if dns_name is not None:
        semantics["dns_name"] = dns_name
    return TelemetryEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": "2026-01-01T00:00:00Z",
            "semantics": semantics,
            "raw": RawSource.from_payload(
                {"kind": "synthetic_dns"},
                adapter="jsonl",
                original_timestamp="2026-01-01T00:00:00.123Z",
            ),
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/intent-proof"))
    args = parser.parse_args()
    destination: Path = args.out
    if str(destination).startswith(("\\\\", "//")) or any(
        part.is_symlink() or part.is_junction() for part in (destination, *destination.parents)
    ):
        parser.error("output must use a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination == destination.parent or destination.exists():
        parser.error("output must be a new local directory; existing files are never replaced")

    parsed = parse_intent(INTENT)
    events = (_event("fixture:dns-good", "www.example.com"), _event("fixture:dns-missing", None))
    analysis = analyze_intent(parsed, events)
    files = intent_artifacts(parsed, events)
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    print(f"state={analysis.state}; candidates={len(analysis.candidates)}; {destination}")


if __name__ == "__main__":
    main()
