"""Project a synthetic flow through seven declared local schema/metadata subsets."""

import argparse
from pathlib import Path

from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.schema_mapping import mapping_artifacts
from dvi_sentinel.serialization import parse_json


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/profile-proof"))
    args = parser.parse_args()
    destination: Path = args.out
    if str(destination).startswith(("\\\\", "//")) or any(
        part.is_symlink() or part.is_junction() for part in (destination, *destination.parents)
    ):
        parser.error("output must use a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination == destination.parent or destination.exists():
        parser.error("output must be a new local directory; existing files are never replaced")
    sample = TelemetryEvent.model_validate(
        {
            "event_id": "fixture:profile-flow",
            "timestamp": "2026-01-01T00:00:00.123456Z",
            "semantics": {
                "category": "flow",
                "action": "observed",
                "protocol": "tcp",
                "source": {"address": "192.0.2.1", "port": 12345},
                "destination": {"address": "198.51.100.2", "port": 443},
            },
            "raw": RawSource.from_payload({"kind": "synthetic_flow"}, adapter="jsonl"),
        }
    )
    files = mapping_artifacts((sample,))
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "schema_profiles").mkdir()
    for name, content in files.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    summaries = parse_json(files["roundtrip_report.json"])
    print("profiles=7")
    print({row["profile_id"]: row["decision"] for row in summaries["records"]})


if __name__ == "__main__":
    main()
