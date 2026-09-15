"""Export known and incomplete synthetic semantic signals to a new local directory."""

import argparse
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.ontology import export_ontology, ontology_artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/ontology-proof"))
    args = parser.parse_args()
    destination: Path = args.out
    if str(destination).startswith(("\\\\", "//")) or any(
        part.is_symlink() or part.is_junction() for part in (destination, *destination.parents)
    ):
        parser.error("output must use a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination == destination.parent or destination.exists():
        parser.error("output must be a new local directory; existing files are never replaced")

    parsed = normalize(
        b'{"event_id":"fixture:flow","timestamp":"2026-01-01T00:00:00Z",'
        b'"category":"flow","action":"observed","protocol":"tcp",'
        b'"src_ip":"192.0.2.1","dst_ip":"198.51.100.2"}\n'
        b'{"event_id":"fixture:dns","timestamp":"2026-01-01T00:00:01Z",'
        b'"category":"dns","action":"query","dns_name":"demo.example"}\n',
        "jsonl",
    )
    if not parsed.parser_success:
        raise ValueError(parsed.errors)
    # A model-valid event can still lack the evidence required by a semantic profile.
    missing = TelemetryEvent.model_validate(
        parsed.events[1].model_dump()
        | {
            "event_id": "fixture:missing-question",
            "semantics": {"category": "dns", "action": "query"},
        }
    )
    export = export_ontology((*parsed.events, missing))
    files = ontology_artifacts(export)
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    known = sum(item.state == "known" for item in export.extractions)
    print(f"known={known} unknown={len(export.extractions) - known}; {destination}")


if __name__ == "__main__":
    main()
