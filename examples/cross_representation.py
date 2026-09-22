"""Measure meaning, timestamp and context retention through eight local representations."""

import argparse
from pathlib import Path

from dvi_sentinel.adapters import normalize
from dvi_sentinel.metamorphic import metamorphic_artifacts
from dvi_sentinel.metamorphic_models import MetamorphicInput, MetamorphicReport
from dvi_sentinel.serialization import canonical_json, parse_json


def fixture() -> MetamorphicInput:
    record = {
        "event_id": "fixture:flow",
        "timestamp": "2026-01-01T00:00:00.123456Z",
        "category": "flow",
        "action": "observed",
        "protocol": "tcp",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.2",
        "correlation_id": "flow:1",
        "sensor": "fixture:sensor",
        "vendor": "FixtureLab",
        "tags": ["synthetic"],
        "labels": ["benign"],
    }
    normalized = normalize(canonical_json(record).encode("utf-8"), "jsonl")
    assert normalized.parser_success
    return MetamorphicInput(source=normalized.events[0])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/cross-representation-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    request = fixture()
    artifacts = metamorphic_artifacts(request, expected_digest=request.stable_digest())
    report = MetamorphicReport.model_validate(parse_json(artifacts["metamorphic_report.json"]))
    assert len(report.results) == 8 and len(report.matrix) == 64
    assert {f.finding_class for f in report.findings} >= {
        "timestamp_precision_loss",
        "metadata_context_loss",
        "unsupported_profile_feature",
    }
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in artifacts.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    print(f"Representations=8; matrix=64; findings={len(report.findings)}; state={report.state}")
    for row in report.results:
        print(f"{row.representation}: {row.state}")
    print(destination)


if __name__ == "__main__":
    main()
