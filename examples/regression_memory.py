"""Persist and reload a four-run local regression/recovery history."""

import argparse
from pathlib import Path

from dvi_sentinel.confidence_models import ConfidenceInput, ConfidenceSettings
from dvi_sentinel.regression_memory import (
    append_record,
    register_baseline,
    regression_memory_artifacts,
)
from dvi_sentinel.regression_memory_io import load_regression_memory
from dvi_sentinel.regression_memory_models import (
    DetectorRevision,
    DriftInput,
    DriftMemory,
    DriftPolicy,
    DriftRecord,
    ProfileStamp,
)
from dvi_sentinel.schema_profiles import schema_profile

if __package__:
    from .statistical_confidence import fixture_run
else:
    from statistical_confidence import fixture_run


def fixture_record(
    sequence: int, *, fragile: bool = False, count: int = 32, seeds: tuple[int, ...] = (11, 22, 33)
) -> DriftRecord:
    measurement = ConfidenceInput(
        current=tuple(fixture_run(seed, fragile=fragile, count=count) for seed in seeds),
        settings=ConfidenceSettings(bootstrap_resamples=100),
    )
    return DriftRecord(
        id=f"fixture:run:{sequence}",
        sequence=sequence,
        detector=DetectorRevision(
            detector_id="fixture:detector",
            version="sensor-dependent-v2" if fragile else "robust-v1",
            comparison_contract="fixture:signal-v1",
            definition_digest=measurement.current[0].snapshot.detector_digest,
        ),
        profiles=(ProfileStamp.from_profile(schema_profile("dvi")),),
        measurement=measurement,
    )


def fixture() -> DriftInput:
    memory = DriftMemory()
    for sequence, fragile in enumerate((False, True, True, False)):
        record = fixture_record(sequence, fragile=fragile)
        memory = append_record(
            memory,
            record,
            expected_digest=memory.stable_digest(),
            expected_record_digest=record.stable_digest(),
        )
        if sequence == 0:
            memory = register_baseline(
                memory, "release", record.id, expected_digest=memory.stable_digest()
            )
    return DriftInput(
        memory=memory,
        current_id="fixture:run:3",
        named_baseline="release",
        # An explicit finite-fixture policy; this is not a population/release claim.
        policy=DriftPolicy(minimum_confidence="low_confidence", max_plausible_detection_drop=0.15),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/regression-memory-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without symlink ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    request = fixture()
    artifacts = regression_memory_artifacts(request, expected_digest=request.stable_digest())
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in artifacts.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    restored = load_regression_memory(
        destination, "regression_memory.json", expected_digest=request.memory.stable_digest()
    )
    assert restored == request.memory and restored.baselines[0].record_id == "fixture:run:0"
    print(
        "Four local runs, one fixed baseline, four reloadable history artifacts; "
        + str(destination)
    )


if __name__ == "__main__":
    main()
