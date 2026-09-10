import hashlib
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dvi_sentinel.artifact_models import REQUIRED_ARTIFACTS, ArtifactManifest
from dvi_sentinel.artifact_store import ArtifactError, verify_artifacts, write_artifacts
from dvi_sentinel.harness import FixtureHarness
from dvi_sentinel.harness_models import FixtureCase, FixtureResults, HarnessRequest
from dvi_sentinel.run_artifacts import FixtureCapture, build_run_artifacts, json_bytes
from dvi_sentinel.scenario import Scenario
from dvi_sentinel.serialization import canonical_json, parse_json

NOW = datetime(2026, 9, 10, tzinfo=UTC)


def bundle(evidence, when=NOW):
    return build_run_artifacts(evidence, started_at=when, finished_at=when, git_commit="a" * 40)


def rewrite_manifest(root, name, data):
    (root / name).write_bytes(data)
    manifest = parse_json((root / "manifest.json").read_bytes())
    entry = next(e for e in manifest["artifacts"] if e["path"] == name)
    entry.update(sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
    (root / "manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")


def test_complete_real_run_has_portable_verified_evidence(tmp_path, evidence):
    files = bundle(evidence)
    assert set(files) >= REQUIRED_ARTIFACTS | {
        "differential_schema_report.json",
        "minimal_case.json",
        "root_cause.json",
        "shrinking_trace.jsonl",
        "minimal_case.md",
        "fixtures/telemetry-000.jsonl",
    }
    output = tmp_path / "complete"
    written = write_artifacts(output, files)
    assert (
        written.valid
        and verify_artifacts(output, expected_manifest_digest=written.manifest_digest).valid
    )
    manifest = ArtifactManifest.model_validate_json((output / "manifest.json").read_bytes())
    for entry in manifest.artifacts:
        data = (output / entry.path).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry.sha256 and len(data) == entry.size_bytes
        assert "\\" not in entry.path and not Path(entry.path).is_absolute()
    score = parse_json(files["score.json"])
    assert score["metrics"]["missed"] > 0
    assert parse_json(files["minimal_case.json"])["status"] == "minimized"
    assert parse_json(files["run.json"])["git_commit"] == "a" * 40


def test_repeated_runs_only_change_documented_clock_fields(tmp_path, evidence):
    first, second = bundle(evidence), bundle(evidence, NOW + timedelta(seconds=1))
    assert {k for k in first if first[k] != second[k]} == {"run.json"}
    left, right = parse_json(first["run.json"]), parse_json(second["run.json"])
    assert {k for k in left if left[k] != right[k]} == {"started_at", "finished_at"}
    for name in ("one", "two"):
        assert write_artifacts(tmp_path / name, first).valid
    assert (tmp_path / "one/manifest.json").read_bytes() == (
        tmp_path / "two/manifest.json"
    ).read_bytes()


@settings(max_examples=8)
@given(
    st.sampled_from(["score.json", "matches.jsonl", "normalized_events.jsonl", "run.json"]),
    st.integers(min_value=0, max_value=1_000_000),
    st.integers(min_value=1, max_value=255),
)
def test_single_byte_mutation_is_detected_and_exact_restoration_recovers(
    evidence, name, offset, mask
):
    with TemporaryDirectory(prefix="dvi-tamper-test-") as temporary:
        root = Path(temporary) / "run"
        anchor = write_artifacts(root, bundle(evidence)).manifest_digest
        path = root / name
        before = path.read_bytes()
        mutated = bytearray(before)
        mutated[offset % len(before)] ^= mask
        path.write_bytes(mutated)
        assert not verify_artifacts(root, expected_manifest_digest=anchor).valid
        path.write_bytes(before)
        assert verify_artifacts(root, expected_manifest_digest=anchor).valid


@pytest.mark.parametrize("kind", ["changed", "missing", "extra", "empty_directory", "manifest"])
def test_tampering_is_detected(tmp_path, evidence, kind):
    output = tmp_path / "run"
    anchor = write_artifacts(output, bundle(evidence)).manifest_digest
    if kind == "changed":
        (output / "score.json").write_bytes(b"{}")
    elif kind == "missing":
        (output / "matches.jsonl").unlink()
    elif kind == "extra":
        (output / "unlisted.txt").write_text("inert")
    elif kind == "empty_directory":
        (output / "unlisted").mkdir()
    else:
        (output / "manifest.json").write_bytes(b'{"schema_version":"99"}')
    assert not verify_artifacts(output, expected_manifest_digest=anchor).valid


@pytest.mark.parametrize(
    "name", ["score.json", "matches.jsonl", "normalized_events.jsonl", "root_cause.json"]
)
def test_rehashed_but_inconsistent_evidence_fails_contract(tmp_path, evidence, name):
    output = tmp_path / "run"
    write_artifacts(output, bundle(evidence))
    rewrite_manifest(output, name, b"{}\n")
    result = verify_artifacts(output)
    assert not result.valid and result.issues[0].code == "DVI-ARTIFACT-CONTRACT"


def test_external_anchor_detects_coherent_manifest_rewrite(tmp_path, evidence):
    output = tmp_path / "run"
    anchor = write_artifacts(output, bundle(evidence)).manifest_digest
    record = parse_json((output / "run.json").read_bytes())
    record["command"] = ["different", "invocation"]
    rewrite_manifest(output, "run.json", (canonical_json(record) + "\n").encode())
    assert verify_artifacts(output).valid
    assert not verify_artifacts(output, expected_manifest_digest=anchor).valid


def test_validly_typed_but_rehashed_score_cannot_change_measured_counts(tmp_path, evidence):
    output = tmp_path / "run"
    write_artifacts(output, bundle(evidence))
    score = parse_json((output / "score.json").read_bytes())
    score["metrics"]["missed"] += 1
    rewrite_manifest(output, "score.json", (canonical_json(score) + "\n").encode())
    result = verify_artifacts(output)
    assert not result.valid and result.issues[0].code == "DVI-ARTIFACT-CONTRACT"


def test_overwrite_requires_verified_owned_output_and_explicit_choice(tmp_path, evidence):
    output = tmp_path / "run"
    files = bundle(evidence)
    write_artifacts(output, files)
    with pytest.raises(ArtifactError, match="EXISTS"):
        write_artifacts(output, files)
    assert write_artifacts(
        output, bundle(evidence, NOW + timedelta(seconds=1)), overwrite=True
    ).valid
    (output / "personal.txt").write_text("preserve")
    with pytest.raises(ArtifactError, match="EXISTS"):
        write_artifacts(output, files, overwrite=True)
    assert (output / "personal.txt").read_text() == "preserve"
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ArtifactError, match="EXISTS"):
        write_artifacts(empty, files, overwrite=True)


def test_failed_publication_restores_prior_bundle_and_cleans_stage(tmp_path, evidence, monkeypatch):
    output = tmp_path / "run"
    written = write_artifacts(output, bundle(evidence))
    original_replace = os.replace

    def fail_stage(source, destination):
        if Path(source).name.startswith(".dvi-stage-"):
            raise OSError("injected rename failure")
        return original_replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_stage)
    with pytest.raises(OSError, match="injected"):
        write_artifacts(output, bundle(evidence, NOW + timedelta(seconds=1)), overwrite=True)
    assert verify_artifacts(output, expected_manifest_digest=written.manifest_digest).valid
    assert sorted(p.name for p in tmp_path.iterdir()) == ["run"]


@pytest.mark.parametrize(
    "name", ["../escape", "C:/escape", "con.txt", "a\\b", "UPPER.json", "a//b"]
)
def test_nonportable_paths_rejected_before_any_output(tmp_path, evidence, name):
    with pytest.raises(ValueError, match="PATH"):
        write_artifacts(tmp_path / "run", bundle(evidence) | {name: b"inert"})
    assert not list(tmp_path.iterdir())


def test_invalid_staging_never_publishes_or_damages_existing_output(tmp_path, evidence):
    files = bundle(evidence) | {"score.json": b"{}"}
    with pytest.raises(ArtifactError, match="VERIFY"):
        write_artifacts(tmp_path / "run", files)
    assert not list(tmp_path.iterdir())


def test_fixture_harness_source_is_captured_and_required(tmp_path, evidence):
    fixture = FixtureResults(
        cases=tuple(
            FixtureCase(case_id=o.case_id, detections=o.detections) for o in evidence.observations
        )
    )
    scenario = Scenario.model_validate(
        evidence.scenario.model_dump() | {"harness": {"kind": "fixture", "path": "detector.json"}}
    )
    harness = FixtureHarness(fixture)
    captured = replace(
        evidence,
        scenario=scenario,
        harness_fixture=json_bytes(fixture),
        probes=(),
        differential=None,
        minimal=None,
        observations=tuple(
            harness.evaluate(HarnessRequest(case_id=c.id, events=c.events))
            for c in evidence.plan.cases
        ),
    )
    files = bundle(captured)
    assert files["fixtures/detector-results.json"] == json_bytes(fixture)
    assert write_artifacts(tmp_path / "run", files).valid
    with pytest.raises(ArtifactError, match="HARNESS"):
        bundle(replace(captured, harness_fixture=None))


def test_assembly_rejects_missing_or_mismatched_run_inputs(evidence):
    with pytest.raises(ArtifactError, match="INPUT"):
        bundle(replace(evidence, fixtures=()))
    with pytest.raises(ArtifactError, match="OBSERVATIONS"):
        bundle(replace(evidence, observations=evidence.observations[1:]))
    bad = FixtureCapture(evidence.fixtures[0].specification, b"{}\n")
    with pytest.raises(ArtifactError, match="INPUT"):
        bundle(replace(evidence, fixtures=(bad,)))
