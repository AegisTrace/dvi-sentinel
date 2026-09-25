import hashlib
import os
import subprocess
import sys
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
from dvi_sentinel.lineage import build_lineage, lineage_artifacts
from dvi_sentinel.lineage_models import LineageSpec, ProvenanceDAG
from dvi_sentinel.provenance_bundle import (
    evidence_summary,
    run_specifications,
    with_artifact_lineage,
)
from dvi_sentinel.report_models import ReportDocument
from dvi_sentinel.reports import build_reports, write_reports
from dvi_sentinel.run_artifacts import FixtureCapture, build_run_artifacts, json_bytes
from dvi_sentinel.scenario import Scenario
from dvi_sentinel.serialization import canonical_json, parse_json

NOW = datetime(2026, 9, 10, tzinfo=UTC)


def test_versioned_bundle_lineage_and_report_regeneration(tmp_path, evidence):
    legacy = bundle(evidence)
    v2 = with_artifact_lineage(legacy)
    root = tmp_path / "v2"
    write_artifacts(root, v2)
    assert parse_json((root / "manifest.json").read_bytes())["schema_version"] == "2"
    report = build_reports(root)
    document = ReportDocument.model_validate_json(report["report.json"])
    dag = ProvenanceDAG.model_validate_json(v2["provenance_dag.json"])
    assert document.schema_version == "2" and document.lineage == evidence_summary(dag)
    assert b"provenance_dag.json" in report["report.html"]
    assert b"Artifact lineage and integrity" in report["report.md"]
    written = write_reports(root)
    assert (
        written.valid
        and verify_artifacts(root, expected_manifest_digest=written.manifest_digest).valid
    )
    assert write_reports(root, overwrite=True).manifest_digest == written.manifest_digest
    assert build_reports(root) == report
    final_dag = ProvenanceDAG.model_validate_json((root / "provenance_dag.json").read_bytes())
    assert evidence_summary(final_dag) == document.lineage
    assert (
        next(n for n in final_dag.nodes if n.artifact.path == "report.html").parents[0].path
        == "report.json"
    )
    for path, data in legacy.items():
        assert (root / path).read_bytes() == data


@pytest.mark.parametrize("rehashed", [False, True])
def test_bundle_dag_tamper_propagates_even_after_manifest_rehash(tmp_path, evidence, rehashed):
    root = tmp_path / "v2"
    files = with_artifact_lineage(bundle(evidence))
    write_artifacts(root, files)
    name = "fixtures/telemetry-000.jsonl"
    changed = files[name] + b"\n"
    if rehashed:
        rewrite_manifest(root, name, changed)
    else:
        (root / name).write_bytes(changed)
    result = verify_artifacts(root)
    issues = {(i.path, i.code) for i in result.issues}
    assert not result.valid
    assert (name, "DVI-LINEAGE-CHANGED") in issues
    assert ("score.json", "DVI-LINEAGE-PARENT_INVALID") in issues
    assert ("comparison.json", "DVI-LINEAGE-PARENT_INVALID") in issues


def test_bundle_missing_parent_propagates_without_reading_unlisted_paths(
    tmp_path, evidence, monkeypatch
):
    import dvi_sentinel.artifact_store as store

    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    (root / "normalized_events.jsonl").unlink()
    seen = []
    original = store.read_fixture

    def confined(base, path, **kwargs):
        assert base == root.resolve()
        seen.append(path)
        return original(base, path, **kwargs)

    monkeypatch.setattr(store, "read_fixture", confined)
    result = verify_artifacts(root)
    assert not result.valid
    assert any(i.code == "DVI-LINEAGE-MISSING" for i in result.issues)
    assert any(
        i.path == "score.json" and i.code == "DVI-LINEAGE-PARENT_INVALID" for i in result.issues
    )
    assert all(".." not in p and not Path(p).is_absolute() for p in seen)


@pytest.mark.parametrize(
    "missing", ["provenance_dag.json", "artifact_lineage.json", "integrity_report.json"]
)
def test_schema_two_requires_all_lineage_controls(tmp_path, evidence, missing):
    files = with_artifact_lineage(bundle(evidence))
    del files[missing]
    with pytest.raises(ValueError, match="provenance DAG"):
        write_artifacts(tmp_path / "no-output", files)
    assert not (tmp_path / "no-output").exists()


@pytest.mark.parametrize("name", ["artifact_lineage.json", "integrity_report.json"])
def test_rehashed_materialized_lineage_views_are_rederived(tmp_path, evidence, name):
    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    rewrite_manifest(root, name, b"{}\n")
    result = verify_artifacts(root)
    assert not result.valid and any(i.code == "DVI-LINEAGE-VIEW" for i in result.issues)


def test_legacy_manifest_and_report_versions_remain_supported(tmp_path, evidence):
    root = tmp_path / "legacy"
    write_artifacts(root, bundle(evidence))
    assert parse_json((root / "manifest.json").read_bytes())["schema_version"] == "1"
    document = ReportDocument.model_validate_json(build_reports(root)["report.json"])
    assert document.schema_version == "1" and document.lineage is None
    assert "lineage" not in parse_json(build_reports(root)["report.json"])
    assert write_reports(root).valid
    for version, lineage in (("2", None), ("1", {"invalid": "summary"})):
        with pytest.raises(ValueError):
            ReportDocument.model_validate(
                document.model_dump() | {"schema_version": version, "lineage": lineage}
            )


def test_version_one_cannot_smuggle_dag_and_version_two_cannot_silently_drop_it(tmp_path, evidence):
    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    data = parse_json((root / "manifest.json").read_bytes())
    data["schema_version"] = "1"
    (root / "manifest.json").write_text(canonical_json(data), encoding="utf-8")
    assert not verify_artifacts(root).valid
    data["schema_version"] = "2"
    data["artifacts"] = [a for a in data["artifacts"] if a["path"] != "provenance_dag.json"]
    (root / "manifest.json").write_text(canonical_json(data), encoding="utf-8")
    assert not verify_artifacts(root).valid


def test_fixed_dependency_recipe_cannot_be_coherently_reparented(tmp_path, evidence):
    root = tmp_path / "v2"
    files = with_artifact_lineage(bundle(evidence))
    write_artifacts(root, files)
    data = {
        k: v
        for k, v in files.items()
        if k not in {"provenance_dag.json", "artifact_lineage.json", "integrity_report.json"}
    }
    specs = tuple(
        s.model_copy(update={"parents": ("scenario.json",)}) if s.path == "score.json" else s
        for s in run_specifications(data)
    )
    forged = build_lineage(data, specs)
    for name, value in lineage_artifacts(forged, data).items():
        rewrite_manifest(root, name, value)
    result = verify_artifacts(root)
    assert not result.valid and any(i.code == "DVI-LINEAGE-CONTRACT" for i in result.issues)


def test_unknown_extra_artifact_requires_declared_parents(tmp_path, evidence):
    files = bundle(evidence) | {"extra.json": b"declared local evidence"}
    with pytest.raises(ValueError, match="INVENTORY"):
        with_artifact_lineage(files)
    with pytest.raises(ValueError, match="INTEGRITY"):
        with_artifact_lineage(
            files, declarations=(LineageSpec(path="extra.json", kind="analysis"),)
        )
    declarations = (
        LineageSpec(path="extra.json", kind="oracle_decision", parents=("matches.jsonl",)),
    )
    root = tmp_path / "v2"
    assert write_artifacts(root, with_artifact_lineage(files, declarations=declarations)).valid
    assert write_reports(root).valid


def test_scenario_and_report_summary_cannot_drift(tmp_path, evidence):
    files = bundle(evidence)
    with pytest.raises(ValueError, match="SCENARIO"):
        with_artifact_lineage(files | {"scenario.json": b"{}"})
    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(files))
    write_reports(root)
    contents = {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    }
    report = parse_json(contents["report.json"])
    report["lineage"]["evidence_sha256"] = "0" * 64
    contents["report.json"] = (canonical_json(report) + "\n").encode()
    with pytest.raises(ValueError, match="provenance summary"):
        with_artifact_lineage(contents)


def test_lineage_external_pin_still_detects_coherent_rewrite(tmp_path, evidence):
    root = tmp_path / "v2"
    first = write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    second = write_artifacts(
        root, with_artifact_lineage(bundle(evidence, NOW + timedelta(seconds=1))), overwrite=True
    )
    assert second.valid and first.manifest_digest != second.manifest_digest
    assert not verify_artifacts(root, expected_manifest_digest=first.manifest_digest).valid


@pytest.mark.parametrize(
    "name", ["report.json", "report.md", "report.html", "provenance.json", "scenario.json"]
)
def test_rehashed_dag_does_not_bypass_report_or_scenario_contract(tmp_path, evidence, name):
    from dvi_sentinel.artifact_models import LINEAGE_FILES

    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    write_reports(root)
    contents = {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file() and p.name not in LINEAGE_FILES | {"manifest.json"}
    }
    if name == "report.json":
        report = parse_json(contents[name])
        report["lineage"]["evidence_sha256"] = "0" * 64
        contents[name] = (canonical_json(report) + "\n").encode()
    else:
        contents[name] += b"\n"
    forged = build_lineage(contents, run_specifications(contents))
    for path, data in (contents | lineage_artifacts(forged, contents)).items():
        rewrite_manifest(root, path, data)
    result = verify_artifacts(root)
    assert not result.valid and any(i.code == "DVI-LINEAGE-CONTRACT" for i in result.issues)


def test_lineage_regression_report_preserves_baseline_source_roots(tmp_path, evidence):
    prior, current = tmp_path / "prior", tmp_path / "current"
    for root in (prior, current):
        write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    first = write_reports(current, previous=prior)
    assert first.valid
    assert write_reports(current, overwrite=True).manifest_digest == first.manifest_digest


@pytest.mark.parametrize(
    "path", ["../private.json", "https://example.invalid/data", "fixtures/absent.json"]
)
def test_forged_dag_never_causes_a_metadata_only_file_read(tmp_path, evidence, monkeypatch, path):
    import dvi_sentinel.artifact_store as store

    root = tmp_path / "v2"
    files = with_artifact_lineage(bundle(evidence))
    write_artifacts(root, files)
    data = parse_json(files["provenance_dag.json"])
    data["nodes"][0]["artifact"]["path"] = path
    rewrite_manifest(root, "provenance_dag.json", (canonical_json(data) + "\n").encode())
    original = store.read_fixture

    def read_only_manifest_entries(base, relative, **kwargs):
        assert relative in files or relative == "manifest.json"
        assert relative != path
        return original(base, relative, **kwargs)

    monkeypatch.setattr(store, "read_fixture", read_only_manifest_entries)
    assert not verify_artifacts(root).valid


def test_nested_junction_is_rejected_before_fixture_open(tmp_path, evidence, monkeypatch):
    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    junction = root / "fixtures"
    real = Path.is_junction
    monkeypatch.setattr(Path, "is_junction", lambda self: self == junction or real(self))
    scandir = os.scandir

    def no_junction_traversal(path):
        assert Path(path) != junction
        return scandir(path)

    monkeypatch.setattr(os, "scandir", no_junction_traversal)
    verified = verify_artifacts(root)
    assert not verified.valid
    assert any(
        i.code == "DVI-ARTIFACT-MISSING" and i.path.startswith("fixtures/") for i in verified.issues
    )


def test_verifier_bounds_actual_captured_bytes_not_only_manifest_sizes(
    tmp_path, evidence, monkeypatch
):
    import dvi_sentinel.artifact_store as store

    root = tmp_path / "v2"
    write_artifacts(root, with_artifact_lineage(bundle(evidence)))
    monkeypatch.setattr(store, "MAX_BUNDLE_BYTES", 1)
    result = verify_artifacts(root)
    assert not result.valid
    assert any(i.explanation == "Actual bundle bytes exceed 128 MiB" for i in result.issues)


def test_lineage_example_has_all_twelve_required_kinds_and_refuses_overwrite(tmp_path):
    project = Path(__file__).parents[1]
    destination = tmp_path / "example"
    command = [
        sys.executable,
        str(project / "examples/artifact_lineage.py"),
        "--out",
        str(destination),
    ]
    first = subprocess.run(command, cwd=project, capture_output=True, text=True, check=True)
    assert "lineage verified" in first.stdout
    assert verify_artifacts(destination).valid
    dag = ProvenanceDAG.model_validate_json((destination / "provenance_dag.json").read_bytes())
    assert {n.kind for n in dag.nodes} >= {
        "scenario",
        "input_fixture",
        "normalized_events",
        "schema_projection",
        "variation_case",
        "oracle_decision",
        "match_result",
        "score_result",
        "counterfactual_result",
        "shrunk_case",
        "report",
        "benchmark_result",
    }
    original = (destination / "manifest.json").read_bytes()
    second = subprocess.run(command, cwd=project, capture_output=True, text=True)
    assert second.returncode != 0 and "DVI-ARTIFACT-EXISTS" in second.stderr
    assert (destination / "manifest.json").read_bytes() == original


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
