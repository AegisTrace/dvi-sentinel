"""Generate deterministic human/machine reports exclusively from verified local evidence."""

import hashlib
from pathlib import Path

from dvi_sentinel.artifact_contract import read_jsonl, read_model
from dvi_sentinel.artifact_models import (
    MAX_ARTIFACT_BYTES,
    ArtifactEntry,
    ArtifactManifest,
    ArtifactVerification,
    RunRecord,
    VariationArtifact,
)
from dvi_sentinel.artifact_store import ArtifactError, verify_artifacts, write_artifacts
from dvi_sentinel.comparison import compare_snapshots
from dvi_sentinel.comparison_models import ComparisonSnapshot, ComparisonThresholds
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.provenance import build_provenance
from dvi_sentinel.report_models import ReportDocument
from dvi_sentinel.report_rendering import render_html, render_markdown
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.score_models import ResilienceFrontier
from dvi_sentinel.shrinking_models import MinimalCounterexample

REPORT_FILES = {"report.json", "report.md", "report.html", "provenance.json", "regression.json"}
LIMITATIONS = (
    "Only local synthetic/documentation fixtures are evaluated;"
    " these results do not establish live detector performance.",
    "A detected baseline is required for variation-associated fragility."
    " Unknown observations are not measured misses or passes.",
    "A robust probe covers its tested counterfactual only. Findings are associations;"
    " ablation necessity is conditional on the fixture.",
    "Distances are comparable within a variation family only."
    " A shrunk case is a local minimum under supported reductions, not a global proof.",
    "Ratios expose denominators; absent samples remain unavailable."
    " Evidence completeness is availability, not correctness or probability.",
    "SHA-256 checks integrity, not authorship. Independently retain the final"
    " manifest digest to detect a coherent bundle rewrite.",
    "Normalized mappings cover the documented DVI subset; no full ECS, OCSF,"
    " OpenTelemetry or Suricata compatibility is claimed.",
)


def _verified(directory: Path) -> ArtifactManifest:
    result = verify_artifacts(directory)
    if not result.valid:
        raise ArtifactError("DVI-REPORT-INTEGRITY: input bundle failed verification")
    return read_model(directory, "manifest.json", ArtifactManifest)


def build_reports(
    directory: Path,
    *,
    previous: Path | None = None,
    thresholds: ComparisonThresholds | None = None,
) -> dict[str, bytes]:
    manifest = _verified(directory)
    entries = {a.path: a for a in manifest.artifacts if a.path not in REPORT_FILES}
    record = read_model(directory, "run.json", RunRecord)
    score = read_model(directory, "score.json", ResilienceFrontier)
    snapshot = read_model(directory, "comparison.json", ComparisonSnapshot)
    files: dict[str, bytes] = {}
    regression = None
    baseline = None
    if previous is not None:
        _verified(previous)
        baseline = read_model(previous, "comparison.json", ComparisonSnapshot)
    elif "regression_baseline.json" in entries:
        baseline = read_model(directory, "regression_baseline.json", ComparisonSnapshot)
    if baseline is not None:
        limits = thresholds or (
            read_model(directory, "regression_thresholds.json", ComparisonThresholds)
            if "regression_thresholds.json" in entries
            else ComparisonThresholds()
        )
        files["regression_baseline.json"] = json_bytes(baseline)
        files["regression_thresholds.json"] = json_bytes(limits)
        regression = compare_snapshots(baseline, snapshot, limits)
        files["regression.json"] = json_bytes(regression)
        for name, data in files.items():
            entries[name] = ArtifactEntry(
                path=name, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data)
            )
    cases = tuple(v.variation for v in read_jsonl(directory, "variations.jsonl", VariationArtifact))
    provenance = build_provenance(
        record,
        tuple(entries[name] for name in sorted(entries)),
        read_jsonl(directory, "normalized_events.jsonl", TelemetryEvent),
        cases,
        snapshot.probes,
        snapshot.differential,
        score,
    )
    document = ReportDocument(
        run=record,
        frontier=score,
        cases=snapshot.assessments,
        probes=snapshot.probes,
        differential=snapshot.differential,
        minimal=read_model(directory, "minimal_case.json", MinimalCounterexample)
        if "minimal_case.json" in entries
        else None,
        regression=regression,
        provenance=provenance,
        limitations=LIMITATIONS,
    )
    files.update(
        {
            "report.json": json_bytes(document),
            "provenance.json": json_bytes(provenance),
            "report.md": render_markdown(document).encode("utf-8"),
            "report.html": render_html(document).encode("utf-8"),
        }
    )
    if any(len(data) > MAX_ARTIFACT_BYTES for data in files.values()):
        raise ArtifactError("DVI-REPORT-SIZE: report exceeds 32 MiB")
    return files


def write_reports(
    directory: Path,
    *,
    previous: Path | None = None,
    overwrite: bool = False,
    thresholds: ComparisonThresholds | None = None,
) -> ArtifactVerification:
    manifest = _verified(directory)
    if not overwrite and any(a.path in REPORT_FILES for a in manifest.artifacts):
        raise ArtifactError("DVI-REPORT-EXISTS: existing reports require explicit overwrite")
    reports = build_reports(directory, previous=previous, thresholds=thresholds)
    contents = {
        a.path: read_fixture(directory, a.path, limit=MAX_ARTIFACT_BYTES)
        for a in manifest.artifacts
        if a.path not in REPORT_FILES
    }
    return write_artifacts(directory, contents | reports, overwrite=True)
