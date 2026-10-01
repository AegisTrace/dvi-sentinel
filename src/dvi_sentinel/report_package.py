"""Deterministic local report assets and a bounded, non-recursive ZIP (A)."""

from collections.abc import Mapping
from importlib.resources import files
from io import BytesIO
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from dvi_sentinel.artifact_models import (
    LINEAGE_FILES,
    MAX_ARTIFACT_BYTES,
    ArtifactEntry,
    ArtifactManifest,
    RunRecord,
)
from dvi_sentinel.lineage import (
    bound_contents,
    build_lineage,
    byte_digest,
    encoded,
    lineage_artifacts,
)
from dvi_sentinel.lineage_models import ProvenanceDAG
from dvi_sentinel.serialization import parse_json

ASSET_PATH = "report_assets/report.css"
ARCHIVE_PATH = "report_bundle.zip"


def report_assets() -> dict[str, bytes]:
    return {ASSET_PATH: files("dvi_sentinel").joinpath("templates/report.css").read_bytes()}


def report_archive(contents: Mapping[str, bytes]) -> bytes:
    """Build from confined bytes only. Never read or extract an input ZIP."""
    bound_contents(contents)
    dag = ProvenanceDAG.model_validate(parse_json(contents["provenance_dag.json"]))
    captured = {p: b for p, b in contents.items() if p not in LINEAGE_FILES | {ARCHIVE_PATH}}
    inner_dag = build_lineage(
        captured,
        tuple(node.specification() for node in dag.nodes if node.artifact.path != ARCHIVE_PATH),
    )
    captured.update(lineage_artifacts(inner_dag, captured))
    record = RunRecord.model_validate(parse_json(captured["run.json"]))
    manifest = ArtifactManifest(
        schema_version="2",
        tool_version=record.tool_version,
        run_id=record.run_id,
        artifacts=tuple(
            ArtifactEntry(path=p, sha256=byte_digest(b), size_bytes=len(b))
            for p, b in sorted(captured.items())
        ),
    )
    captured["manifest.json"] = encoded(manifest)
    # ZIP_STORED provides stable bytes across supported Python/zlib versions.
    if sum(len(b) + 2 * len(p.encode()) + 128 for p, b in captured.items()) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-REPORT-BOUNDS: portable archive exceeds 32 MiB")
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_STORED, allowZip64=False) as archive:
        for path, content in sorted(captured.items()):
            info = ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return buffer.getvalue()


def verify_advanced_report(contents: Mapping[str, bytes]) -> None:
    """Recheck the displayed native evidence, primary run data, assets and optional outer ZIP."""
    from dvi_sentinel.advanced_report_evidence import advanced_evidence, read_rows
    from dvi_sentinel.artifact_models import VariationArtifact
    from dvi_sentinel.comparison import compare_snapshots
    from dvi_sentinel.comparison_models import ComparisonSnapshot, ComparisonThresholds
    from dvi_sentinel.models import TelemetryEvent
    from dvi_sentinel.provenance import build_provenance
    from dvi_sentinel.provenance_bundle import PRESENTATION_FILES
    from dvi_sentinel.report_models import ReportDocument
    from dvi_sentinel.reports import LIMITATIONS
    from dvi_sentinel.score_models import ResilienceFrontier
    from dvi_sentinel.shrinking_models import MinimalCounterexample

    report = ReportDocument.model_validate(parse_json(contents["report.json"]))
    run = RunRecord.model_validate(parse_json(contents["run.json"]))
    score = ResilienceFrontier.model_validate(parse_json(contents["score.json"]))
    snapshot = ComparisonSnapshot.model_validate(parse_json(contents["comparison.json"]))
    entries = tuple(
        ArtifactEntry(path=p, sha256=byte_digest(b), size_bytes=len(b))
        for p, b in sorted(contents.items())
        if p not in LINEAGE_FILES | PRESENTATION_FILES or p == "regression.json"
    )
    provenance = build_provenance(
        run,
        entries,
        read_rows(contents["normalized_events.jsonl"], TelemetryEvent),
        tuple(row.variation for row in read_rows(contents["variations.jsonl"], VariationArtifact)),
        snapshot.probes,
        snapshot.differential,
        score,
    )
    minimum = (
        MinimalCounterexample.model_validate(parse_json(contents["minimal_case.json"]))
        if "minimal_case.json" in contents
        else None
    )
    regression = None
    if "regression_baseline.json" in contents:
        regression = compare_snapshots(
            ComparisonSnapshot.model_validate(parse_json(contents["regression_baseline.json"])),
            snapshot,
            ComparisonThresholds.model_validate(parse_json(contents["regression_thresholds.json"])),
        )
    if (
        report.advanced != advanced_evidence(contents)
        or report.run != run
        or report.frontier != score
        or report.cases != snapshot.assessments
        or report.probes != snapshot.probes
        or report.differential != snapshot.differential
        or report.minimal != minimum
        or report.provenance != provenance
        or report.regression != regression
        or report.limitations != LIMITATIONS
        or (regression is not None and contents.get("regression.json") != encoded(regression))
        or any(contents.get(p) != b for p, b in report_assets().items())
    ):
        raise ValueError("DVI-REPORT-EVIDENCE: report differs from verified source bytes or assets")
    if ARCHIVE_PATH in contents and contents[ARCHIVE_PATH] != report_archive(contents):
        raise ValueError("DVI-REPORT-ARCHIVE: archive differs from the self-contained bundle")
