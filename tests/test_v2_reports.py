import io
from html.parser import HTMLParser
from zipfile import ZipFile

import pytest

from dvi_sentinel.advanced_report_evidence import ANALYSIS_PATHS, advanced_evidence
from dvi_sentinel.artifact_models import LINEAGE_FILES
from dvi_sentinel.artifact_store import ArtifactError, verify_artifacts, write_artifacts
from dvi_sentinel.lineage import build_lineage, encoded, lineage_artifacts
from dvi_sentinel.lineage_models import ProvenanceDAG
from dvi_sentinel.provenance_bundle import (
    extra_specifications,
    run_specifications,
    verify_bundle_lineage,
    with_artifact_lineage,
)
from dvi_sentinel.report_models import ReportDocument
from dvi_sentinel.report_package import ARCHIVE_PATH, ASSET_PATH, report_archive
from dvi_sentinel.report_rendering import render_html, render_markdown, sections
from dvi_sentinel.reports import build_reports, write_reports
from dvi_sentinel.serialization import canonical_json, parse_json
from examples.advanced_report import fixture_bundle

EXPECTED_SECTIONS = (
    "Executive Summary",
    "Scenario and Inputs",
    "Semantic Signal",
    "Detection Intent",
    "Schema/Profile Mapping",
    "Temporal and Correlation Evidence",
    "Oracle Consensus",
    "Fragility Frontier",
    "Counterfactual Explanation",
    "Minimal Reproducer",
    "Statistical Confidence",
    "Knowledge Graph Summary",
    "Weak Edges",
    "Recommendations",
    "Limitations",
    "Reproduction Commands",
    "Artifact Provenance",
    "Safety Boundary",
)


@pytest.fixture(scope="module")
def native_files():
    return fixture_bundle()


@pytest.fixture(scope="module")
def advanced_bundle(tmp_path_factory, native_files):
    root = tmp_path_factory.mktemp("advanced-parent") / "full"
    write_artifacts(root, native_files)
    generated = build_reports(root, advanced=True)
    combined = native_files | generated
    dag = ProvenanceDAG.model_validate_json(native_files["provenance_dag.json"])
    combined = with_artifact_lineage(combined, declarations=extra_specifications(dag, combined))
    write_artifacts(root, combined, overwrite=True)
    return root, combined, generated


class LocalHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        values = dict(attrs)
        assert not any(k.lower().startswith("on") or k in {"src", "srcset"} for k in values)
        if "href" in values:
            self.links.append(values["href"])
        if "id" in values:
            self.ids.append(values["id"])


def rehash(files):
    dag = ProvenanceDAG.model_validate_json(files["provenance_dag.json"])
    data = {p: b for p, b in files.items() if p not in LINEAGE_FILES}
    changed = build_lineage(data, run_specifications(data) + extra_specifications(dag, data))
    return data | lineage_artifacts(changed, data)


def test_all_eighteen_sections_use_actual_native_evidence(advanced_bundle):
    root, files, _ = advanced_bundle
    doc = ReportDocument.model_validate_json(files["report.json"])
    assert doc.schema_version == "3"
    assert tuple(s.title for s in sections(doc)) == EXPECTED_SECTIONS
    assert all(getattr(doc.advanced, field) is not None for field in ANALYSIS_PATHS)
    assert doc.frontier.metrics.missed == 9 and doc.frontier.metrics.detected == 2
    assert doc.advanced.intent.state == "unknown"  # aggregate rule metadata cannot prove intent
    assert doc.advanced.temporal.state == "unknown"
    assert doc.advanced.oracle.state != "confirmed"
    assert doc.advanced.minimum.state != "minimized"
    assert all(
        g.confidence_class not in {"high", "moderate"} for g in doc.advanced.confidence.groups
    )
    assert "unknown" in files["report.html"].decode()
    assert verify_artifacts(root).valid
    for name, path in ANALYSIS_PATHS.items():
        assert getattr(doc.advanced, name).model_dump(mode="json") == parse_json(files[path])
    recommendations = next(s for s in sections(doc) if s.title == "Recommendations")
    assert "counterfactual_summary.json" in recommendations.references
    assert recommendations.rows
    for row in recommendations.rows:
        for reference in row[1].split("; "):
            artifact, pointer = reference.split("#", 1)
            value = parse_json(files[artifact])
            for part in pointer.split("/")[1:]:
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value is not None


def test_archive_is_deterministic_and_extracted_bundle_is_independently_verified(
    advanced_bundle, tmp_path
):
    root, files, generated = advanced_bundle
    assert report_archive(files) == files[ARCHIVE_PATH]
    assert build_reports(root) == generated  # format persists without --advanced
    extracted = tmp_path / "extracted"
    with ZipFile(io.BytesIO(files[ARCHIVE_PATH])) as archive:
        names = archive.namelist()
        assert names == sorted(names) and ARCHIVE_PATH not in names
        assert set(names) == set(files) - {ARCHIVE_PATH} | {"manifest.json"}
        assert all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in archive.infolist())
        archive.extractall(extracted)  # trusted output generated above; runtime never extracts
    assert verify_artifacts(extracted).valid
    assert (extracted / "report.json").read_bytes() == files["report.json"]
    parsed = LocalHTML()
    parsed.feed(files["report.html"].decode())
    assert len(parsed.ids) == len(set(parsed.ids))
    assert not set(parsed.tags) & {"script", "iframe", "object", "embed", "img"}
    for link in parsed.links:
        assert not link.startswith(("http", "//", "javascript:", "data:", "file:"))
        assert link[1:] in parsed.ids if link.startswith("#") else (extracted / link).is_file()
    css = files[ASSET_PATH].decode()
    assert "url(" not in css and "@import" not in css and "@font-face" not in css


def test_absent_optional_evidence_is_explicit_and_regeneration_is_stable(tmp_path):
    root = tmp_path / "run"
    write_artifacts(root, fixture_bundle(optional=False))
    before = write_reports(root, advanced=True)
    doc = ReportDocument.model_validate_json((root / "report.json").read_bytes())
    assert all(getattr(doc.advanced, name) is None for name in ANALYSIS_PATHS)
    assert tuple(s.title for s in sections(doc)) == EXPECTED_SECTIONS
    assert (root / "report.html").read_text(encoding="utf-8").count("Not supplied:") == 9
    with pytest.raises(ArtifactError, match="EXISTS"):
        write_reports(root, advanced=True)
    assert write_reports(root, overwrite=True).manifest_digest == before.manifest_digest


@pytest.mark.parametrize("path", ["report.html", ASSET_PATH, ARCHIVE_PATH])
def test_rehashed_presentations_assets_and_archive_cannot_replace_verified_output(
    advanced_bundle, path
):
    _, files, _ = advanced_bundle
    damaged = rehash(files | {path: files[path] + b"changed"})
    assert any(i.code == "DVI-LINEAGE-CONTRACT" for i in verify_bundle_lineage(damaged))


@pytest.mark.parametrize("field", ["run", "frontier", "limitations", "advanced"])
def test_rehashed_report_json_cannot_rewrite_source_claims(advanced_bundle, field):
    _, files, _ = advanced_bundle
    data = parse_json(files["report.json"])
    if field == "run":
        data["run"]["command"] = ["different", "invocation"]
    elif field == "frontier":
        data["frontier"]["findings"] = []
    elif field == "limitations":
        data["limitations"] = ["universal confidence"]
    else:
        data["advanced"]["intent"] = None
    doc = ReportDocument.model_validate(data)
    damaged = files | {
        "report.json": encoded(doc),
        "report.html": render_html(doc).encode(),
        "report.md": render_markdown(doc).encode(),
    }
    assert verify_bundle_lineage(rehash(damaged))


@pytest.mark.parametrize(
    "field", ["temporal", "mapping", "oracle", "counterfactual", "confidence", "graph", "minimum"]
)
def test_changed_native_input_cannot_be_reported(native_files, field):
    path = ANALYSIS_PATHS[field]
    data = parse_json(native_files[path])
    data["input_digest"] = "0" * 64
    with pytest.raises(ValueError):
        advanced_evidence(native_files | {path: (canonical_json(data) + "\n").encode()})


def test_escaping_applies_to_all_advanced_text_and_does_not_add_external_links(advanced_bundle):
    _, files, _ = advanced_bundle
    data = parse_json(files["report.json"])
    payload = "<script>bad</script> [remote](https://example.com) {{ 7*7 }} | x"
    data["run"]["configuration"]["metadata"]["description"] = payload
    data["run"]["configuration"]["reporting"]["title"] = payload
    doc = ReportDocument.model_validate(data)
    page, md = render_html(doc), render_markdown(doc)
    assert "<script>" not in page and "&lt;script&gt;" in page and "{{ 7*7 }}" in page
    assert r"\[remote\]" in md and r"\| x" in md and "[remote](https" not in md
    parsed = LocalHTML()
    parsed.feed(page)
    assert not any("example.com" in link for link in parsed.links)


def test_advanced_output_requires_verified_version_two_input(tmp_path, native_files):
    root = tmp_path / "legacy"
    original = {
        p: b
        for p, b in fixture_bundle(optional=False).items()
        if p not in LINEAGE_FILES and p != "scenario.json"
    }
    write_artifacts(root, original)
    with pytest.raises(ArtifactError, match="VERSION"):
        build_reports(root, advanced=True)
    assert not (root / "report.json").exists()
    newer = tmp_path / "newer"
    write_artifacts(newer, native_files)
    (newer / "semantic_loss_report.json").write_bytes(b"{}")
    with pytest.raises(ArtifactError, match="INTEGRITY"):
        build_reports(newer, advanced=True)
    assert not (newer / "report.json").exists()


def test_archive_bound_is_checked_before_zip_publication(advanced_bundle, monkeypatch):
    import dvi_sentinel.report_package as package

    monkeypatch.setattr(package, "MAX_ARTIFACT_BYTES", 1024)
    with pytest.raises(ValueError, match="BOUNDS"):
        report_archive(advanced_bundle[1])


def test_legacy_versions_keep_advanced_field_out_of_serialization(tmp_path):
    root = tmp_path / "run"
    write_artifacts(root, fixture_bundle(optional=False))
    generated = build_reports(root)
    assert parse_json(generated["report.json"])["schema_version"] == "2"
    assert "advanced" not in parse_json(generated["report.json"])
    assert ASSET_PATH not in generated and ARCHIVE_PATH not in generated
    assert b"Executive Summary" not in generated["report.html"]


def test_advanced_regression_survives_packaging_and_rebuild(tmp_path):
    previous, current = tmp_path / "previous", tmp_path / "current"
    source = fixture_bundle(optional=False)
    write_artifacts(previous, source)
    write_artifacts(current, source)
    anchor = write_reports(current, advanced=True, previous=previous)
    assert verify_artifacts(current).valid
    assert write_reports(current, overwrite=True).manifest_digest == anchor.manifest_digest
    doc = ReportDocument.model_validate_json((current / "report.json").read_bytes())
    assert doc.regression.status == "passed"


@pytest.mark.parametrize(
    "name", ["intent", "mapping", "oracle", "counterfactual", "confidence", "graph"]
)
def test_well_formed_native_analysis_from_another_scope_is_rejected(native_files, name):
    from dvi_sentinel.confidence import analyze_confidence
    from dvi_sentinel.confidence_models import ConfidenceInput, ConfidenceReport
    from dvi_sentinel.counterfactual_models import CounterfactualInput, CounterfactualSummary
    from dvi_sentinel.counterfactuals import mine_counterfactuals
    from dvi_sentinel.detection_intent import analyze_intent
    from dvi_sentinel.intent_models import IntentAnalysis
    from dvi_sentinel.metamorphic import analyze_representations
    from dvi_sentinel.metamorphic_models import MetamorphicReport
    from dvi_sentinel.models import TelemetryEvent
    from dvi_sentinel.oracle_consensus import oracle_artifacts
    from dvi_sentinel.oracle_models import OracleConsensus, OracleEvidence

    data = {
        p: b
        for p, b in native_files.items()
        if p not in set(ANALYSIS_PATHS.values()) - {ANALYSIS_PATHS[name]}
    }
    path = ANALYSIS_PATHS[name]
    event = TelemetryEvent.model_validate_json(
        native_files["normalized_events.jsonl"].splitlines()[0]
    )
    other = TelemetryEvent.model_validate(event.model_dump() | {"event_id": "unrelated:event"})
    if name == "intent":
        source = IntentAnalysis.model_validate_json(data[path])
        data[path] = encoded(analyze_intent(source.parsed, (other,)))
    elif name == "mapping":
        source = MetamorphicReport.model_validate_json(data[path])
        request = source.input.model_copy(update={"source": other})
        data[path] = encoded(
            analyze_representations(request, expected_digest=request.stable_digest())
        )
    elif name == "oracle":
        source = OracleConsensus.model_validate_json(data[path])
        request = OracleEvidence.model_validate(
            source.evidence.model_dump()
            | {
                "subject_id": "unrelated:case",
                "observation": source.evidence.observation.model_copy(
                    update={"case_id": "unrelated:case"}
                ),
            }
        )
        data[path] = oracle_artifacts(request, expected_digest=request.stable_digest())[path]
    elif name == "counterfactual":
        source = CounterfactualSummary.model_validate_json(data[path])
        request = CounterfactualInput.model_validate(source.input.model_dump() | {"seed": 99})
        data[path] = encoded(mine_counterfactuals(request, expected_digest=request.stable_digest()))
    elif name == "confidence":
        source = ConfidenceReport.model_validate_json(data[path])
        request_data = source.input.model_dump()
        request_data["current"][0]["snapshot"]["seed"] = 99
        request = ConfidenceInput.model_validate(request_data)
        data[path] = encoded(analyze_confidence(request, expected_digest=request.stable_digest()))
    # Graph retains a coherent study, but its source artifact was omitted above.
    with pytest.raises(ValueError, match="DVI-REPORT-EVIDENCE"):
        advanced_evidence(data)


def test_baseline_event_bound_precedes_expensive_analysis(native_files):
    rows = native_files["normalized_events.jsonl"].splitlines()
    with pytest.raises(ValueError, match="128 baseline"):
        advanced_evidence(native_files | {"normalized_events.jsonl": b"\n".join([rows[0]] * 129)})


def test_capture_rechecks_source_hashes_after_initial_verification(tmp_path, monkeypatch):
    import dvi_sentinel.reports as reports

    root = tmp_path / "race"
    write_artifacts(root, fixture_bundle(optional=False))
    reader = reports.read_fixture

    def changed(directory, name, **kwargs):
        original = reader(directory, name, **kwargs)
        return original + b" " if name == "score.json" else original

    monkeypatch.setattr(reports, "read_fixture", changed)
    with pytest.raises(ArtifactError, match="changed during capture"):
        build_reports(root, advanced=True)
    assert not (root / "report.html").exists()
