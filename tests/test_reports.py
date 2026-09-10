import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from dvi_sentinel.artifact_store import ArtifactError, verify_artifacts, write_artifacts
from dvi_sentinel.comparison_models import ComparisonThresholds
from dvi_sentinel.differential import run_differential
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import FixtureResults, HarnessRequest
from dvi_sentinel.probes import run_probes
from dvi_sentinel.report_models import ReportDocument
from dvi_sentinel.report_rendering import render_html, render_markdown
from dvi_sentinel.reports import build_reports, write_reports
from dvi_sentinel.run_artifacts import build_run_artifacts, json_bytes
from dvi_sentinel.scenario import Scenario
from dvi_sentinel.serialization import parse_json


def publish(path, evidence):
    now = datetime(2026, 9, 10, tzinfo=UTC)
    files = build_run_artifacts(
        evidence,
        started_at=now,
        finished_at=now,
        command=("python", "examples/write_run_artifacts.py"),
    )
    write_artifacts(path, files)
    return files


class HTMLInventory(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.links = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attributes = dict(attrs)
        if "href" in attributes:
            self.links.append(attributes["href"])
        if "id" in attributes:
            self.ids.append(attributes["id"])
        assert not any(k.startswith("on") or k == "src" for k in attributes)


def test_report_content_matches_measured_golden_sections(tmp_path, evidence):
    publish(tmp_path / "run", evidence)
    files = build_reports(tmp_path / "run")
    assert set(files) == {"report.json", "report.md", "report.html", "provenance.json"}
    document = ReportDocument.model_validate_json(files["report.json"])
    assert document.frontier.metrics.detected == 2
    assert document.frontier.metrics.missed == 9
    assert document.frontier.metrics.unknown == 0
    assert document.minimal.status == "minimized"
    assert document.regression is None
    markdown = files["report.md"].decode()
    headings = "\n".join(line for line in markdown.splitlines() if line.startswith("## ")) + "\n"
    assert headings == (Path(__file__).parent / "golden/report_headings.txt").read_text()
    assert "2/11 (18.2%)" in files["report.html"].decode()
    assert "DVI-MATCH-NO-CANDIDATE" in files["report.html"].decode()
    assert files == build_reports(tmp_path / "run")


def test_publication_preserves_sources_and_repeated_reports(tmp_path, evidence):
    output = tmp_path / "run"
    original = publish(output, evidence)
    written = write_reports(output)
    assert (
        written.valid
        and verify_artifacts(output, expected_manifest_digest=written.manifest_digest).valid
    )
    for name, content in original.items():
        assert (output / name).read_bytes() == content
    generated = {
        name: (output / name).read_bytes()
        for name in ("report.json", "provenance.json", "report.md", "report.html")
    }
    assert build_reports(output) == generated
    with pytest.raises(ArtifactError, match="EXISTS"):
        write_reports(output)
    assert write_reports(output, overwrite=True).manifest_digest == written.manifest_digest


def test_absent_optional_analyses_have_explicit_sections(tmp_path, evidence):
    publish(tmp_path / "run", replace(evidence, probes=(), differential=None, minimal=None))
    report = build_reports(tmp_path / "run")
    page = report["report.html"].decode()
    for text in (
        "Assumption probes were not requested",
        "Cross-schema comparison was not requested",
        "Failure shrinking was not requested",
        "regression was not measured",
    ):
        assert text in page
    document = parse_json(report["report.json"])
    assert (
        document["probes"] == []
        and document["minimal"] is None
        and document["differential"] is None
    )


def test_report_escaping_cannot_create_markup_links_or_template_execution(tmp_path, evidence):
    publish(tmp_path / "run", evidence)
    document = parse_json(build_reports(tmp_path / "run")["report.json"])
    text = (
        '<script>alert("inert")</script> [link](https://example.com) ![image](x) {{ 7*7 }} | cell'
    )
    document["run"]["configuration"]["reporting"]["title"] = text
    document["run"]["configuration"]["metadata"]["description"] = text
    typed = ReportDocument.model_validate(document)
    page, markdown = render_html(typed), render_markdown(typed)
    assert "<script>" not in page and "&lt;script&gt;" in page and "{{ 7*7 }}" in page
    assert "<script>" not in markdown and "[link](https://example.com)" not in markdown
    assert r"\[link\]" in markdown and r"\| cell" in markdown
    parsed = HTMLInventory()
    parsed.feed(page)
    assert not set(parsed.tags) & {"script", "iframe", "object", "embed", "img", "link"}
    assert len(set(parsed.ids)) == len(parsed.ids)
    assert all(not link.startswith(("http", "//", "javascript:")) for link in parsed.links)
    assert all(link[1:] in parsed.ids for link in parsed.links if link.startswith("#"))


def test_all_finding_references_resolve_to_hashed_source_records(tmp_path, evidence):
    output = tmp_path / "run"
    publish(output, evidence)
    document = ReportDocument.model_validate_json(build_reports(output)["report.json"])
    assert {f.finding_id for f in document.provenance.findings} == {
        f.id for f in document.frontier.findings
    }
    event_ids = {event.event_id for event in document.provenance.events}
    assert {f.source for f in document.frontier.findings} == {"variation", "probe"}
    for finding in document.provenance.findings:
        assert set(finding.event_ids) <= event_ids
        assert finding.scenario_digest == document.run.scenario_digest
        for reference in finding.references:
            data = (output / reference.artifact).read_bytes()
            assert hashlib.sha256(data).hexdigest() == reference.sha256
            if reference.line:
                value = parse_json(data.splitlines()[reference.line - 1])
            elif reference.pointer:
                value = parse_json(data)
            else:
                continue
            for part in reference.pointer.split("/")[1:]:
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value is not None


def changed_detector(evidence, *, raw=False):
    data = evidence.scenario.model_dump()
    rule = data["harness"]["rules"][0]
    rule["max_count"] = None
    if raw:
        rule["conditions"] = [{"field": "raw.src_ip", "operator": "exists"}]
    scenario = Scenario.model_validate(data)
    detector = RuleLogicHarness(scenario.harness)
    events = evidence.plan.cases[0].events
    return replace(
        evidence,
        scenario=scenario,
        minimal=None,
        observations=tuple(
            detector.evaluate(HarnessRequest(case_id=c.id, events=c.events))
            for c in evidence.plan.cases
        ),
        probes=run_probes(events, scenario.variations, detector, expected=scenario.expected),
        differential=run_differential(events, detector, expected=scenario.expected),
    )


def test_schema_findings_reference_actual_case_evidence(tmp_path, evidence):
    output = tmp_path / "run"
    publish(output, changed_detector(evidence, raw=True))
    document = ReportDocument.model_validate_json(build_reports(output)["report.json"])
    schema_ids = {f.id for f in document.frontier.findings if f.source == "differential"}
    assert schema_ids
    for finding in document.provenance.findings:
        if finding.finding_id in schema_ids:
            assert any(
                r.artifact == "differential_schema_report.json" and r.pointer.startswith("/cases/")
                for r in finding.references
            )


def test_regression_report_uses_verified_baseline_and_retains_it(tmp_path, evidence):
    current, previous = tmp_path / "current", tmp_path / "previous"
    publish(previous, changed_detector(evidence))
    publish(current, evidence)
    files = build_reports(current, previous=previous)
    document = ReportDocument.model_validate_json(files["report.json"])
    assert document.regression.status == "regressed" and len(document.regression.newly_missed) == 9
    assert "regression_baseline.json" in files and "regression.json" in files
    assert write_reports(current, previous=previous).valid
    assert build_reports(current) == files
    (previous / "score.json").write_bytes(b"{}")
    with pytest.raises(ArtifactError, match="INTEGRITY"):
        build_reports(current, previous=previous)


def test_invalid_input_bundle_cannot_produce_reports(tmp_path, evidence):
    publish(tmp_path / "run", evidence)
    (tmp_path / "run/score.json").write_bytes(b"{}")
    with pytest.raises(ArtifactError, match="INTEGRITY"):
        build_reports(tmp_path / "run")
    assert not (tmp_path / "run/report.html").exists()


def test_custom_regression_limits_survive_rerender(tmp_path, evidence):
    current, previous = tmp_path / "current", tmp_path / "previous"
    publish(previous, changed_detector(evidence))
    publish(current, evidence)
    limits = ComparisonThresholds(max_detection_rate_drop=1.0, max_new_misses=100)
    files = build_reports(current, previous=previous, thresholds=limits)
    assert parse_json(files["regression.json"])["status"] == "passed"
    assert write_reports(current, previous=previous, thresholds=limits).valid
    assert build_reports(current) == files


def test_unknown_observations_are_reported_without_false_findings(tmp_path, evidence):
    source = FixtureResults(cases=())
    detector = FixtureHarness(source)
    scenario = Scenario.model_validate(
        evidence.scenario.model_dump()
        | {
            "harness": {"kind": "fixture", "path": "missing-observations.json"},
        }
    )
    unavailable = replace(
        evidence,
        scenario=scenario,
        harness_fixture=json_bytes(source),
        probes=(),
        differential=None,
        minimal=None,
        observations=tuple(
            detector.evaluate(HarnessRequest(case_id=c.id, events=c.events))
            for c in evidence.plan.cases
        ),
    )
    publish(tmp_path / "run", unavailable)
    files = build_reports(tmp_path / "run")
    document = ReportDocument.model_validate_json(files["report.json"])
    assert document.frontier.metrics.unknown == 11
    assert document.frontier.metrics.detected == document.frontier.metrics.missed == 0
    assert not document.frontier.findings
    page = files["report.html"].decode()
    assert "DVI-MATCH-HARNESS" in page and "unavailable" in page
