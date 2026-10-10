from pathlib import Path

import pytest

from dvi_sentinel import __version__
from dvi_sentinel.expert_benchmark_models import ExpertReport
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.lineage_models import ProvenanceDAG
from dvi_sentinel.provenance_bundle import verify_bundle_lineage
from examples import release_v2

ROOT = Path(__file__).resolve().parents[1] / "benchmarks"


@pytest.fixture(scope="module")
def release_files():
    return release_v2.release_bundle(ROOT)


def test_release_binds_all_benchmark_sources_and_detects_tampering(release_files):
    report = ExpertReport.model_validate_json(release_files["benchmark_report.json"])
    assert report.tool_version == __version__
    assert report.scope == "full_suite" and report.passed
    assert len(report.results) == 32
    sources = {entry.path: entry for result in report.results for entry in result.sources}
    for path, entry in sources.items():
        captured = release_files["benchmark_sources/" + path]
        assert captured == (ROOT / path).read_bytes()
        assert byte_digest(captured) == entry.sha256
    dag = ProvenanceDAG.model_validate_json(release_files["provenance_dag.json"])
    primary = next(n for n in dag.nodes if n.artifact.path == "benchmark_report.json")
    assert {p.path for p in primary.parents} == {"benchmark_sources/" + p for p in sources}
    assert not verify_bundle_lineage(release_files)
    changed = release_files | {"benchmark_sources/v2/suite.json": b"{}\n"}
    issues = verify_bundle_lineage(changed)
    assert any(i.path == "benchmark_sources/v2/suite.json" for i in issues)
    assert any(i.path == "benchmark_report.json" for i in issues)


def test_release_rejects_source_changed_after_benchmark(monkeypatch, release_files):
    report = ExpertReport.model_validate_json(release_files["benchmark_report.json"])
    monkeypatch.setattr(release_v2, "run_expert_benchmarks", lambda root: report)
    read = release_v2.read_fixture

    def changed_source(root, relative):
        data = read(root, relative)
        return data + b" " if relative == "v2/suite.json" else data

    monkeypatch.setattr(release_v2, "read_fixture", changed_source)
    with pytest.raises(ValueError, match="source bytes changed"):
        release_v2.release_bundle(ROOT)
