"""Execute declared expert fixtures and assert independently specified expected results."""

import hashlib
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from dvi_sentinel.benchmark_models import BenchmarkReport, BenchmarkSuite
from dvi_sentinel.benchmarks import run_benchmarks
from dvi_sentinel.serialization import canonical_json, parse_json

ROOT = Path(__file__).parents[1] / "benchmarks"
FAMILIES = (
    "schema_alias",
    "timestamp_precision",
    "timezone",
    "ordering",
    "optional_field",
    "severity_mapping",
    "correlation_key",
    "benign_noise",
    "volume",
    "adapter_disagreement",
)


@pytest.fixture(scope="module")
def benchmark_report():
    return run_benchmarks(ROOT)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("control", (False, True))
def test_known_fragility_and_control_oracles(benchmark_report, family, control):
    result = next(
        r for r in benchmark_report.results if r.case.family == family and r.case.control == control
    )
    assert result.passed, [(c.name, c.expected, c.observed) for c in result.checks if not c.passed]
    assert result.frontier.baseline.match.status == "detected"
    assert {f.finding_class for f in result.frontier.findings} == set(result.case.finding_classes)
    if control:
        assert not result.frontier.findings and result.minimum is None
    elif family != "adapter_disagreement":
        assert result.minimum.status == "minimized"
        assert (
            result.minimum.baseline.status == "detected" and result.minimum.final.status == "missed"
        )
        assert result.minimum.preservation.valid
    else:
        assert result.minimum is None
        differences = result.differential.cases[0].differences
        assert len(differences) == 1 and differences[0].path == "/semantics/action"
        assert differences[0].finding_class == "adapter_disagreement"


def test_suite_is_deterministic_roundtrippable_and_links_source_evidence(benchmark_report):
    assert len(benchmark_report.results) == 20 and benchmark_report.passed
    assert canonical_json(run_benchmarks(ROOT)) == canonical_json(benchmark_report)
    assert BenchmarkReport.model_validate_json(canonical_json(benchmark_report)) == benchmark_report
    for result in benchmark_report.results:
        for path, expected in result.source_digests.items():
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected
        assert {c.id for c in result.plan.cases} == {a.case_id for a in result.assessments}
        assert not result.plan.event_budget_exhausted


def test_incorrect_expectation_fails_without_changing_measured_evidence(tmp_path, benchmark_report):
    shutil.copytree(ROOT, tmp_path / "suite")
    root = tmp_path / "suite"
    declaration = parse_json((root / "suite.json").read_bytes())
    case = next(c for c in declaration["cases"] if c["id"] == "volume-fragile")
    case["reason_code"] = "DVI-MATCH-DETECTED"
    declaration["cases"] = [case]
    (root / "suite.json").write_text(canonical_json(declaration), encoding="utf-8")
    changed = run_benchmarks(root)
    assert not changed.passed
    result = changed.results[0]
    original = next(r for r in benchmark_report.results if r.case.id == "volume-fragile")
    assert result.frontier == original.frontier and result.minimum == original.minimum
    assert {c.name for c in result.checks if not c.passed} == {"reason_code", "minimum_reason"}


def test_unexpected_counterexample_is_reported_as_a_failed_check(tmp_path):
    root = tmp_path / "suite"
    shutil.copytree(ROOT, root)
    declaration = parse_json((root / "suite.json").read_bytes())
    case = next(c for c in declaration["cases"] if c["id"] == "volume-fragile")
    case["minimum"] = None
    declaration["cases"] = [case]
    (root / "suite.json").write_text(canonical_json(declaration), encoding="utf-8")
    report = run_benchmarks(root)
    assert not report.passed
    assert [(c.name, c.observed) for c in report.results[0].checks if not c.passed] == [
        ("minimum", '"minimized"')
    ]


def test_benchmark_sources_cannot_escape_the_declared_fixture_root(tmp_path):
    declaration = parse_json((ROOT / "suite.json").read_bytes())
    declaration["cases"] = [declaration["cases"][0]]
    declaration["cases"][0]["scenario"] = "../outside.yaml"
    (tmp_path / "suite.json").write_text(canonical_json(declaration), encoding="utf-8")
    with pytest.raises(ValueError, match="DVI-POL"):
        run_benchmarks(tmp_path)


@pytest.mark.parametrize("problem", ["duplicate_id", "bad_range", "ambiguous_target"])
def test_benchmark_contract_rejects_ambiguous_declarations(problem):
    declaration = parse_json((ROOT / "suite.json").read_bytes())
    if problem == "duplicate_id":
        declaration["cases"].append(declaration["cases"][0])
    elif problem == "bad_range":
        declaration["cases"][0]["metrics"][0].update(minimum=1, maximum=0)
    else:
        declaration["cases"][0]["comparison_fixture"] = "equivalent.csv"
    with pytest.raises(ValidationError):
        BenchmarkSuite.model_validate(declaration)
