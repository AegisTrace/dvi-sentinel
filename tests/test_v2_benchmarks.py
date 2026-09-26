"""Independent paired fixtures, regression exits, retained unknowns and confined evidence."""

import hashlib
import json
import runpy
import shutil
from pathlib import Path

import pytest

from dvi_sentinel.expert_benchmark_models import CATEGORIES, ExpertReport, ExpertSuite
from dvi_sentinel.expert_benchmark_reports import (
    expert_benchmark_artifacts,
    write_expert_benchmarks,
)
from dvi_sentinel.expert_benchmarks import run_expert_benchmarks
from dvi_sentinel.serialization import canonical_json, parse_json

ROOT = Path(__file__).parents[1]
BENCHMARKS = ROOT / "benchmarks"


@pytest.fixture(scope="module")
def report():
    return run_expert_benchmarks(BENCHMARKS)


@pytest.fixture
def copy(tmp_path):
    return Path(shutil.copytree(BENCHMARKS, tmp_path / "benchmarks"))


def change_suite(root, identity, **updates):
    path = root / "v2/suite.json"
    data = json.loads(path.read_bytes())
    next(c for c in data["cases"] if c["benchmark_id"] == identity).update(updates)
    path.write_text(json.dumps(data), encoding="utf-8")


def case(report, identity):
    return next(r for r in report.results if r.case.benchmark_id == identity)


@pytest.mark.parametrize("category", CATEGORIES)
def test_each_category_has_independent_diagnostic_and_control(report, category):
    rows = [r for r in report.results if r.case.category == category]
    assert len(rows) == 2 and {r.case.control for r in rows} == {False, True}
    assert all(r.passed and all(c.passed for c in r.checks) for r in rows)
    positive = next(r for r in rows if not r.case.control)
    control = next(r for r in rows if r.case.control)
    assert positive.evidence != control.evidence
    assert positive.measured.findings
    assert set(positive.measured.findings) - set(control.measured.findings)
    assert positive.case.expected_score_range.metric == positive.measured.score.metric
    assert positive.case.proof_command[3] == positive.case.benchmark_id


def test_all_real_input_bytes_are_pinned_and_scenarios_validated(report):
    assert len(report.results) == 32 and report.scope == "full_suite" and report.passed
    assert len({r.case.benchmark_id for r in report.results}) == 32
    for row in report.results:
        for entry in row.sources:
            content = (BENCHMARKS / entry.path).read_bytes()
            assert (entry.size_bytes, entry.sha256) == (
                len(content),
                hashlib.sha256(content).hexdigest(),
            )
        assert {row.case.scenario, *row.case.fixtures, "v2/suite.json"}.issubset(
            e.path for e in row.sources
        )


def test_report_roundtrip_matrix_references_and_byte_determinism(report):
    first = expert_benchmark_artifacts(report)
    second = expert_benchmark_artifacts(run_expert_benchmarks(BENCHMARKS))
    assert first == second
    assert ExpertReport.model_validate(parse_json(first["benchmark_report.json"])) == report
    matrix = parse_json(first["benchmark_matrix.json"])
    assert matrix["report_sha256"] == hashlib.sha256(first["benchmark_report.json"]).hexdigest()
    assert matrix["passed"] and matrix["scope"] == "full_suite"
    for i, row in enumerate(matrix["rows"]):
        assert row["evidence_ref"] == f"/results/{i}/evidence"
        assert row["evidence_sha256"] == report.results[i].evidence.stable_digest()
        assert row["measured"] == report.results[i].measured.model_dump(mode="json")
    assert b"not a release-safety verdict" in first["benchmark_report.md"]


def test_legacy_evidence_still_exercises_actual_probes_and_shrinker(report):
    rows = [r for r in report.results if r.evidence.kind == "legacy"]
    assert len(rows) == 16
    for row in rows:
        native = row.evidence.result
        assert native.passed and native.frontier.baseline.match.status == "detected"
        if not row.case.control and native.differential is None:
            assert native.minimum.status == "minimized"
            assert native.minimum.preservation.valid
            assert native.minimum.baseline.status == "detected"
            assert native.minimum.final.status == "missed"
            assert row.measured.minimum.status == "minimized"


def test_sequence_boundary_shrinks_one_ms_change_to_one_microsecond_minimum(report):
    row = case(report, "sequence_window_fragility-diagnostic")
    evidence = row.evidence
    assert evidence.baseline.status == "detected" and evidence.match.status == "missed"
    assert evidence.candidate.preservation.valid
    assert evidence.window.outcome == "contradicted"
    assert parse_json(evidence.window.observed_json) == {"delta_ms": 11.0}
    assert parse_json(evidence.window.expected_json)["duration_ms"] == 10
    minimum = evidence.minimum
    deltas = [
        abs((b.timestamp - a.timestamp).total_seconds())
        for a, b in zip(minimum.original_events, minimum.events, strict=True)
    ]
    assert sorted(deltas) == [0.0, 0.000001]
    assert row.measured.minimum.maximum_time_shift_us == 1
    assert minimum.status == "minimized" and minimum.root_cause.status == "measured"
    assert case(report, "sequence_window_fragility-control").evidence.window.outcome == "supported"


def test_unknown_profile_loss_is_not_counted_as_agreement_or_a_detector_miss(report):
    row = case(report, "cross_profile_semantic_loss-diagnostic")
    assert row.passed and row.measured.state == "unknown"
    assert row.measured.score.ratio.value is None
    assert row.measured.score.ratio.denominator == 0 and row.measured.score.unknown == 1
    assert row.evidence.report.results[0].semantic.decision == "unknown"
    assert row.measured.minimum.reason == "analysis_only"
    assert row.measured.oracle_consensus == row.measured.confidence_class == "not_applicable"


def test_wrong_signature_produces_actual_disagreeing_oracles(report):
    row = case(report, "oracle_disagreement-diagnostic")
    evidence = row.evidence.report
    assert evidence.state == "ambiguous" and evidence.evidence is not None
    decisions = {d.oracle_id: d.decision for d in evidence.decisions}
    assert len(decisions) == 9
    assert decisions["detection"] == decisions["statistical"] == "fail"
    assert decisions["temporal"] == "pass"
    assert len(evidence.evidence.repetitions) == 3
    assert all(
        o.detections[0].signature == "different-signal" for o in evidence.evidence.repetitions
    )


def test_statistical_controls_retain_conditional_uncertainty(report):
    small = case(report, "statistical_small_sample_warning-diagnostic")
    large = case(report, "statistical_small_sample_warning-control")
    assert small.measured.score.ratio.denominator == 4
    assert large.measured.score.ratio.denominator == 32
    assert small.measured.confidence_class == "insufficient_sample"
    assert large.measured.confidence_class == "low_confidence"
    assert (
        "small_sample" in small.measured.findings and "small_sample" not in large.measured.findings
    )
    for row in (small, large):
        assert "dependent_fixtures" in row.measured.findings
        assert "seed_stability_unknown" in row.measured.findings
        assert not row.evidence.report.input.settings.independent_trials_assumed


def test_source_tamper_invalidates_unchanged_descendants_and_bundle_view(report):
    broken = case(report, "provenance_tamper_detection-diagnostic").evidence
    intact = case(report, "provenance_tamper_detection-control").evidence
    assert broken.dag == intact.dag
    assert intact.integrity.valid and not intact.bundle_issues
    assert not broken.integrity.valid and broken.bundle_issues
    assert "fixtures/telemetry-000.jsonl" in broken.integrity.invalidated
    assert "score.json" in broken.integrity.invalidated
    before, after = ({e.path: e for e in row.observed} for row in (intact, broken))
    assert before["score.json"] == after["score.json"]
    assert (
        after["fixtures/telemetry-000.jsonl"].size_bytes
        == before["fixtures/telemetry-000.jsonl"].size_bytes + 1
    )


@pytest.mark.parametrize(
    "updates,check",
    [
        ({"expected_findings": ["different_finding"]}, "findings"),
        ({"expected_state": "different_state"}, "state"),
        (
            {"expected_score_range": {"metric": "agreement_rate", "minimum": 0, "maximum": 0}},
            "score_range",
        ),
        ({"expected_oracle_consensus": "confirmed"}, "oracle_consensus"),
        ({"expected_confidence_class": "high_confidence"}, "confidence_class"),
        (
            {"expected_minimal_reproducer": {"status": "unavailable", "reason": "unresolved"}},
            "minimum",
        ),
    ],
)
def test_changed_expectations_fail_without_changing_measurement(copy, report, updates, check):
    identity = "normalization_loss-control"
    change_suite(copy, identity, **updates)
    changed = run_expert_benchmarks(copy, case_id=identity)
    original, observed = case(report, identity), changed.results[0]
    assert not changed.passed and changed.scope == "selected_case"
    assert observed.evidence == original.evidence and observed.measured == original.measured
    assert next(c for c in observed.checks if c.name == check).passed is False
    assert changed.suite_sha256 != report.suite_sha256


def test_control_labels_never_enter_measurement(copy, report):
    change_suite(copy, "normalization_loss-control", control=False)
    change_suite(copy, "normalization_loss-diagnostic", control=True)
    actual = run_expert_benchmarks(copy, case_id="normalization_loss-control").results[0]
    assert actual.evidence == case(report, "normalization_loss-control").evidence


def test_changed_detector_fixture_fails_known_oracle_contract(copy):
    path = copy / "v2/flow.yaml"
    text = path.read_text()
    # Change only the emitted signature; keep the independent expected signature.
    assert text.count("    signature: synthetic-observation") == 1
    path.write_text(
        text.replace("    signature: synthetic-observation", "    signature: different-signal")
    )
    actual = run_expert_benchmarks(copy, case_id="oracle_disagreement-control")
    assert not actual.passed and actual.results[0].measured.oracle_consensus == "ambiguous"
    assert actual.results[0].measured.score.ratio.value == 0


def test_unsupported_intent_stays_unknown_and_fails_supported_expectation(copy):
    path = copy / "v2/intent_flow.yaml"
    path.write_text(path.read_text().replace("name: eq", "name: regex"))
    actual = run_expert_benchmarks(copy, case_id="rule_intent_mismatch-control")
    assert not actual.passed and actual.results[0].measured.state == "unknown"
    assert actual.results[0].measured.score.ratio.value is None


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_id",
        "missing_case",
        "duplicate_role",
        "wrong_engine",
        "proof_command",
        "unknown_field",
        "boolean_seed",
        "range",
    ],
)
def test_malformed_suite_is_rejected_before_measurement(copy, monkeypatch, mutation):
    data = json.loads((copy / "v2/suite.json").read_bytes())
    row = data["cases"][0]
    if mutation == "duplicate_id":
        data["cases"][1] = row
    elif mutation == "missing_case":
        data["cases"].pop()
    elif mutation == "duplicate_role":
        row["control"] = not row["control"]
    elif mutation == "wrong_engine":
        row["operation"] = {"kind": "oracle"}
    elif mutation == "proof_command":
        row["proof_command"] = ["powershell", "Write-Output bad"]
    elif mutation == "unknown_field":
        row["execute"] = "no"
    elif mutation == "boolean_seed":
        data["seed"] = True
    else:
        row["expected_score_range"].update(minimum=0.9, maximum=0.1)
    (copy / "v2/suite.json").write_text(json.dumps(data))
    monkeypatch.setattr(
        "dvi_sentinel.expert_benchmarks.measure_native", lambda *a, **k: pytest.fail("measured")
    )
    with pytest.raises(ValueError):
        run_expert_benchmarks(copy)


@pytest.mark.parametrize(
    "path",
    [
        "../outside.yaml",
        "/outside.yaml",
        "c:/outside.yaml",
        "v2/../flow.yaml",
        "v2/con.yaml",
        "v2/%66low.yaml",
    ],
)
def test_nonportable_scenario_paths_rejected(copy, path):
    change_suite(copy, "normalization_loss-control", scenario=path)
    with pytest.raises(ValueError, match="PATH"):
        run_expert_benchmarks(copy, case_id="normalization_loss-control")


def test_input_inventory_cannot_omit_actual_source(copy):
    change_suite(copy, "normalization_loss-control", fixtures=["v2/dns.jsonl"])
    with pytest.raises(ValueError, match="INVENTORY"):
        run_expert_benchmarks(copy, case_id="normalization_loss-control")


def test_bad_selection_and_event_bounds(copy):
    with pytest.raises(ValueError, match="SELECTION"):
        run_expert_benchmarks(copy, case_id="missing")
    path = copy / "v2/trials_32.jsonl"
    template = json.loads(path.read_text().splitlines()[0])
    path.write_text(
        "".join(json.dumps(template | {"event_id": f"event:{i}"}) + "\n" for i in range(65))
    )
    with pytest.raises(ValueError, match="64 native events"):
        run_expert_benchmarks(copy, case_id="statistical_small_sample_warning-control")


def test_file_and_aggregate_byte_limits(copy, monkeypatch):
    path = copy / "v2/flow.jsonl"
    path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="exceeds"):
        run_expert_benchmarks(copy, case_id="normalization_loss-control")
    monkeypatch.setattr("dvi_sentinel.expert_benchmarks.MAX_INPUT_BYTES", 1)
    with pytest.raises(ValueError, match="16 MiB"):
        run_expert_benchmarks(copy, case_id="sequence_window_fragility-control")


def test_link_or_network_root_is_rejected_before_open(copy, monkeypatch):
    monkeypatch.setattr(Path, "is_junction", lambda p: p == copy)
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("opened linked root"))
    for root in (copy, Path("//server/fixtures")):
        with pytest.raises(ValueError, match="plain local"):
            run_expert_benchmarks(root)


def test_report_cannot_forge_pass_flags_or_drop_results(report):
    data = report.model_dump(mode="json")
    data["results"][0]["checks"][0]["passed"] = False
    with pytest.raises(ValueError, match="CHECKS"):
        ExpertReport.model_validate(data)
    data = report.model_dump(mode="json")
    data["results"].pop()
    with pytest.raises(ValueError, match="SCOPE"):
        ExpertReport.model_validate(data)


def test_export_rejects_forged_measured_summary(report):
    from dvi_sentinel.expert_benchmark_models import acceptance_checks

    row = report.results[0]
    measured = row.measured.model_copy(update={"state": "forged"})
    row = row.model_copy(
        update={"measured": measured, "checks": acceptance_checks(row.case, measured)}
    )
    forged = report.model_copy(update={"results": (row, *report.results[1:])})
    with pytest.raises(ValueError, match="PROJECTION"):
        expert_benchmark_artifacts(forged)


def test_new_directory_writes_are_exact_and_refuse_overwrite(tmp_path, report, monkeypatch):
    destination = tmp_path / "output"
    expected = expert_benchmark_artifacts(report)
    write_expert_benchmarks(destination, report)
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == expected
    with pytest.raises(ValueError, match="new local directory"):
        write_expert_benchmarks(destination, report)
    monkeypatch.setattr("dvi_sentinel.expert_benchmark_reports.MAX_OUTPUT_BYTES", 1)
    with pytest.raises(ValueError, match="32 MiB"):
        write_expert_benchmarks(tmp_path / "bounded", report)
    assert not (tmp_path / "bounded").exists()


def test_cli_exit_codes_and_selected_scope(copy, tmp_path, capsys):
    main = runpy.run_path(str(ROOT / "examples/run_v2_benchmarks.py"))["main"]
    identity = "normalization_loss-control"
    args = ["--root", str(copy), "--case", identity, "--out", str(tmp_path / "passed")]
    assert main(args) == 0
    assert "selected_case: 1/1" in capsys.readouterr().out
    report = json.loads((tmp_path / "passed/benchmark_report.json").read_bytes())
    assert report["scope"] == "selected_case" and len(report["results"]) == 1
    change_suite(
        copy, identity, expected_state="<script>alert(1)</script>|[link](https://invalid.example)"
    )
    args[-1] = str(tmp_path / "failed")
    assert main(args) == 1
    markdown = (tmp_path / "failed/benchmark_report.md").read_text()
    assert "<script>" not in markdown and "&lt;script&gt;" in markdown
    assert "\\|\\[link\\]" in markdown
    with pytest.raises(SystemExit) as invalid:
        main(args)
    assert invalid.value.code == 2
    args[-1] = str(tmp_path / "invalid")
    args[3] = "missing"
    with pytest.raises(SystemExit) as invalid:
        main(args)
    assert invalid.value.code == 2 and not (tmp_path / "invalid").exists()


def test_suite_roundtrip_does_not_change_declared_oracles():
    data = parse_json((BENCHMARKS / "v2/suite.json").read_bytes())
    suite = ExpertSuite.model_validate(data)
    assert parse_json(canonical_json(suite)) == data


def test_all_cases_run_with_process_execution_forbidden(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("benchmark attempted process execution")

    monkeypatch.setattr("subprocess.Popen", denied)
    assert run_expert_benchmarks(BENCHMARKS).passed


def test_changed_source_during_measurement_is_not_published(copy, monkeypatch):
    from dvi_sentinel.expert_benchmarks import measure_native

    def changed(*args, **kwargs):
        result = measure_native(*args, **kwargs)
        with (copy / "v2/flow.jsonl").open("ab") as stream:
            stream.write(b"\n")
        return result

    monkeypatch.setattr("dvi_sentinel.expert_benchmarks.measure_native", changed)
    with pytest.raises(ValueError, match="inputs changed during execution"):
        run_expert_benchmarks(copy, case_id="normalization_loss-control")


@pytest.mark.parametrize("mutation", ["budget", "identity", "variants", "nested_link"])
def test_legacy_reuse_and_policy_limits_fail_before_execution(copy, monkeypatch, mutation):
    identity = "schema_alias_fragility-control"
    if mutation == "budget":
        path = copy / "suite.json"
        data = json.loads(path.read_bytes())
        data["event_budget"] += 1
        path.write_text(json.dumps(data))
    elif mutation == "identity":
        change_suite(copy, identity, operation={"kind": "legacy", "case_id": "timezone-control"})
    elif mutation == "variants":
        path = copy / "schema_alias-control.yaml"
        path.write_text(path.read_text().replace("max_variants: 8", "max_variants: 9"))
    else:
        monkeypatch.setattr(Path, "is_junction", lambda p: p.name == "events.jsonl")
    monkeypatch.setattr(
        "dvi_sentinel.expert_benchmarks.run_benchmark_case",
        lambda *a, **k: pytest.fail("executed invalid input"),
    )
    with pytest.raises(ValueError):
        run_expert_benchmarks(copy, case_id=identity)


def test_broken_baseline_cannot_pass_a_legacy_control(copy):
    path = copy / "schema_alias-control.yaml"
    text = path.read_text()
    path.write_text(text.replace("value: observed", "value: absent"))
    actual = run_expert_benchmarks(copy, case_id="schema_alias_fragility-control")
    assert not actual.passed and actual.results[0].measured.state == "incomplete"
    assert actual.results[0].measured.minimum.status == "unavailable"
    assert actual.results[0].measured.minimum.reason == "unresolved"


@pytest.mark.parametrize("mutation", ["precision", "baseline", "invariant"])
def test_unresolved_sequence_never_passes_or_claims_absent_failure(copy, mutation):
    if mutation == "precision":
        path = copy / "v2/sequence.jsonl"
        path.write_text(path.read_text().replace("00.000000Z", "00Z"))
    elif mutation == "baseline":
        path = copy / "v2/sequence_control.yaml"
        path.write_text(path.read_text().replace("min_count: 2", "min_count: 3"))
    else:
        path = copy / "v2/sequence_change.json"
        path.write_text(json.dumps({"event_id": "expert:flow:2", "delta_ms": 2}))
    actual = run_expert_benchmarks(copy, case_id="sequence_window_fragility-control")
    row = actual.results[0]
    assert not actual.passed and row.measured.state in {"unknown", "baseline_failed"}
    assert row.measured.minimum.status == "unavailable"
    assert row.measured.minimum.reason == "unresolved"
    if mutation == "precision":
        assert row.evidence.match.status == "detected"
        assert row.evidence.window.outcome == "unknown"
        assert row.measured.score.ratio.value == 1  # Detection and timing resolution are separate.


def test_sequence_overflow_is_invalid_input_and_writes_nothing(copy, tmp_path):
    path = copy / "v2/sequence.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[1]["timestamp"] = "9999-12-31T23:59:59.999999Z"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    main = runpy.run_path(str(ROOT / "examples/run_v2_benchmarks.py"))["main"]
    with pytest.raises(SystemExit) as invalid:
        main(
            [
                "--root",
                str(copy),
                "--case",
                "sequence_window_fragility-control",
                "--out",
                str(tmp_path / "overflow"),
            ]
        )
    assert invalid.value.code == 2 and not (tmp_path / "overflow").exists()


def test_missing_shrink_operation_cannot_claim_no_failure(copy):
    path = copy / "suite.json"
    data = json.loads(path.read_bytes())
    row = next(c for c in data["cases"] if c["id"] == "schema_alias-fragile")
    row.update(shrink_family=None, minimum=None)
    path.write_text(json.dumps(data))
    actual = run_expert_benchmarks(copy, case_id="schema_alias_fragility-diagnostic")
    row = actual.results[0]
    assert not actual.passed and row.measured.state == "fragile"
    assert row.measured.minimum.status == "unavailable"
    assert row.measured.minimum.reason == "unresolved"
