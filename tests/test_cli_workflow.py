import importlib
import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from dvi_sentinel.artifact_store import verify_artifacts
from dvi_sentinel.cli.main import app
from dvi_sentinel.harness_models import FixtureCase, FixtureResults
from dvi_sentinel.models import DetectionEvent, RawSource
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.serialization import parse_json

runner = CliRunner()
ROOT = Path(__file__).parents[1]


def scenario_file(root, *, robust=False, updates=None):
    data = yaml.safe_load((ROOT / "examples/artifact_scenario.yaml").read_text())
    if robust:
        data["harness"]["rules"][0]["max_count"] = None
    if updates:
        data.update(updates)
    telemetry = root / "probes/events.jsonl"
    telemetry.parent.mkdir(parents=True, exist_ok=True)
    telemetry.write_bytes((ROOT / "examples/probes/events.jsonl").read_bytes())
    scenario = root / ("robust.yaml" if robust else "fragile.yaml")
    scenario.write_text(yaml.safe_dump(data), encoding="utf-8")
    return scenario


@pytest.fixture(scope="module")
def completed_runs(tmp_path_factory):
    root = tmp_path_factory.mktemp("cli-runs")
    outputs = {}
    for name, robust in (("fragile", False), ("robust", True)):
        scenario = scenario_file(root, robust=robust)
        output = root / name
        result = runner.invoke(
            app, ["run", str(scenario), "--out", str(output), "--seed", "42", "--json"]
        )
        assert result.exit_code == 0, result.output
        outputs[name] = output
    return outputs


def test_doctor_checks_installed_runtime_and_template():
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0 and parse_json(result.output)["status"] == "ready"
    assert all(check["status"] == "pass" for check in parse_json(result.output)["checks"])
    assert runner.invoke(app, ["doctor"]).exit_code == 0


def test_unicode_jsonl_labels_survive_the_complete_cli_pipeline(tmp_path):
    scenario = scenario_file(tmp_path, robust=True)
    source = tmp_path / "probes/events.jsonl"
    records = [parse_json(line) for line in source.read_bytes().splitlines()]
    label = "lab\u0085fixture\u2028text\u2029end"
    records[0]["labels"] = [label]
    source.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in records) + "\n", encoding="utf-8"
    )
    output = tmp_path / "unicode-output"
    result = runner.invoke(app, ["run", str(scenario), "--out", str(output), "--json"])
    assert result.exit_code == 0, result.output
    assert parse_json(result.output)["missed"] == 0
    assert verify_artifacts(output).valid
    normalized = [
        parse_json(line) for line in (output / "normalized_events.jsonl").read_bytes().splitlines()
    ]
    assert normalized[0]["labels"] == [label]
    assert normalized[0]["raw"]["record_index"] == 1
    assert runner.invoke(app, ["ci-check", str(output), "--threshold", "1"]).exit_code == 0


def test_doctor_reports_package_metadata_failure(monkeypatch):
    doctor = importlib.import_module("dvi_sentinel.cli.doctor")
    original = doctor.metadata.version

    def missing(name):
        if name == "Jinja2":
            raise doctor.metadata.PackageNotFoundError(name)
        return original(name)

    monkeypatch.setattr(doctor.metadata, "version", missing)
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 2 and parse_json(result.output)["status"] == "unavailable"


def test_actual_runs_publish_complete_reports_and_known_outcomes(completed_runs):
    for name, path in completed_runs.items():
        assert verify_artifacts(path).valid
        assert all(
            (path / file).is_file()
            for file in (
                "run.json",
                "report.html",
                "report.md",
                "report.json",
                "provenance.json",
                "manifest.json",
            )
        )
        score = parse_json((path / "score.json").read_bytes())
        assert score["metrics"]["missed"] == (9 if name == "fragile" else 0)
        assert score["metrics"]["detected"] == (2 if name == "fragile" else 11)
    assert (completed_runs["fragile"] / "minimal_case.json").is_file()
    assert not (completed_runs["robust"] / "minimal_case.json").exists()


def test_ci_thresholds_distinguish_run_completion_from_acceptance(completed_runs):
    fragile, robust = completed_runs["fragile"], completed_runs["robust"]
    failed = runner.invoke(app, ["ci-check", str(fragile / "run.json"), "--json"])
    assert failed.exit_code == 1 and parse_json(failed.output)["status"] == "failed"
    passed = runner.invoke(app, ["ci-check", str(robust), "--threshold", "1", "--json"])
    assert passed.exit_code == 0 and parse_json(passed.output)["status"] == "passed"
    allowed = runner.invoke(app, ["ci-check", str(fragile), "--threshold", "0.1", "--json"])
    assert allowed.exit_code == 0
    invalid = runner.invoke(app, ["ci-check", str(robust), "--threshold", "nan", "--json"])
    assert invalid.exit_code == 2 and "THRESHOLD" in invalid.output


def test_compare_accepts_verified_run_directories_and_reports_regression(completed_runs):
    result = runner.invoke(
        app,
        [
            "compare",
            str(completed_runs["robust"]),
            str(completed_runs["fragile"] / "run.json"),
            "--json",
        ],
    )
    assert result.exit_code == 1
    data = parse_json(result.output)
    assert data["status"] == "regressed" and len(data["newly_missed"]) == 9


def test_report_requires_overwrite_and_captures_baseline(completed_runs):
    output = completed_runs["fragile"]
    refused = runner.invoke(app, ["report", str(output), "--json"])
    assert refused.exit_code == 2 and "EXISTS" in refused.output
    result = runner.invoke(
        app,
        [
            "report",
            str(output),
            "--baseline",
            str(completed_runs["robust"]),
            "--overwrite",
            "--json",
        ],
    )
    assert result.exit_code == 0 and verify_artifacts(output).valid
    assert parse_json((output / "report.json").read_bytes())["regression"]["status"] == "regressed"


@pytest.mark.parametrize("failure", ["malformed", "unsafe", "missing", "partial", "duplicate"])
def test_bad_scenarios_or_fixtures_fail_without_output_or_traceback(tmp_path, failure):
    scenario = scenario_file(tmp_path)
    if failure == "malformed":
        scenario.write_text("metadata: [", encoding="utf-8")
    elif failure == "unsafe":
        scenario.write_text(scenario.read_text() + "execution: inert\n", encoding="utf-8")
    elif failure == "missing":
        (tmp_path / "probes/events.jsonl").unlink()
    elif failure == "partial":
        with (tmp_path / "probes/events.jsonl").open("ab") as stream:
            stream.write(b"{}\n")
    else:
        data = yaml.safe_load(scenario.read_text())
        data["inputs"] *= 2
        scenario.write_text(yaml.safe_dump(data), encoding="utf-8")
    output = tmp_path / "result"
    for command in (
        ["validate", str(scenario), "--json"],
        ["run", str(scenario), "--out", str(output), "--json"],
    ):
        result = runner.invoke(app, command)
        assert result.exit_code == 2 and parse_json(result.output)["status"] == "invalid_input"
        assert "Traceback" not in result.output and not output.exists()


def test_validate_normalizes_local_input_and_preserves_warnings(tmp_path):
    scenario = scenario_file(tmp_path, updates={"variations": {}})
    result = runner.invoke(app, ["validate", str(scenario), "--json"])
    assert result.exit_code == 0
    data = parse_json(result.output)
    assert data["events"] == 2
    assert any(decision["rule_id"] == "DVI-POL-013" for decision in data["policy"])


def test_optional_flags_and_explicit_run_overwrite(tmp_path):
    scenario = scenario_file(tmp_path, robust=True)
    output = tmp_path / "run"
    command = [
        "run",
        str(scenario),
        "--out",
        str(output),
        "--no-probes",
        "--no-differential",
        "--no-shrink",
        "--json",
    ]
    first = runner.invoke(app, command)
    assert first.exit_code == 0
    original = (output / "score.json").read_bytes()
    refused = runner.invoke(app, command)
    assert refused.exit_code == 2 and "EXISTS" in refused.output
    repeated = runner.invoke(app, [*command, "--overwrite"])
    assert repeated.exit_code == 0 and (output / "score.json").read_bytes() == original
    assert parse_json(first.output)["run_id"] == parse_json(repeated.output)["run_id"]
    assert (output / "assumption_probes.jsonl").read_bytes() == b""
    assert not (output / "differential_schema_report.json").exists()


def test_no_variant_coverage_is_unknown_not_a_pass(tmp_path):
    scenario = scenario_file(tmp_path, robust=True, updates={"variations": {}})
    output = tmp_path / "run"
    assert runner.invoke(app, ["run", str(scenario), "--out", str(output)]).exit_code == 0
    checked = runner.invoke(app, ["ci-check", str(output), "--json"])
    assert checked.exit_code == 2 and parse_json(checked.output)["status"] == "unknown"


def test_tampered_bundle_is_rejected_by_every_consumer(tmp_path, completed_runs):
    # Use a new real output so the shared comparison fixtures remain intact.
    scenario = scenario_file(tmp_path, robust=True)
    output = tmp_path / "run"
    assert (
        runner.invoke(app, ["run", str(scenario), "--out", str(output), "--no-shrink"]).exit_code
        == 0
    )
    (output / "score.json").write_bytes(b"{}")
    for command in (
        ["report", str(output), "--overwrite"],
        ["ci-check", str(output)],
        ["compare", str(completed_runs["robust"]), str(output)],
    ):
        result = runner.invoke(app, [*command, "--json"])
        assert result.exit_code == 2 and "INTEGRITY" in result.output


def test_probe_only_failure_is_shrunk_through_the_cli(tmp_path):
    scenario = scenario_file(
        tmp_path,
        robust=True,
        updates={
            "variations": {
                "families": ["metadata"],
                "optional_fields": ["sensor"],
                "max_variants": 4,
            }
        },
    )
    data = yaml.safe_load(scenario.read_text())
    data["harness"]["rules"][0]["conditions"] = [{"field": "raw.src_ip", "operator": "exists"}]
    scenario.write_text(yaml.safe_dump(data), encoding="utf-8")
    output = tmp_path / "run"
    result = runner.invoke(app, ["run", str(scenario), "--out", str(output), "--json"])
    assert result.exit_code == 0, result.output
    score = parse_json((output / "score.json").read_bytes())
    assert score["metrics"]["missed"] == 0
    assert any(f["source"] == "probe" for f in score["findings"])
    minimal = parse_json((output / "minimal_case.json").read_bytes())
    assert minimal["probe"]["name"] == "schema_alias" and minimal["status"] == "minimized"


def test_exhausted_event_budget_cannot_pass_ci(tmp_path):
    scenario = scenario_file(tmp_path, robust=True)
    output = tmp_path / "run"
    result = runner.invoke(
        app, ["run", str(scenario), "--out", str(output), "--event-budget", "2", "--json"]
    )
    assert result.exit_code == 0, result.output
    gate = runner.invoke(app, ["ci-check", str(output), "--json"])
    assert gate.exit_code == 2
    assert (
        next(d for d in parse_json(gate.output)["decisions"] if d["name"] == "planning_budget")[
            "status"
        ]
        == "unknown"
    )


def test_baseline_miss_cannot_produce_counterexample_or_passing_gate(tmp_path):
    scenario = scenario_file(
        tmp_path, robust=True, updates={"expected": {"detector": "lab", "signature": "absent"}}
    )
    output = tmp_path / "run"
    assert runner.invoke(app, ["run", str(scenario), "--out", str(output)]).exit_code == 0
    assert not (output / "minimal_case.json").exists()
    gate = runner.invoke(app, ["ci-check", str(output), "--threshold", "0", "--json"])
    assert gate.exit_code == 1
    assert (
        next(d for d in parse_json(gate.output)["decisions"] if d["name"] == "baseline")["status"]
        == "fail"
    )


def test_validate_rejects_unsafe_unused_detector_result_fixture(tmp_path, evidence):
    scenario = scenario_file(
        tmp_path, updates={"harness": {"kind": "fixture", "path": "results.json"}}
    )
    detection = DetectionEvent.model_validate(
        evidence.observations[0].detections[0].model_dump()
        | {
            "raw": RawSource.from_payload({"command": "inert"}, adapter="fixture"),
        }
    )
    (tmp_path / "results.json").write_bytes(
        json_bytes(FixtureResults(cases=(FixtureCase(case_id="unused", detections=(detection,)),)))
    )
    result = runner.invoke(app, ["validate", str(scenario), "--json"])
    assert result.exit_code == 2
    assert parse_json(result.output)["issues"][0]["rule_id"].startswith("DVI-POL-")
