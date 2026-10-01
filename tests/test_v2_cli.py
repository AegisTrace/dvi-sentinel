import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dvi_sentinel.artifact_store import verify_artifacts, write_artifacts
from dvi_sentinel.cli.main import app
from dvi_sentinel.serialization import parse_json
from examples.advanced_report import fixture_bundle
from examples.v2_cli import COMMANDS, arguments, fixture_inputs

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def no_process_execution(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("analysis CLI attempted subprocess execution")

    monkeypatch.setattr(subprocess, "Popen", denied)


@pytest.fixture(scope="module")
def cli_fixture(tmp_path_factory):
    root = tmp_path_factory.mktemp("v2-cli")
    inputs = root / "inputs"
    inputs.mkdir()
    for name, content in fixture_inputs().items():
        (inputs / name).write_bytes(content)
    result = CliRunner().invoke(
        app, ["explain", str(inputs / "explain.json"), "--out", str(root / "explain"), "--json"]
    )
    assert result.exit_code == 0, result.output
    return root, inputs


def argv(command, fixture):
    root, inputs = fixture
    return arguments(command, inputs, root, ROOT / "benchmarks")


@pytest.mark.parametrize(
    "command", (*COMMANDS, "doctor", "validate", "run", "report", "compare", "ci-check")
)
def test_every_command_has_help_and_json(command):
    result = CliRunner().invoke(app, [command, "--help"])
    assert result.exit_code == 0 and "--json" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", COMMANDS)
def test_native_cli_json_artifacts_and_human_summary(command, cli_fixture, tmp_path):
    runner = CliRunner()
    out = tmp_path / command
    result = runner.invoke(app, [*argv(command, cli_fixture), "--out", str(out), "--json"])
    assert result.exit_code == 0, result.output
    data = parse_json(result.output)
    assert data["command"] == command and data["status"] == "completed"
    assert data["result"] and data["sources"]
    assert json.loads((out / "command_result.json").read_bytes()) == data
    for entry in data["artifacts"]:
        raw = (out / entry["path"]).read_bytes()
        assert len(raw) == entry["size_bytes"]
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
    native = data["result"]
    if command == "ontology":
        assert len(native["extractions"]) == 2
        assert all(e["state"] == "known" for e in native["extractions"])
    elif command == "map-schema":
        assert len(native["reports"]) == 14
        assert {r["decision"] for r in native["reports"]} >= {"lossless", "lossy"}
    elif command == "analyze-rule":
        assert native["state"] == "unknown"  # Count semantics require a sequence evaluator.
        assert len(native["candidates"]) == 2
    elif command == "temporal":
        checks = {t["check"]["predicate"]: t["check"] for t in native["traces"]}
        assert (
            checks["alert_within_window"]["outcome"] == "supported"
        )  # Detection subtype retained.
        assert native["state"] == "unknown"
    elif command == "oracles":
        assert len(native["decisions"]) == 9 and native["state"] == "not_enough_evidence"
    elif command == "explore":
        assert native["cases"] and native["seed"] == 42
        assert native["covering"]["state"] == "complete"
    elif command == "explain":
        assert native["state"] == "findings" and len(native["findings"]) == 1
        assert {c["outcome"] for c in native["cases"]} == {"detected", "missed"}
    elif command == "confidence":
        assert native["state"] == "measured"
        assert {g["confidence_class"] for g in native["groups"]} == {"insufficient_sample"}
    elif command == "graph":
        assert native["state"] == "built" and native["summary"]["weak_edges"] > 0
        assert native["summary"]["findings"] == 1
    else:
        assert all(c["passed"] for r in native["results"] for c in r["checks"])
        assert native["scope"] == "selected_case"
        assert native["results"][0]["measured"]["state"] == "detected"
    again = runner.invoke(app, [*argv(command, cli_fixture), "--json"])
    assert again.exit_code == 0 and again.output == result.output
    human = runner.invoke(app, argv(command, cli_fixture))
    assert human.exit_code == 0 and f"{command}:" in human.output
    assert "exit 0" in human.output and "Traceback" not in human.output
    refused = runner.invoke(app, [*argv(command, cli_fixture), "--out", str(out), "--json"])
    assert refused.exit_code == 2 and "EXISTS" in refused.output
    assert json.loads((out / "command_result.json").read_bytes()) == data


@pytest.mark.parametrize("command", COMMANDS)
def test_invalid_input_and_incorrect_pin_are_concise(command, cli_fixture, tmp_path):
    args = argv(command, cli_fixture)
    wrong_pin = CliRunner().invoke(app, [*args, "--input-sha256", "0" * 64, "--json"])
    assert wrong_pin.exit_code == 2 and "INTEGRITY" in wrong_pin.output
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"unexpected": true}', encoding="utf-8")
    result = CliRunner().invoke(app, [args[0], str(invalid), *args[2:], "--json"])
    assert result.exit_code == 2, result.output
    assert parse_json(result.output)["status"] == "invalid_input"
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", COMMANDS)
def test_network_and_junction_inputs_rejected_before_analysis(command, cli_fixture, monkeypatch):
    args = argv(command, cli_fixture)
    for root in ("//live.example/share/file.json", "https://live.example/file.json"):
        result = CliRunner().invoke(app, [command, root, *args[2:], "--json"])
        assert result.exit_code == 2 and parse_json(result.output)["status"] == "invalid_input"
    target = Path(args[1])
    monkeypatch.setattr(Path, "is_junction", lambda p: p == target)
    result = CliRunner().invoke(app, [*args, "--json"])
    assert result.exit_code == 2 and "junction" in result.output


@pytest.mark.parametrize("command", [c for c in COMMANDS if c != "benchmark"])
def test_unsafe_embedded_events_never_publish(command, cli_fixture, tmp_path):
    args = argv(command, cli_fixture)
    source = Path(args[1])
    data = json.loads(source.read_bytes())
    if command == "analyze-rule":
        data["conditions"][0] = {"field": "src_ip", "operator": "eq", "value": "8.8.8.8"}
    else:

        def change(value):
            if isinstance(value, dict):
                return {k: "8.8.8.8" if k == "address" else change(v) for k, v in value.items()}
            if isinstance(value, list):
                return [change(v) for v in value]
            return value

        data = change(data)
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "forbidden"
    result = CliRunner().invoke(
        app, [command, str(path), *args[2:], "--out", str(output), "--json"]
    )
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output and not output.exists()


@pytest.mark.parametrize("command", ["explore", "explain", "confidence"])
def test_seed_override_is_recorded_and_reproducible(command, cli_fixture):
    args = argv(command, cli_fixture)
    runner = CliRunner()
    first = runner.invoke(app, [*args, "--seed", "7", "--json"])
    again = runner.invoke(app, [*args, "--seed", "7", "--json"])
    assert first.exit_code == 0 and first.output == again.output
    native = parse_json(first.output)["result"]
    actual = (
        native["seed"]
        if command == "explore"
        else (
            native["input"]["seed"]
            if command == "explain"
            else native["input"]["settings"]["bootstrap_seed"]
        )
    )
    assert actual == 7
    invalid = runner.invoke(app, [*args, "--seed", "-1", "--json"])
    assert invalid.exit_code == 2 and "Traceback" not in invalid.output


def test_benchmark_regression_retains_actual_evidence_and_exits_one(tmp_path):
    root = tmp_path / "benchmarks"
    shutil.copytree(ROOT / "benchmarks", root)
    path = root / "v2/suite.json"
    data = json.loads(path.read_bytes())
    row = next(r for r in data["cases"] if r["benchmark_id"] == "sequence_window_fragility-control")
    row["expected_state"] = "unknown"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            str(root),
            "--case",
            row["benchmark_id"],
            "--out",
            str(tmp_path / "regression"),
            "--json",
        ],
    )
    assert result.exit_code == 1, result.output
    data = parse_json(result.output)
    assert data["status"] == "failed"
    assert any(not c["passed"] for r in data["result"]["results"] for c in r["checks"])
    assert data["result"]["results"][0]["measured"]["state"] == "detected"
    assert (tmp_path / "regression/benchmark_report.json").is_file()
    human = CliRunner().invoke(app, ["benchmark", str(root), "--case", row["benchmark_id"]])
    assert human.exit_code == 1 and "failed sequence_window_fragility-control: state" in " ".join(
        human.output.split()
    )


def test_input_change_is_detected_before_publication(cli_fixture, tmp_path, monkeypatch):
    from dvi_sentinel.cli import analysis

    path = tmp_path / "events.json"
    path.write_bytes((cli_fixture[1] / "events.json").read_bytes())
    original = analysis.ontology_artifacts

    def altered(export):
        result = original(export)
        path.write_bytes(b"{}")
        return result

    monkeypatch.setattr(analysis, "ontology_artifacts", altered)
    out = tmp_path / "result"
    result = CliRunner().invoke(app, ["ontology", str(path), "--out", str(out), "--json"])
    assert result.exit_code == 2 and "changed during" in result.output
    assert not out.exists()


def test_bounds_encoding_and_output_path_errors_do_not_publish(cli_fixture, tmp_path, monkeypatch):
    from dvi_sentinel.cli import analysis_io

    runner = CliRunner()
    oversized = tmp_path / "large.json"
    oversized.write_bytes(b" " * (analysis_io.MAX_INPUT_BYTES + 1))
    result = runner.invoke(app, ["ontology", str(oversized), "--json"])
    assert result.exit_code == 2 and "exceeds" in result.output
    bad_rule = tmp_path / "rule.yaml"
    bad_rule.write_bytes(b"\xff")
    result = runner.invoke(
        app,
        ["analyze-rule", str(bad_rule), "--events", str(cli_fixture[1] / "events.json"), "--json"],
    )
    assert result.exit_code == 2 and "Traceback" not in result.output
    args = argv("ontology", cli_fixture)
    result = runner.invoke(app, [*args, "--out", "C:relative", "--json"])
    assert result.exit_code == 2 and "PATH" in result.output
    for name in ("NUL", "..", "encoded%2fname"):
        result = runner.invoke(app, [*args, "--out", str(tmp_path / name), "--json"])
        assert result.exit_code == 2
    monkeypatch.setattr(analysis_io, "MAX_OUTPUT_BYTES", 1)
    out = tmp_path / "small"
    result = runner.invoke(app, [*args, "--out", str(out), "--json"])
    assert result.exit_code == 2 and "32 MiB" in result.output and not out.exists()


@pytest.mark.parametrize("format", ["dvi", "sigma_metadata"])
def test_rule_formats_measure_supported_and_unsupported_conditions(format, cli_fixture, tmp_path):
    declaration = (
        {
            "intent_id": "fixture:flow",
            "title": "Local flow intent",
            "fields": [
                {
                    "field": "category",
                    "paths": ["semantics.category"],
                    "operators": [{"name": "eq", "value_json": '"flow"'}],
                }
            ],
        }
        if format == "dvi"
        else {
            "id": "fixture:flow",
            "title": "Local flow metadata",
            "taxonomy": "dvi",
            "logsource": {"category": "flow"},
            "detection": {"selection": {"category": "flow"}, "condition": "selection"},
        }
    )
    path = tmp_path / "rule.json"
    path.write_text(json.dumps(declaration), encoding="utf-8")
    args = [
        "analyze-rule",
        str(path),
        "--format",
        format,
        "--events",
        str(cli_fixture[1] / "events.json"),
        "--json",
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert parse_json(result.output)["result"]["state"] == "supported"
    if format == "dvi":
        declaration["fields"][0]["operators"][0]["name"] = "regex"
    else:
        declaration["detection"]["condition"] = "1 of selection*"
    path.write_text(json.dumps(declaration), encoding="utf-8")
    unresolved = CliRunner().invoke(app, args)
    assert unresolved.exit_code == 0
    assert parse_json(unresolved.output)["result"]["state"] == "unknown"


def test_duplicate_event_ids_and_events_pin_are_rejected(cli_fixture, tmp_path):
    data = json.loads((cli_fixture[1] / "events.json").read_bytes())
    data["events"].append(data["events"][0])
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(app, ["ontology", str(path)])
    assert result.exit_code == 2 and "unique" in result.output and "Traceback" not in result.output
    result = CliRunner().invoke(
        app, [*argv("analyze-rule", cli_fixture), "--events-sha256", "0" * 64, "--json"]
    )
    assert result.exit_code == 2 and "INTEGRITY" in result.output


def test_exploration_budget_omissions_and_oracle_unknowns_are_retained(cli_fixture, tmp_path):
    data = json.loads((cli_fixture[1] / "explore.json").read_bytes())
    data["budget"] = {"max_cases": 0, "max_events": 0}
    path = tmp_path / "limited.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(app, ["explore", str(path), "--json"])
    assert result.exit_code == 0, result.output
    plan = parse_json(result.output)["result"]
    assert not plan["cases"] and plan["skipped"] and plan["covering"]["state"] != "complete"
    data = json.loads((cli_fixture[1] / "oracles.json").read_bytes())
    data["observation"] = None
    path.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(app, ["oracles", str(path), "--json"])
    assert result.exit_code == 0
    consensus = parse_json(result.output)["result"]
    assert consensus["state"] == "not_enough_evidence"
    assert (
        next(d for d in consensus["decisions"] if d["oracle_id"] == "detection")["decision"]
        == "unknown"
    )


def test_benchmark_rejects_unsafe_local_fixture_without_output(tmp_path):
    root = tmp_path / "benchmarks"
    shutil.copytree(ROOT / "benchmarks", root)
    path = root / "v2/sequence.jsonl"
    text = path.read_text(encoding="utf-8")
    assert "192.0.2." in text
    import re

    path.write_text(re.sub(r"192\.0\.2\.\d+", "8.8.8.8", text), encoding="utf-8")
    out = tmp_path / "output"
    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            str(root),
            "--case",
            "sequence_window_fragility-control",
            "--out",
            str(out),
            "--json",
        ],
    )
    assert result.exit_code == 2 and "Traceback" not in result.output and not out.exists()


def test_advanced_report_cli_publishes_and_preserves_the_format(tmp_path):
    root = tmp_path / "run"
    write_artifacts(root, fixture_bundle(optional=False))
    runner = CliRunner()
    first = runner.invoke(app, ["report", str(root), "--advanced", "--json"])
    assert first.exit_code == 0, first.output
    data = parse_json(first.output)
    assert data["verification"]["valid"] and (root / "report_bundle.zip").is_file()
    again = runner.invoke(app, ["report", str(root / "run.json"), "--overwrite", "--json"])
    assert again.exit_code == 0, again.output
    assert parse_json(again.output)["verification"] == data["verification"]
    assert verify_artifacts(root).valid
    denied = runner.invoke(app, ["report", str(root), "--advanced", "--json"])
    assert denied.exit_code == 2 and "EXISTS" in denied.output


def test_advanced_cli_never_renders_a_damaged_bundle(tmp_path):
    root = tmp_path / "run"
    write_artifacts(root, fixture_bundle(optional=False))
    (root / "score.json").write_bytes(b"{}")
    result = CliRunner().invoke(app, ["report", str(root), "--advanced", "--json"])
    assert result.exit_code == 2
    assert parse_json(result.output)["status"] == "invalid_input"
    assert not (root / "report.html").exists()
