import importlib
import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dvi_sentinel.cli.main import app
from examples.verify_ci_proof import main, verify

ROOT = Path(__file__).parents[1]


@pytest.fixture(scope="module")
def evidence_root(tmp_path_factory):
    root = tmp_path_factory.mktemp("ci-proof")
    records = root / "ci-v2-evidence"
    records.mkdir()
    runner = CliRunner()

    def run(name, args, expected=0):
        result = runner.invoke(app, [*args, "--json"])
        assert result.exit_code == expected, result.output
        (records / name).write_text(result.output, encoding="utf-8")

    run("doctor.json", ["doctor"])
    run(
        "benchmark.json",
        ["benchmark", str(ROOT / "benchmarks"), "--out", str(root / "benchmarks/v2")],
    )
    for name, scenario, expected in (
        ("ci-v2", "examples/v2/ci/scenario.yaml", 0),
        ("ci-v2-fragile", "examples/artifact_scenario.yaml", 1),
    ):
        prefix = "fragile-" if expected else ""
        run(
            prefix + "run.json",
            [
                "run",
                str(ROOT / scenario),
                "--out",
                str(root / name),
                "--seed",
                "42",
                "--event-budget",
                "256",
            ],
        )
        run(
            prefix + "gate.json",
            ["ci-check", str(root / name), "--threshold", "1", "--max-unknown", "0"],
            expected,
        )
    run("report.json", ["report", str(root / "ci-v2"), "--overwrite"])
    run("report-refusal.json", ["report", str(root / "ci-v2")], 2)
    return root


@pytest.fixture
def proof_case(evidence_root, tmp_path):
    root = tmp_path / "proof"
    shutil.copytree(evidence_root, root)
    for name, prefix in (("ci-v2", ""), ("ci-v2-fragile", "fragile-")):
        path = root / f"ci-v2-evidence/{prefix}run.json"
        data = json.loads(path.read_bytes())
        data.update(output=str(root / name), report=str(root / name / "report.html"))
        path.write_text(json.dumps(data), encoding="utf-8")
    path = root / "ci-v2-evidence/report.json"
    data = json.loads(path.read_bytes())
    data["report"] = str(root / "ci-v2/report.html")
    path.write_text(json.dumps(data), encoding="utf-8")
    return root


def test_real_cli_evidence_proves_measurement_and_refusal(evidence_root):
    proof = verify(evidence_root)
    assert proof.benchmark_cases == 32 and proof.report_unchanged
    assert (proof.robust_exit, proof.fragile_exit, proof.refusal_exit) == (0, 1, 2)
    assert proof.robust_manifest != proof.fragile_manifest
    with pytest.raises(ValueError, match="isolated installed"):
        verify(evidence_root, require_installed=True)


@pytest.mark.parametrize(
    "mutation",
    [
        "doctor",
        "run_digest",
        "metrics",
        "threshold",
        "report",
        "refusal",
        "benchmark_digest",
        "benchmark_file",
        "bundle",
    ],
)
def test_proof_rejects_changed_measurements_and_artifacts(proof_case, mutation):
    names = {
        "doctor": "doctor",
        "run_digest": "run",
        "metrics": "run",
        "threshold": "gate",
        "report": "report",
        "refusal": "report-refusal",
        "benchmark_digest": "benchmark",
    }
    if mutation in names:
        path = proof_case / f"ci-v2-evidence/{names[mutation]}.json"
        data = json.loads(path.read_bytes())
        if mutation == "doctor":
            data["checks"] = [
                c for c in data["checks"] if c["name"] != "advanced report stylesheet"
            ]
        elif mutation == "run_digest":
            data["manifest_digest"] = "0" * 64
        elif mutation == "metrics":
            data["detected"] += 1
        elif mutation == "threshold":
            next(d for d in data["decisions"] if d["threshold"] == 1)["threshold"] = 0.5
        elif mutation == "report":
            data["verification"]["manifest_digest"] = "0" * 64
        elif mutation == "refusal":
            data["reason"] = "a different error"
        else:
            data["artifacts"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
    else:
        path = proof_case / (
            "benchmarks/v2/benchmark_report.json"
            if mutation == "benchmark_file"
            else "ci-v2/score.json"
        )
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        verify(proof_case)


def test_proof_refuses_linked_root_and_cli_errors_are_concise(evidence_root, monkeypatch, capsys):
    monkeypatch.setattr(Path, "is_junction", lambda p: p == evidence_root)
    monkeypatch.setattr("sys.argv", ["verify_ci_proof.py", "--root", str(evidence_root)])
    with pytest.raises(SystemExit) as rejected:
        main()
    assert rejected.value.code == 2
    assert "junction" in capsys.readouterr().err


@pytest.mark.parametrize("name,field", [("run", "output"), ("run", "report"), ("report", "report")])
def test_captured_paths_are_compared_without_filesystem_resolution(
    proof_case, monkeypatch, name, field
):
    path = proof_case / f"ci-v2-evidence/{name}.json"
    data = json.loads(path.read_bytes())
    supplied = "//remote.invalid/share/report.html"
    data[field] = supplied
    path.write_text(json.dumps(data), encoding="utf-8")
    original = Path.resolve

    def confined_resolve(self, *args, **kwargs):
        assert self != Path(supplied), "captured JSON must not trigger filesystem resolution"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", confined_resolve)
    with pytest.raises(ValueError, match="DVI-CI-PROOF"):
        verify(proof_case)


@pytest.mark.parametrize("asset", ["advanced_report.html.j2", "report.css"])
def test_doctor_rejects_missing_v2_packaged_asset(asset, monkeypatch):
    module = importlib.import_module("dvi_sentinel.cli.doctor")
    actual = module.resources.files("dvi_sentinel")

    class Root:
        def joinpath(self, path):
            return Path("/missing-dvi-asset") if path.endswith(asset) else actual.joinpath(path)

    monkeypatch.setattr(module.resources, "files", lambda name: Root())
    result = CliRunner().invoke(app, ["doctor", "--json"])
    assert result.exit_code == 2 and "Traceback" not in result.output
    data = json.loads(result.output)
    assert data["status"] == "unavailable"
    failed = [c for c in data["checks"] if c["status"] == "fail"]
    assert len(failed) == 1 and failed[0]["name"].startswith("advanced report")
