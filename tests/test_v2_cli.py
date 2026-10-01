from typer.testing import CliRunner

from dvi_sentinel.artifact_store import verify_artifacts, write_artifacts
from dvi_sentinel.cli.main import app
from dvi_sentinel.serialization import parse_json
from examples.advanced_report import fixture_bundle


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
