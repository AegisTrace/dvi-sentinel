"""Assert the public foundation command behavior, including errors."""

from importlib.metadata import version

from typer.testing import CliRunner

from dvi_sentinel import __version__
from dvi_sentinel.cli.main import app

runner = CliRunner()


def test_help_describes_boundary() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "local synthetic fixture-based" in result.output
    assert "--version" in result.output


def test_version_matches_installed_distribution() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"dvi-sentinel {version('dvi-sentinel')}"
    assert version("dvi-sentinel") == __version__


def test_no_arguments_shows_usage() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_unknown_command_is_an_error() -> None:
    result = runner.invoke(app, ["does-not-exist"])
    assert result.exit_code == 2
    assert "No such command" in result.output
