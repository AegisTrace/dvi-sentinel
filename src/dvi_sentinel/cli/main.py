"""Installed and module entry points for DVI Sentinel."""

from typing import Annotated

import typer

from dvi_sentinel import __version__
from dvi_sentinel.cli.analysis import (
    analyze_rule_command,
    confidence_command,
    explain_command,
    explore_command,
    graph_command,
    map_schema_command,
    ontology_command,
    oracles_command,
    temporal_command,
)
from dvi_sentinel.cli.benchmark import benchmark_command
from dvi_sentinel.cli.compare import compare_command
from dvi_sentinel.cli.doctor import doctor_command
from dvi_sentinel.cli.workflow import (
    ci_check_command,
    report_command,
    run_command,
    validate_command,
)

app = typer.Typer(
    help="DVI Sentinel: local synthetic fixture-based detection resilience.",
    add_completion=False,
    rich_markup_mode=None,
)
app.command("compare")(compare_command)
app.command("doctor")(doctor_command)
app.command("run")(run_command)
app.command("report")(report_command)
app.command("ci-check")(ci_check_command)
app.command("validate")(validate_command)
app.command("ontology")(ontology_command)
app.command("map-schema")(map_schema_command)
app.command("analyze-rule")(analyze_rule_command)
app.command("temporal")(temporal_command)
app.command("oracles")(oracles_command)
app.command("explore")(explore_command)
app.command("explain")(explain_command)
app.command("confidence")(confidence_command)
app.command("graph")(graph_command)
app.command("benchmark")(benchmark_command)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Print the tool version.")] = False,
) -> None:
    """Present package information without performing I/O on telemetry."""
    if version:
        typer.echo(f"dvi-sentinel {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
