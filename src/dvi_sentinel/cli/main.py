"""Installed and module entry points for DVI Sentinel."""

from typing import Annotated

import typer

from dvi_sentinel import __version__

app = typer.Typer(
    help="DVI Sentinel: local synthetic fixture-based detection resilience.",
    add_completion=False,
    rich_markup_mode=None,
)


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
