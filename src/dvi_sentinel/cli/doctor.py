"""Read-only checks of the installed local runtime and packaged report template."""

import platform
import sys
from importlib import metadata, resources
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from dvi_sentinel import __version__
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.workflow_models import DoctorCheck, DoctorReport


def doctor_command(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    checks = [
        DoctorCheck(
            name="python",
            status="pass" if sys.version_info >= (3, 12) else "fail",
            value=platform.python_version(),
        )
    ]
    for package in ("Jinja2", "PyYAML", "dvi-sentinel", "pydantic", "rich", "typer"):
        try:
            installed = metadata.version(package)
            okay = package != "dvi-sentinel" or installed == __version__
            checks.append(
                DoctorCheck(name=package, status="pass" if okay else "fail", value=installed)
            )
        except metadata.PackageNotFoundError:
            checks.append(DoctorCheck(name=package, status="fail", value="not installed"))
    present = resources.files("dvi_sentinel").joinpath("templates/report.html.j2").is_file()
    checks.append(
        DoctorCheck(
            name="report template",
            status="pass" if present else "fail",
            value="present" if present else "missing",
        )
    )
    okay = all(check.status == "pass" for check in checks)
    result = DoctorReport(
        status="ready" if okay else "unavailable",
        exit_status=0 if okay else 2,
        checks=tuple(checks),
    )
    if json_output:
        typer.echo(canonical_json(result))
    else:
        table = Table("Local check", "Status", "Value")
        for check in checks:
            table.add_row(check.name, check.status, check.value)
        Console(markup=False, highlight=False).print(table)
        typer.echo("Local fixture runtime only. No external detector or network checks performed.")
    raise typer.Exit(result.exit_status)
