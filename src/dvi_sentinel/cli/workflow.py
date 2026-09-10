"""Run, validate, report and CI-check commands over the implemented local workflow."""

from pathlib import Path
from typing import Annotated

import typer
from pydantic import JsonValue
from rich.console import Console
from rich.table import Table

from dvi_sentinel.artifact_contract import read_model
from dvi_sentinel.artifact_models import RunRecord
from dvi_sentinel.ci_gate import check_run
from dvi_sentinel.cli.common import fail, run_directory
from dvi_sentinel.reports import write_reports
from dvi_sentinel.score_models import ResilienceFrontier
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.workflow import prepare_scenario, run_scenario


def run_command(
    scenario: Annotated[
        Path, typer.Argument(help="Local scenario YAML; fixture paths resolve beside it.")
    ],
    out: Annotated[Path, typer.Option("--out", help="Destination for the complete run bundle.")],
    seed: Annotated[int, typer.Option(min=0, max=2**63 - 1)] = 42,
    overwrite: Annotated[bool, typer.Option(help="Replace a verified prior DVI bundle.")] = False,
    probes: Annotated[bool, typer.Option(help="Run the fixed assumption-probe catalog.")] = True,
    differential: Annotated[
        bool, typer.Option(help="Compare supported telemetry representations.")
    ] = True,
    shrink: Annotated[
        bool, typer.Option(help="Shrink one eligible failure deterministically.")
    ] = True,
    event_budget: Annotated[int, typer.Option(min=1, max=50_000)] = 50_000,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print a machine-readable run summary.")
    ] = False,
) -> None:
    command = (
        "dvi",
        "run",
        str(scenario),
        "--out",
        str(out),
        "--seed",
        str(seed),
        "--event-budget",
        str(event_budget),
        "--probes" if probes else "--no-probes",
        "--differential" if differential else "--no-differential",
        "--shrink" if shrink else "--no-shrink",
        *(("--overwrite",) if overwrite else ()),
    )
    try:
        result = run_scenario(
            scenario,
            out,
            seed=seed,
            overwrite=overwrite,
            probes=probes,
            differential=differential,
            shrink=shrink,
            event_budget=event_budget,
            command=command,
        )
    except (ValueError, OSError, RecursionError) as exc:
        fail(exc, json_output)
    if json_output:
        typer.echo(canonical_json(result))
    else:
        console = Console(markup=False, highlight=False)
        console.print(f"Run completed: {result.run_id}")
        table = Table("Detected", "Missed", "Unknown", "Invalid", "Findings")
        table.add_row(
            *(
                str(getattr(result, field))
                for field in ("detected", "missed", "unknown", "invalid", "findings")
            )
        )
        console.print(table)
        console.print(f"Output: {result.output}\nReport: {result.report}")
        console.print(f"Manifest SHA-256: {result.manifest_digest}")
        console.print("Run completion is separate from threshold acceptance; use dvi ci-check.")


def validate_command(
    scenario: Annotated[Path, typer.Argument(help="Local scenario and its fixture inputs.")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        prepared = prepare_scenario(scenario)
    except (ValueError, OSError, RecursionError) as exc:
        fail(exc, json_output)
    result: dict[str, JsonValue] = {
        "schema_version": "1",
        "status": "valid",
        "exit_status": 0,
        "scenario_id": prepared.scenario.metadata.id,
        "events": len(prepared.events),
        "policy": [d.model_dump(mode="json") for d in prepared.policy],
    }
    if json_output:
        typer.echo(canonical_json(result))
    else:
        typer.echo(
            f"Valid local scenario: {prepared.scenario.metadata.id}; {len(prepared.events)} events"
        )
        for decision in prepared.policy:
            typer.echo(f"{decision.rule_id} {decision.decision}: {decision.explanation}")


def report_command(
    run: Annotated[Path, typer.Argument(help="Verified run directory or run.json.")],
    baseline: Annotated[
        Path | None, typer.Option(help="Optional verified prior run for regression.")
    ] = None,
    overwrite: Annotated[bool, typer.Option(help="Replace existing generated reports.")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        directory = run_directory(run)
        previous = run_directory(baseline) if baseline is not None else None
        verified = write_reports(directory, previous=previous, overwrite=overwrite)
    except (ValueError, OSError, RecursionError) as exc:
        fail(exc, json_output)
    if json_output:
        typer.echo(
            canonical_json(
                {
                    "schema_version": "1",
                    "status": "completed",
                    "exit_status": 0,
                    "report": str(directory.resolve() / "report.html"),
                    "verification": verified.model_dump(mode="json"),
                }
            )
        )
    else:
        typer.echo(f"Report: {directory.resolve() / 'report.html'}")
        typer.echo(f"Manifest SHA-256: {verified.manifest_digest}")


def ci_check_command(
    run: Annotated[Path, typer.Argument(help="Verified run directory or run.json.")],
    threshold: Annotated[
        float | None,
        typer.Option(min=0, max=1, help="Minimum variant detection ratio; default from scenario."),
    ] = None,
    max_unknown: Annotated[
        float | None,
        typer.Option(min=0, max=1, help="Maximum unknown ratio; default from scenario."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        directory = run_directory(run)
        result = check_run(
            read_model(directory, "run.json", RunRecord),
            read_model(directory, "score.json", ResilienceFrontier),
            threshold=threshold,
            max_unknown=max_unknown,
        )
    except (ValueError, OSError, RecursionError) as exc:
        fail(exc, json_output)
    if json_output:
        typer.echo(canonical_json(result))
    else:
        console = Console(markup=False, highlight=False)
        console.print(f"CI gate: {result.status} (exit {result.exit_status})")
        table = Table("Check", "Status", "Observed", "Threshold")
        for decision in result.decisions:
            table.add_row(
                decision.name, decision.status, str(decision.observed), str(decision.threshold)
            )
        console.print(table)
    raise typer.Exit(result.exit_status)
