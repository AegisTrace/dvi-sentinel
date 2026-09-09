"""Local snapshot comparison command; no subprocess or scenario execution."""

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from dvi_sentinel.comparison import compare_snapshots
from dvi_sentinel.comparison_models import ComparisonSnapshot, ComparisonThresholds
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.serialization import canonical_json, parse_json


def compare_command(
    previous: Annotated[Path, typer.Argument(help="Declared previous comparison snapshot JSON.")],
    current: Annotated[Path, typer.Argument(help="Current comparison snapshot JSON.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Print machine-readable JSON.")
    ] = False,
    max_detection_drop: Annotated[float, typer.Option(min=0, max=1)] = 0.0,
    max_unknown_increase: Annotated[float, typer.Option(min=0, max=1)] = 0.0,
    max_new_misses: Annotated[int, typer.Option(min=0)] = 0,
    max_semantic_drop: Annotated[float, typer.Option(min=0, max=1)] = 0.0,
    max_adapter_increase: Annotated[float, typer.Option(min=0, max=1)] = 0.0,
) -> None:
    try:
        old, new = (
            ComparisonSnapshot.model_validate(
                parse_json(
                    read_fixture(
                        path.parent,
                        path.name,
                        limit=32 * 1024 * 1024,
                    )
                )
            )
            for path in (previous, current)
        )
        result = compare_snapshots(
            old,
            new,
            ComparisonThresholds(
                max_detection_rate_drop=max_detection_drop,
                max_unknown_rate_increase=max_unknown_increase,
                max_new_misses=max_new_misses,
                max_semantic_preservation_drop=max_semantic_drop,
                max_adapter_disagreement_increase=max_adapter_increase,
            ),
        )
    except (ValueError, OSError, RecursionError) as exc:
        detail = (
            "; ".join(
                f"{'.'.join(map(str, error['loc']))}: {error['msg']}"
                for error in exc.errors(include_input=False)
            )
            if isinstance(exc, ValidationError)
            else str(exc)
        )
        detail = detail[:1000]
        if json_output:
            typer.echo(
                canonical_json({"status": "invalid_input", "exit_status": 2, "reason": detail})
            )
        else:
            typer.echo(f"Comparison input rejected: {detail}", err=True)
        raise typer.Exit(2) from exc
    if json_output:
        typer.echo(canonical_json(result))
    else:
        console = Console(markup=False, highlight=False)
        console.print(f"Comparison: {result.status} (exit {result.exit_status})")
        for reason in result.reasons:
            console.print(reason)
        table = Table("Metric", "Previous", "Current", "Delta")
        for metric in result.metrics:
            table.add_row(
                metric.metric, str(metric.previous), str(metric.current), str(metric.delta)
            )
        console.print(table)
        family_table = Table("Family", "Detection-rate delta", "Miss-rate delta", "Unknown delta")
        for family in result.families:
            values = {metric.metric: metric.delta for metric in family.metrics}
            family_table.add_row(
                family.family,
                str(values["detection_rate"]),
                str(values["miss_rate"]),
                str(values["unknown_rate"]),
            )
        console.print(family_table)
        console.print(f"Newly missed: {', '.join(result.newly_missed) or 'none'}")
        console.print(f"Recovered: {', '.join(result.recovered) or 'none'}")
        console.print(f"Unchanged misses: {', '.join(result.unchanged_misses) or 'none'}")
        console.print(f"New fragility classes: {', '.join(result.new_fragility_classes) or 'none'}")
        console.print(
            f"Removed fragility classes: {', '.join(result.removed_fragility_classes) or 'none'}"
        )
    raise typer.Exit(result.exit_status)
