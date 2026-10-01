"""Expert benchmark CLI with measured regression exit status (C)."""

from pathlib import Path
from typing import Annotated

import typer

from dvi_sentinel.cli.analysis import Json, Out, Pin
from dvi_sentinel.cli.analysis_io import capture, destination, finish, local_path
from dvi_sentinel.cli.analysis_models import InputPin
from dvi_sentinel.cli.common import fail
from dvi_sentinel.expert_benchmark_reports import expert_benchmark_artifacts
from dvi_sentinel.expert_benchmarks import run_expert_benchmarks
from dvi_sentinel.local_fixtures import MAX_SCENARIO_BYTES


def benchmark_command(
    root: Annotated[Path, typer.Argument(help="Local benchmark root containing v2/suite.json.")],
    case: Annotated[
        str | None, typer.Option(help="Select one declared case; default all 32.")
    ] = None,
    out: Out = None,
    json_output: Json = False,
    input_sha256: Pin = None,
) -> None:
    """Execute expert diagnostics/controls; failed declared checks exit 1."""
    try:
        output = destination(out)
        directory = local_path(root)
        suite = capture(
            directory / "v2/suite.json",
            role="suite",
            expected=input_sha256,
            limit=MAX_SCENARIO_BYTES,
        )
        result = run_expert_benchmarks(directory, case_id=case)
        if result.suite_sha256 != suite.pin.sha256:
            raise ValueError("DVI-CLI-INTEGRITY: benchmark suite changed during capture")
        pins = {
            p.path: InputPin(role=p.path, sha256=p.sha256, size_bytes=p.size_bytes)
            for row in result.results
            for p in row.sources
        }
        failed = [
            f"{row.case.benchmark_id}: {check.name}"
            for row in result.results
            for check in row.checks
            if not check.passed
        ]
        detail = "; failed " + ", ".join(failed[:3]) if failed else ""
        if len(failed) > 3:
            detail += f"; {len(failed) - 3} further failed checks in the report"
        finish(
            "benchmark",
            expert_benchmark_artifacts(result),
            result,
            f"{result.scope}; "
            f"{sum(r.passed for r in result.results)}/{len(result.results)} cases passed{detail}",
            (suite,),
            output,
            json_output,
            exit_status=0 if result.passed else 1,
            pins=tuple(pins[p] for p in sorted(pins) if p != "v2/suite.json"),
        )
    except (ValueError, OSError, RecursionError, OverflowError) as exc:
        fail(exc, json_output)
