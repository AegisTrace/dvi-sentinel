"""Shared bounded local input handling and expected user-error presentation."""

from pathlib import Path
from typing import NoReturn

import typer
from pydantic import JsonValue, ValidationError

from dvi_sentinel.artifact_contract import read_model
from dvi_sentinel.artifact_store import ArtifactError, verify_artifacts
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.serialization import canonical_json, parse_json


def fail(error: Exception, json_output: bool) -> NoReturn:
    detail = (
        "; ".join(
            f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in error.errors(include_input=False)
        )
        if isinstance(error, ValidationError)
        else str(error)
    )
    result: dict[str, JsonValue] = {
        "schema_version": "1",
        "status": "invalid_input",
        "exit_status": 2,
        "reason": detail[:1000],
    }
    if isinstance(error, PolicyError):
        result["issues"] = [d.model_dump(mode="json") for d in error.decisions]
    if json_output:
        typer.echo(canonical_json(result))
    else:
        typer.echo(f"Input rejected: {result['reason']}", err=True)
    raise typer.Exit(2) from error


def run_directory(path: Path) -> Path:
    directory = (
        path
        if path.is_dir()
        else path.parent
        if path.name in {"run.json", "manifest.json", "report.json"}
        else None
    )
    if directory is None:
        raise ArtifactError(
            "DVI-CLI-PATH: require a run directory, run.json, manifest.json or report.json"
        )
    verified = verify_artifacts(directory)
    if not verified.valid:
        raise ArtifactError("DVI-CLI-INTEGRITY: run bundle failed verification")
    return directory


def comparison_input(path: Path) -> ComparisonSnapshot:
    if path.is_dir() or path.name in {"run.json", "manifest.json", "report.json"}:
        return read_model(run_directory(path), "comparison.json", ComparisonSnapshot)
    return ComparisonSnapshot.model_validate(
        parse_json(read_fixture(path.parent, path.name, limit=32 * 1024 * 1024))
    )
