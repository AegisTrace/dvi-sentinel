"""Bounded local analysis input/output and common CLI presentation (R/W/C)."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console

from dvi_sentinel.artifact_models import ArtifactEntry, portable_path
from dvi_sentinel.cli.analysis_models import AnalysisResult, CommandName, InputPin
from dvi_sentinel.cli.common import fail
from dvi_sentinel.expert_benchmarks import plain_local_path
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.models import ValueModel
from dvi_sentinel.serialization import canonical_json, parse_json

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


def local_path(path: Path) -> Path:
    # Check lexical components before any filesystem inspection, including device paths.
    if path.drive and not path.root:
        raise ValueError("DVI-CLI-PATH: drive-relative paths are unsupported")
    for part in path.parts:
        if part == path.anchor:
            continue
        if (
            part in {".", ".."}
            or any(c in part for c in ":%\x00")
            or part.rstrip(" .") != part
            or part.split(".")[0].lower()
            in {
                "con",
                "prn",
                "aux",
                "nul",
                *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10)),
            }
        ):
            raise ValueError("DVI-CLI-PATH: require a plain local path")
    return plain_local_path(path)


@dataclass(frozen=True)
class CapturedInput:
    path: Path
    content: bytes
    pin: InputPin
    limit: int

    def recheck(self) -> None:
        path = local_path(self.path)
        if read_fixture(path.parent, path.name, limit=self.limit) != self.content:
            raise ValueError("DVI-CLI-INTEGRITY: input changed during analysis")


def capture(
    path: Path,
    *,
    role: str = "input",
    expected: str | None = None,
    limit: int = MAX_INPUT_BYTES,
) -> CapturedInput:
    path = local_path(path)
    content = read_fixture(path.parent, path.name, limit=limit)
    pin = InputPin(role=role, sha256=byte_digest(content), size_bytes=len(content))
    if expected is not None and expected != pin.sha256:
        raise ValueError("DVI-CLI-INTEGRITY: input SHA-256 differs from the supplied pin")
    return CapturedInput(path, content, pin, limit)


def destination(out: Path | None) -> Path | None:
    if out is None:
        return None
    path = local_path(out)
    if path.exists():
        raise ValueError("DVI-CLI-EXISTS: output must be a new local directory")
    return path


def finish[T: ValueModel](
    command: CommandName,
    files: dict[str, bytes],
    result: T,
    summary: str,
    sources: tuple[CapturedInput, ...],
    out: Path | None,
    json_output: bool,
    *,
    exit_status: Literal[0, 1] = 0,
    pins: tuple[InputPin, ...] = (),
) -> None:
    if not files or len(files) > 128 or "command_result.json" in files:
        raise ValueError("DVI-CLI-OUTPUT: invalid analysis artifact inventory")
    artifacts = tuple(
        ArtifactEntry(
            path=portable_path(name), sha256=byte_digest(content), size_bytes=len(content)
        )
        for name, content in sorted(files.items())
    )
    response = AnalysisResult(
        command=command,
        status="failed" if exit_status else "completed",
        exit_status=exit_status,
        summary=summary,
        sources=tuple(s.pin for s in sources) + pins,
        artifacts=artifacts,
        result=result,
    )
    encoded = (canonical_json(response) + "\n").encode("utf-8")
    if sum(map(len, files.values())) + len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("DVI-CLI-BOUNDS: complete output exceeds 32 MiB")
    for source in sources:
        source.recheck()
    output = destination(out)
    if output is not None:
        output.mkdir(parents=True, exist_ok=False)
        for name, content in sorted((files | {"command_result.json": encoded}).items()):
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(content)
    if json_output:
        typer.echo(encoded.decode("utf-8"), nl=False)
    else:
        console = Console(markup=False, highlight=False)
        console.print(f"{command}: {summary}")
        console.print(f"Artifacts: {len(artifacts)}; exit {exit_status}")
        if output is not None:
            console.print(f"Output: {output}")
        console.print("Analysis findings are conditional on these local inputs.")
    if exit_status:
        raise typer.Exit(exit_status)


def execute[T: ValueModel, R: ValueModel](
    command: CommandName,
    path: Path,
    input_model: type[T],
    analyze: Callable[[T], dict[str, bytes]],
    primary: str,
    result_model: type[R],
    describe: Callable[[R], str],
    out: Path | None,
    json_output: bool,
    expected: str | None,
) -> None:
    try:
        output = destination(out)
        source = capture(path, expected=expected)
        request = input_model.model_validate(parse_json(source.content))
        files = analyze(request)
        result = result_model.model_validate(parse_json(files[primary]))
        summary = describe(result)  # Also enforces native authoritative gate failures.
        finish(command, files, result, summary, (source,), output, json_output)
    except (ValueError, OSError, RecursionError, OverflowError) as exc:
        fail(exc, json_output)
