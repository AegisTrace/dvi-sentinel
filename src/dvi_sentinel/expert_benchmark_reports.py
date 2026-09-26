"""Deterministic evidence-linked benchmark projections and bounded new-directory writes (A/W)."""

from html import escape
from pathlib import Path

from pydantic import JsonValue

from dvi_sentinel.expert_benchmark_models import ExpertReport
from dvi_sentinel.expert_benchmark_summary import summarize_expert
from dvi_sentinel.expert_benchmarks import plain_local_path
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.serialization import canonical_json

MAX_OUTPUT_BYTES = 32 * 1024 * 1024


def _cell(value: str) -> str:
    value = escape(value, quote=True)
    for char in "\\`*_{}[]()#+-.!|":
        value = value.replace(char, "\\" + char)
    return value.replace("\r", " ").replace("\n", " ")


def expert_benchmark_artifacts(report: ExpertReport) -> dict[str, bytes]:
    """Revalidate checks and native projections; return three canonical linked artifacts."""
    report = ExpertReport.model_validate(report.model_dump(mode="python"))
    if any(r.measured != summarize_expert(r.evidence) for r in report.results):
        raise ValueError("DVI-EXPERT-PROJECTION: summary differs from native engine evidence")
    encoded = (canonical_json(report) + "\n").encode("utf-8")
    rows: list[JsonValue] = []
    lines = [
        "# Expert benchmark report",
        "",
        f"Scope: {report.scope}. Checks passed: "
        f"{sum(r.passed for r in report.results)}/{len(report.results)}.",
        "",
        "A passing check reproduces a declared diagnostic or control. "
        "It is not a release-safety verdict.",
        "Unknown evidence remains unknown; non-applicable analyses "
        "include reasons in the JSON report.",
        "Scores have different scopes and must not be averaged across categories.",
        "",
        "[Native evidence and expectations](benchmark_report.json) | "
        "[Evidence matrix](benchmark_matrix.json)",
        "",
        "| Benchmark | Role | State | Findings | Score (numerator/denominator) | Checks |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for index, result in enumerate(report.results):
        measured, case = result.measured, result.case
        rows.append(
            {
                "benchmark_id": case.benchmark_id,
                "category": case.category,
                "control": case.control,
                "passed": result.passed,
                "measured": measured.model_dump(mode="json"),
                "evidence_ref": f"/results/{index}/evidence",
                "evidence_sha256": result.evidence.stable_digest(),
                "checks_ref": f"/results/{index}/checks",
                "sources_ref": f"/results/{index}/sources",
            }
        )
        ratio = measured.score.ratio
        score = f"{measured.score.metric}: {ratio.numerator}/{ratio.denominator}"
        lines.append(
            "| "
            + " | ".join(
                _cell(v)
                for v in (
                    case.benchmark_id,
                    "control" if case.control else "diagnostic",
                    measured.state,
                    ", ".join(measured.findings) or "none",
                    score,
                    "pass" if result.passed else "FAIL",
                )
            )
            + " |"
        )
    lines.extend(("", "## Regressions", ""))
    failed = [
        f"- {_cell(r.case.benchmark_id)}: {_cell(c.name)}; expected {_cell(c.expected)}, "
        f"observed {_cell(c.observed)}."
        for r in report.results
        for c in r.checks
        if not c.passed
    ]
    lines.extend(failed or ["None."])
    matrix: dict[str, JsonValue] = {
        "schema_version": "2",
        "scope": report.scope,
        "suite_sha256": report.suite_sha256,
        "report_file": "benchmark_report.json",
        "report_sha256": byte_digest(encoded),
        "passed": report.passed,
        "rows": rows,
    }
    contents = {
        "benchmark_report.json": encoded,
        "benchmark_report.md": ("\n".join(lines) + "\n").encode("utf-8"),
        "benchmark_matrix.json": (canonical_json(matrix) + "\n").encode("utf-8"),
    }
    if sum(map(len, contents.values())) > MAX_OUTPUT_BYTES:
        raise ValueError("DVI-EXPERT-BOUNDS: combined benchmark artifacts exceed 32 MiB")
    return contents


def write_expert_benchmarks(destination: Path, report: ExpertReport) -> None:
    destination = plain_local_path(destination)
    if destination.exists():
        raise ValueError("DVI-EXPERT-OUTPUT: destination must be a new local directory")
    contents = expert_benchmark_artifacts(report)
    destination.mkdir(parents=True, exist_ok=False)
    for path, content in sorted(contents.items()):
        with (destination / path).open("xb") as stream:
            stream.write(content)
