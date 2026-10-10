"""Produce the V2 release report with pinned expert benchmark evidence."""

import argparse
from pathlib import Path

from dvi_sentinel.artifact_models import LINEAGE_FILES
from dvi_sentinel.artifact_store import verify_artifacts, write_artifacts
from dvi_sentinel.expert_benchmark_reports import expert_benchmark_artifacts
from dvi_sentinel.expert_benchmarks import plain_local_path, run_expert_benchmarks
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.lineage_models import LineageSpec, ProvenanceDAG
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.provenance_bundle import extra_specifications, with_artifact_lineage
from dvi_sentinel.reports import write_reports
from examples.advanced_report import fixture_bundle


def release_bundle(benchmark_root: Path) -> dict[str, bytes]:
    """Attach actual benchmark results with checked source bytes and explicit parents."""
    benchmark_root = plain_local_path(benchmark_root)
    report = run_expert_benchmarks(benchmark_root)
    if not report.passed:
        raise ValueError("Release benchmark expectations failed")
    base = fixture_bundle()
    dag = ProvenanceDAG.model_validate_json(base["provenance_dag.json"])
    declarations = list(extra_specifications(dag, base))
    contents = {path: data for path, data in base.items() if path not in LINEAGE_FILES}
    sources = {}
    for result in report.results:
        for entry in result.sources:
            if entry.path in sources and sources[entry.path] != entry:
                raise ValueError("Benchmark source identity changed across cases")
            sources[entry.path] = entry
    for path, entry in sorted(sources.items()):
        data = read_fixture(benchmark_root, path)
        if len(data) != entry.size_bytes or byte_digest(data) != entry.sha256:
            raise ValueError("Benchmark source bytes changed after execution")
        name = "benchmark_sources/" + path
        contents[name] = data
        declarations.append(LineageSpec(path=name, kind="input_fixture", source=True))
    artifacts = expert_benchmark_artifacts(report)
    contents.update(artifacts)
    for path in artifacts:
        parents = (
            tuple(sorted("benchmark_sources/" + p for p in sources))
            if path == "benchmark_report.json"
            else ("benchmark_report.json",)
        )
        declarations.append(LineageSpec(path=path, kind="benchmark_result", parents=parents))
    return with_artifact_lineage(contents, declarations=tuple(declarations))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new local report directory")
    parser.add_argument(
        "--benchmarks", type=Path, default=Path(__file__).resolve().parents[1] / "benchmarks"
    )
    args = parser.parse_args()
    output = plain_local_path(args.out)
    if output.exists():
        parser.error("release output must be a new local directory")
    write_artifacts(output, release_bundle(args.benchmarks))
    anchor = write_reports(output, advanced=True)
    verified = verify_artifacts(output, expected_manifest_digest=anchor.manifest_digest)
    if not verified.valid:
        raise ValueError(verified.issues)
    print(f"Verified release report: {output / 'report.html'}")
    print(f"Manifest SHA-256: {anchor.manifest_digest}")


if __name__ == "__main__":
    main()
