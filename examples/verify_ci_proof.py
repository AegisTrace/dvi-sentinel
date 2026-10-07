"""Verify retained CI command evidence against actual local artifacts; no execution."""

import argparse
import sys
from pathlib import Path
from typing import Literal

import dvi_sentinel
from dvi_sentinel.artifact_contract import read_model
from dvi_sentinel.artifact_models import ArtifactVerification, RunRecord
from dvi_sentinel.artifact_store import verify_artifacts
from dvi_sentinel.ci_gate import check_run
from dvi_sentinel.cli.analysis_io import local_path
from dvi_sentinel.cli.analysis_models import AnalysisResult
from dvi_sentinel.expert_benchmark_models import ExpertReport
from dvi_sentinel.expert_benchmark_reports import expert_benchmark_artifacts
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.models import NonEmpty, Sha256, ValueModel
from dvi_sentinel.score_models import ResilienceFrontier
from dvi_sentinel.serialization import canonical_json, parse_json
from dvi_sentinel.workflow_models import DoctorReport, GateResult, RunSummary


class ReportResult(ValueModel):
    schema_version: Literal["1"]
    status: Literal["completed"]
    exit_status: Literal[0]
    report: NonEmpty
    verification: ArtifactVerification


class Refusal(ValueModel):
    schema_version: Literal["1"]
    status: Literal["invalid_input"]
    exit_status: Literal[2]
    reason: NonEmpty


class CIProof(ValueModel):
    schema_version: Literal["1"] = "1"
    status: Literal["verified"] = "verified"
    tool_version: NonEmpty
    installed_package: bool
    benchmark_cases: Literal[32] = 32
    benchmark_sha256: Sha256
    robust_manifest: Sha256
    fragile_manifest: Sha256
    report_unchanged: Literal[True] = True
    robust_exit: Literal[0] = 0
    fragile_exit: Literal[1] = 1
    refusal_exit: Literal[2] = 2


def read[T: ValueModel](root: Path, name: str, model: type[T]) -> T:
    return model.model_validate(parse_json(read_fixture(root, name, limit=32 * 1024 * 1024)))


def verify_run(root: Path, name: str, *, fragile: bool) -> ArtifactVerification:
    directory = local_path(root / name)
    prefix = "fragile-" if fragile else ""
    saved = read(root, f"ci-v2-evidence/{prefix}run.json", RunSummary)
    checked = verify_artifacts(directory, expected_manifest_digest=saved.manifest_digest)
    record = read_model(directory, "run.json", RunRecord)
    score = read_model(directory, "score.json", ResilienceFrontier)
    if (
        not checked.valid
        or checked.run_id != saved.run_id
        or record.scenario_id != ("artifact-proof" if fragile else "v2-ci-control")
        or Path(saved.output) != directory
        or Path(saved.report) != directory / "report.html"
        or any(
            getattr(saved, field) != getattr(score.metrics, field)
            for field in ("detected", "missed", "unknown", "invalid")
        )
        or saved.findings != len(score.findings)
    ):
        raise ValueError("DVI-CI-PROOF: run summary differs from verified fixture evidence")
    gate = read(root, f"ci-v2-evidence/{prefix}gate.json", GateResult)
    actual = check_run(record, score, threshold=1.0, max_unknown=0.0)
    if gate != actual or actual.exit_status != (1 if fragile else 0):
        raise ValueError("DVI-CI-PROOF: declared threshold or expected gate outcome differs")
    if fragile and saved.missed == 0:
        raise ValueError("DVI-CI-PROOF: negative control needs an actual measured miss")
    return checked


def verify(root: Path, *, require_installed: bool = False) -> CIProof:
    root = local_path(root)
    installed = Path(dvi_sentinel.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    if require_installed and not installed:
        raise ValueError("DVI-CI-PROOF: require the isolated installed package")
    doctor = read(root, "ci-v2-evidence/doctor.json", DoctorReport)
    required = {
        "python",
        "dvi-sentinel",
        "report template",
        "advanced report template",
        "advanced report stylesheet",
    }
    if (
        doctor.exit_status != 0
        or not required.issubset({c.name for c in doctor.checks})
        or any(c.status != "pass" for c in doctor.checks)
    ):
        raise ValueError("DVI-CI-PROOF: runtime or packaged report assets are unavailable")
    robust = verify_run(root, "ci-v2", fragile=False)
    fragile = verify_run(root, "ci-v2-fragile", fragile=True)
    report = read(root, "ci-v2-evidence/report.json", ReportResult)
    if report.verification != robust or Path(report.report) != root / "ci-v2/report.html":
        raise ValueError("DVI-CI-PROOF: regenerated report changed the original bundle")
    refusal = read(root, "ci-v2-evidence/report-refusal.json", Refusal)
    if "DVI-REPORT-EXISTS" not in refusal.reason:
        raise ValueError("DVI-CI-PROOF: expected explicit report overwrite refusal")
    benchmark = read(root, "ci-v2-evidence/benchmark.json", AnalysisResult[ExpertReport])
    if (
        benchmark.command != "benchmark"
        or benchmark.exit_status != 0
        or benchmark.status != "completed"
        or not benchmark.result.passed
        or benchmark.result.scope != "full_suite"
        or len(benchmark.result.results) != 32
    ):
        raise ValueError("DVI-CI-PROOF: require all 32 expert cases with accepted measurements")
    artifacts = expert_benchmark_artifacts(benchmark.result)
    if {e.path for e in benchmark.artifacts} != set(artifacts):
        raise ValueError("DVI-CI-PROOF: incomplete benchmark artifact inventory")
    for entry in benchmark.artifacts:
        content = read_fixture(root, "benchmarks/v2/" + entry.path, limit=32 * 1024 * 1024)
        if (
            content != artifacts[entry.path]
            or len(content) != entry.size_bytes
            or byte_digest(content) != entry.sha256
        ):
            raise ValueError("DVI-CI-PROOF: benchmark artifact differs from command evidence")
    return CIProof(
        tool_version=dvi_sentinel.__version__,
        installed_package=installed,
        benchmark_sha256=byte_digest(artifacts["benchmark_report.json"]),
        robust_manifest=robust.manifest_digest,
        fragile_manifest=fragile.manifest_digest,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--require-installed", action="store_true")
    args = parser.parse_args()
    try:
        proof = verify(args.root, require_installed=args.require_installed)
    except (ValueError, OSError, RecursionError) as exc:
        parser.error(str(exc))
    print(canonical_json(proof))


if __name__ == "__main__":
    main()
