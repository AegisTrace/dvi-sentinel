"""Add verified report outputs to the artifact example's existing bundle."""

from pathlib import Path

from dvi_sentinel.reports import write_reports

if __name__ == "__main__":
    output = Path(__file__).parent.parent / "runs/artifact-proof"
    result = write_reports(output, overwrite=True)
    print(f"{result.run_id}: reports verified; manifest {result.manifest_digest}")
