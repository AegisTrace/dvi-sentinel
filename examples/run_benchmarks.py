"""Execute the repository benchmark suite and write its deterministic evidence report."""

import argparse
from pathlib import Path

from dvi_sentinel.benchmarks import run_benchmarks
from dvi_sentinel.serialization import canonical_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/benchmarks/benchmark_report.json"))
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output exists; choose a new --out path")
    report = run_benchmarks(Path(__file__).resolve().parents[1] / "benchmarks")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8", newline="\n") as output:
        output.write(canonical_json(report) + "\n")
    for result in report.results:
        print(f"{result.case.id}: {'PASS' if result.passed else 'FAIL'}")
        for check in result.checks:
            if not check.passed:
                print(f"  {check.name}: expected {check.expected}; observed {check.observed}")
    print(f"Report: {args.out}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
