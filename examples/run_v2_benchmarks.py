"""Run the sixteen-category fixture-only expert suite with regression exit codes."""

import argparse
from pathlib import Path

from dvi_sentinel.expert_benchmark_reports import write_expert_benchmarks
from dvi_sentinel.expert_benchmarks import plain_local_path, run_expert_benchmarks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1] / "benchmarks"
    )
    parser.add_argument("--case", dest="case_id")
    parser.add_argument(
        "--out", type=Path, required=True, help="new local directory for three artifacts"
    )
    args = parser.parse_args(argv)
    try:
        destination = plain_local_path(args.out)
        if destination.exists():
            raise ValueError("DVI-EXPERT-OUTPUT: destination must be a new local directory")
        report = run_expert_benchmarks(args.root, case_id=args.case_id)
        write_expert_benchmarks(destination, report)
    except (ValueError, OSError, RecursionError) as exc:
        parser.error(str(exc))
    print(
        f"{report.scope}: "
        f"{sum(r.passed for r in report.results)}/{len(report.results)} cases passed"
    )
    for result in report.results:
        for check in result.checks:
            if not check.passed:
                print(f"FAIL {result.case.benchmark_id}: {check.name}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
