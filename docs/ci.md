# CI quality gate

`.github/workflows/ci.yml` runs on pushes, pull requests and manual dispatch.
The Ubuntu 24.04 matrix covers Python 3.12 and 3.13 with a ten-minute job timeout.
It installs the editable development package with standard pip, runs Ruff,
formatting, strict mypy and the complete pytest suite with branch coverage, and
requires at least 90% combined coverage. It then builds a wheel/sdist, installs
the wheel into an isolated environment, runs `pip check`, and invokes the installed
CLI outside the checkout before running a bounded robust fixture and its CI gate.
It also runs the expert benchmark script through the installed wheel and retains
`benchmark_report.json`; the benchmark acceptance assertions are part of pytest.

The workflow uses only `contents: read`; it requires no repository secrets and
does not retain checkout credentials. It does not use `pull_request_target` or
execute a contributor-provided workflow with privileged base-repository secrets.
Obsolete runs for the same ref are cancelled. Python tests have an automatic guard
against DNS and network socket I/O; dependency installation and Actions transport
still require the runner's normal network access. This test guard is not an OS
sandbox. DVI's own scenario and fixture policies remain enforced independently.

Only generated documentation-fixture evidence and coverage XML are uploaded, with
seven-day retention and a distinct name for each Python version. No credentials,
external logs, arbitrary workspace directories or hidden files are selected.
These artifacts make failures and report provenance inspectable without rerunning
the job. They do not establish visual readability, which was separately confirmed
by the project owner for V1; see [release verification](release_v1.md).

## Action pinning policy

Use full commit SHAs from verified stable releases, with the corresponding version
in a comment. Review release notes and update the SHA/version together; tags are
not used as executable references. The initial pins were verified against the
official releases:

- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)
- [actions/setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0)
- [actions/upload-artifact v7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1)

Workflow syntax is checked locally with
[actionlint v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12), obtained
from its official release and verified against its published SHA-256 checksums.
It is a development validation tool, not a package/runtime dependency.

## Local reproduction

In a fresh environment, from the repository root:

```sh
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src/dvi_sentinel
python -m coverage run -m pytest
python -m coverage report --fail-under=90
python -m coverage xml
python -m build
python -m venv .venv-package
.venv-package/bin/python -m pip install dist/*.whl
.venv-package/bin/python -m pip check
.venv-package/bin/dvi doctor --json
.venv-package/bin/python -m dvi_sentinel.cli.main --version
.venv-package/bin/dvi run examples/foundation_scenario.yaml --out runs/ci --seed 42 --event-budget 256 --json
.venv-package/bin/dvi ci-check runs/ci --threshold 1 --json
.venv-package/bin/python examples/run_benchmarks.py --out runs/benchmarks/benchmark_report.json
```

On Windows, replace `bin/` with `Scripts/`, and pass the wheel path explicitly
because PowerShell does not expand native-command file globs. Run the doctor and
module-version checks from outside the checkout using absolute executable paths
to confirm installed-package behavior. Repeat output requires a verified prior
bundle and `--overwrite`, or a fresh destination.

The 90% coverage floor is a regression guard, not evidence that every behavior is
correct. Property, metamorphic, interaction and benchmark assertions provide
behavioral evidence. Dependabot, SBOM, Scorecard and SARIF remain roadmap work.
