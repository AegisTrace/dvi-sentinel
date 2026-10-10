# CI quality gate

The [workflow](../.github/workflows/ci.yml) runs on pushes, pull requests and manual
dispatch. Three Ubuntu 24.04 jobs must pass for the exact commit: `core (3.12)`,
`core (3.13)` and `container`. Each has a fifteen-minute timeout. Obsolete runs for
the same ref are cancelled. CI verifies development behavior; it does not publish
packages, images, releases or tags.

## Installed package proof

Both Python jobs run whole-repository Ruff lint/format, strict mypy and the complete
pytest suite with JUnit and branch coverage, requiring at least 90% combined
statement/branch coverage. They build a wheel and sdist, download the wheel's
dependencies to a local wheelhouse, then install into an isolated environment with
`--no-index --find-links`. `pip check`, doctor and the module version run against
the installed package; the first CLI inspection runs outside the checkout.

The installed CLI then executes:

- The established V1 robust fixture, acceptance gate and fixture benchmarks.
- `dvi benchmark benchmarks --out runs/benchmarks/v2 --json`: all 32 expert
  diagnostic/control cases across sixteen categories, with independent expectations.
- `dvi run examples/v2/ci/scenario.yaml --out runs/ci-v2 --seed 42 --event-budget 256 --json`:
  a robust synthetic flow predicate under bounded timing, ordering, metadata and
  volume variations. This uses the existing scenario workflow.
- `dvi report runs/ci-v2 --overwrite --json`: regenerate the retained report and
  verify that its manifest still matches the original run.
- `dvi ci-check runs/ci-v2 --threshold 1 --max-unknown 0 --json`: require every
  measured case detected and no unknown outcomes.
- The fragile artifact fixture under the same gate, requiring an actual measured
  miss and exit 1; report overwrite refusal, requiring its specific reason and exit 2.
- The advanced report example and all ten V2 analysis commands with native artifacts.

The [proof verifier](../examples/verify_ci_proof.py) reads captured command JSON,
verifies actual bundle manifests and counts, rederives both gate results, checks
the unchanged report, and compares every native benchmark artifact to its typed
command result and digest. `--require-installed` also rejects an import outside the
active isolated environment. Captured paths are compared as text without resolving
them against the filesystem. The verifier reads bounded local evidence and invokes
no commands. Tests tamper with measurements, thresholds, assets and bytes to prove
that plausible-looking summaries cannot substitute for matching artifacts.

## Container and network boundary

The container job builds the digest-pinned [Dockerfile](../Dockerfile) with its
hash-locked runtime dependencies. Execution uses a non-root UID/GID, `--network none`,
`--read-only`, `--cap-drop ALL`, `no-new-privileges`, a bounded temporary filesystem
and a single output mount. It runs doctor, the full V2 benchmark, robust scenario,
report regeneration and strict gate, plus all ten commands and the advanced report.

The workflow uses only `contents: read`, requires no repository secrets and does
not retain checkout credentials. It does not use `pull_request_target`. Python tests
automatically deny DNS and network socket I/O; this guard is not an OS sandbox.
Actions transport, dependency download and image/package build can use the network.
Runtime fixture checks need no network after installation, and the container job
enforces that boundary. No scenario supplies shell commands or external detectors.

## Retained evidence and limits

Each Python job uploads only fixture bundles, command/proof JSON, benchmark reports,
advanced reports, ten-command outputs, JUnit and coverage XML. The container job
uploads its corresponding fixture evidence. Artifacts are attempted even after a
failed step, have distinct job names and expire after seven days. No credentials,
external telemetry, hidden files or arbitrary workspace directories are selected.

A coverage floor does not prove every behavior correct. Independent expectations,
negative controls and artifact verification supply behavioral evidence. Hashes do
not authenticate authorship; there is no signed attestation or SBOM. CI does not
establish visual readability. Release publication also requires a rendered report inspection and the remaining
release gates, recorded for V2 in [release verification](release_v2.md). V1's inspection is recorded in
[release verification](release_v1.md).

## Action and dependency maintenance

Actions use full commit SHAs verified against stable releases, with versions in
comments. Review release notes and update each SHA/version pair together:

- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)
- [actions/setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0)
- [actions/upload-artifact v7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1)

Workflow syntax is checked locally with
[actionlint v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12), verified
against its published SHA-256 checksum. It is not a runtime dependency.

Dependency vulnerability alerts are enabled. Maintainers review alerts and publish
tested updates directly on `main`. The [Dependabot configuration](../.github/dependabot.yml)
covers uv, Actions and Docker with version update pull requests disabled by
`open-pull-requests-limit: 0`, as documented in
[GitHub's version update guidance](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configuring-dependabot-version-updates).
Automatic security update pull requests are separately disabled in repository
settings: the version limit does not disable them, per
[GitHub's security update guidance](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/customizing-dependabot-security-prs).
These settings preserve the repository's only-`main` policy; alerts alone do not
remediate vulnerabilities or guarantee a response time.

## Local reproduction

Use a fresh environment and output directories. From the repository root:

```sh
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src/dvi_sentinel
python -m coverage run -m pytest --junitxml=runs/pytest.xml
python -m coverage report --fail-under=90
python -m coverage xml
python -m build
python -m pip download --only-binary=:all: --dest runs/wheelhouse dist/*.whl
python -m venv .venv-package
.venv-package/bin/python -m pip install --no-index --find-links runs/wheelhouse dist/*.whl
.venv-package/bin/python -m pip check
.venv-package/bin/dvi doctor --json
.venv-package/bin/dvi benchmark benchmarks --out runs/benchmarks/v2 --json
.venv-package/bin/dvi run examples/v2/ci/scenario.yaml --out runs/ci-v2 --seed 42 --event-budget 256 --json
.venv-package/bin/dvi report runs/ci-v2 --overwrite --json
.venv-package/bin/dvi ci-check runs/ci-v2 --threshold 1 --max-unknown 0 --json
.venv-package/bin/python examples/advanced_report.py --out runs/reports/v2
.venv-package/bin/python examples/v2_cli.py --out runs/cli/v2
.venv-package/bin/python -m examples.release_v2 --out runs/release-v2
```

The workflow contains the exact capture paths and exit-code checks needed before
running `python examples/verify_ci_proof.py --root runs --require-installed`. Run
that verifier with the isolated environment's Python, before moving the evidence:
captured command paths describe their original execution location.

On Windows, use `Scripts/` instead of `bin/` and an explicit wheel path because
PowerShell does not expand native-command file globs. Capture JSON as UTF-8; older
PowerShell redirection defaults to UTF-16. Use absolute executables from outside
the checkout for installed-package inspection. Repeated output needs a fresh
destination or the command's supported, verified overwrite option.
