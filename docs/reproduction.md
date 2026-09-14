# Fresh-checkout reproduction

Verified on 2026-09-14 at commit
`e7469d0578da4dcf367b49983a3ddb763b170ff9`, package `0.1.0.dev0`, using a fresh
GitHub clone, Python 3.12.14 on Windows and Docker's Linux engine 29.5.2. The
commands below use PowerShell. They need Git and Python 3.12/3.13; Docker is needed
only for the container section. Clone/install/build can fetch dependencies. DVI
execution reads synthetic local fixtures and requires no credentials or targets.

The recorded checkout is `runs/phase20-checkout/` beneath the original repository.
Start from an unused directory. Outputs are created under the new checkout's
`runs/`; existing output directories are deliberately refused. This proves the
development candidate's executable workflow. The separate rendered HTML check
remains open; this record does not declare a release.

## Install and execute

The verification cloned with
`git clone https://github.com/AegisTrace/dvi-sentinel.git runs/phase20-checkout`
from the original repository, then used the new checkout as the working directory.
A fresh `.venv` was created with `uv venv .venv --python 3.12`; if Python is already
installed, `python -m venv .venv` is the standard equivalent. No activation is needed.

```powershell
.venv\Scripts\python.exe -m ensurepip
.venv\Scripts\python.exe -m pip install -e '.[dev]'
.venv\Scripts\python.exe -m pip check
.venv\Scripts\dvi.exe doctor --json
.venv\Scripts\dvi.exe validate benchmarks/benign_noise-control.yaml --json
.venv\Scripts\dvi.exe run benchmarks/benign_noise-control.yaml --out runs/robust --seed 42 --event-budget 256 --json
.venv\Scripts\dvi.exe run examples/artifact_scenario.yaml --out runs/fragile --seed 42 --event-budget 256 --json
.venv\Scripts\dvi.exe run benchmarks/benign_noise-control.yaml --out runs/robust-repeat --seed 42 --event-budget 256 --json
.venv\Scripts\dvi.exe compare runs/robust runs/robust-repeat --json
.venv\Scripts\dvi.exe ci-check runs/robust --threshold 1 --json
.venv\Scripts\dvi.exe ci-check runs/fragile --threshold 1 --json
if ($LASTEXITCODE -ne 1) { throw 'Expected measured failure exit 1' }
.venv\Scripts\python.exe examples/run_benchmarks.py --out runs/benchmarks/benchmark_report.json
```

Every command above returned 0 except the deliberately failing fragile CI gate,
which returned 1. `doctor` reported ready and all dependency/template checks passed.
The robust scenario detected both generated variants, with no findings or
unknowns. The fragile scenario detected 2/11 variants and missed nine, with ten
findings across variation/probe evidence and a saved minimum. Its run command
still returns 0 because the experiment completed successfully.

The repeated robust run compares as passed with no new misses. The full benchmark
runner passes all 20 cases and 275 checks, including ten controls with no findings.
See [benchmark limits](benchmarks.md) and [CLI gate semantics](cli.md).

## Inspect evidence and regenerate reports

Read `runs/fragile/report.md` for the finding summary; `report.json` retains the
typed analysis, `provenance.json` maps findings to source hashes and record/field
locations, and `minimal_case.json` retains the bounded counterexample. The
standalone `report.html` contains the same human sections with embedded CSS.

```powershell
$reportPaths = @('runs/fragile/report.json', 'runs/fragile/report.md', 'runs/fragile/report.html', 'runs/fragile/provenance.json', 'runs/fragile/manifest.json')
$beforeReport = Get-FileHash -LiteralPath $reportPaths -Algorithm SHA256
.venv\Scripts\dvi.exe report runs/fragile --overwrite --json
$afterReport = Get-FileHash -LiteralPath $reportPaths -Algorithm SHA256
if (Compare-Object $beforeReport $afterReport -Property Path,Hash) { throw 'Report bytes changed' }
```

Regeneration returned 0 and all five files stayed byte-identical. Manifest-backed
consumer commands verify the bundle before reading it. Direct verification also
passed against the independently recorded manifest hashes below. All 72 evidence
references in the fragile provenance resolved, with matching SHA-256 values and
valid JSON/JSONL pointers; both robust bundles each had two valid event references.

| Output directory | Observed manifest SHA-256 |
| --- | --- |
| `runs/robust/` | `19cdd89f4cbb6a7c4f26a756cf711bdf8e59a93b9eccfb7df93a63a9461db291` |
| `runs/robust-repeat/` | `b81ed97e1878e4fb096e488e77e6b4a4eb517d822e44c40c917aad8bb21c4786` |
| `runs/fragile/` | `151135cebea2b9b3589e3d6979abe287da4e39c1a3aa3041401baf14b48cedfa` |

These hashes identify this recorded execution. New runs have different clocks
and invocation provenance, so their complete manifest hashes change. Save the
`manifest_digest` printed by your own run outside its bundle. The verification API
accepts that value as `expected_manifest_digest`; see [artifact integrity](run_artifacts.md).

## Verify an actual regression

The following executed setup copies the existing synthetic fixture and creates
two scenario files differing only in the detector's count limit. It requires no
manual editing. Keeping metadata, input paths, expectations, seed and variation
settings identical makes the detector comparison meaningful.

```powershell
@'
from pathlib import Path
import yaml
root = Path('runs/regression-inputs')
(root / 'probes').mkdir(parents=True)
(root / 'probes/events.jsonl').write_bytes(Path('examples/probes/events.jsonl').read_bytes())
scenario = yaml.safe_load(Path('examples/artifact_scenario.yaml').read_text(encoding='utf-8'))
(root / 'fragile.yaml').write_text(yaml.safe_dump(scenario), encoding='utf-8')
scenario['harness']['rules'][0]['max_count'] = None
(root / 'robust.yaml').write_text(yaml.safe_dump(scenario), encoding='utf-8')
'@ | .venv\Scripts\python.exe -
.venv\Scripts\dvi.exe run runs/regression-inputs/robust.yaml --out runs/regression-baseline --seed 42 --event-budget 256 --json
.venv\Scripts\dvi.exe run runs/regression-inputs/fragile.yaml --out runs/regression-current --seed 42 --event-budget 256 --json
$regressionJson = .venv\Scripts\dvi.exe compare runs/regression-baseline runs/regression-current --json
if ($LASTEXITCODE -ne 1) { throw 'Expected regression exit 1' }
$regression = $regressionJson | ConvertFrom-Json
if ($regression.status -ne 'regressed' -or $regression.newly_missed.Count -ne 9) { throw 'Unexpected regression evidence' }
.venv\Scripts\dvi.exe report runs/regression-current --baseline runs/regression-baseline --overwrite --json
```

Observed: the baseline detected 11/11 variants; the changed rule detected 2/11.
Comparison returned `regressed`, nine newly missed cases and exit 1. Report
regeneration returned 0 and captured the baseline/thresholds/results in the bundle.
Its resulting verified manifest is
`e43f8f0b57598ac239f1e8eeb5f034d2eaa7dde60a05f97f8cdbf2b87553800c`.
Different benchmark scenario IDs are intentionally incompatible; comparing those
would not establish a detector regression.

## Quality and packaging checks

```powershell
.venv\Scripts\ruff.exe check .
.venv\Scripts\ruff.exe format --check .
.venv\Scripts\mypy.exe src/dvi_sentinel
.venv\Scripts\python.exe -m coverage run -m pytest
.venv\Scripts\python.exe -m coverage report --fail-under=90
.venv\Scripts\python.exe -m build
.venv\Scripts\python.exe -m venv .venv-wheel
.venv-wheel\Scripts\python.exe -m pip install dist/dvi_sentinel-0.1.0.dev0-py3-none-any.whl
.venv-wheel\Scripts\python.exe -m pip check
```

Observed: Ruff 0.16.7 passed; 101 Python files were formatted; mypy 1.20.2 passed
50 source files; pytest 9.1.1/Hypothesis 6.168.0 passed 418 tests in 154.16 seconds.
One real symlink test was skipped because Windows denied creation privilege;
Linux CI executes that test. Combined statement/branch coverage was 95%.
Build 1.6.1 with isolated Hatchling 1.32.0 produced a wheel and sdist. Runtime
versions were Jinja2 3.1.6, Pydantic 2.13.5, PyYAML 6.0.3, Rich 14.3.4 and
Typer 0.27.2. These are the observed standard-pip resolution; `uv.lock` provides
the separate pinned dependency workflow.

The wheel was also checked outside the source checkout's root, then used for a
complete robust run with its own output directory:

```powershell
$wheelDvi = (Resolve-Path -LiteralPath .venv-wheel/Scripts/dvi.exe).Path
$wheelPython = (Resolve-Path -LiteralPath .venv-wheel/Scripts/python.exe).Path
Push-Location runs
try {
  & $wheelDvi doctor --json
  & $wheelPython -m dvi_sentinel.cli.main --version
} finally { Pop-Location }
.venv-wheel\Scripts\dvi.exe run benchmarks/benign_noise-control.yaml --out runs/wheel-robust --seed 42 --event-budget 256 --json
.venv-wheel\Scripts\dvi.exe ci-check runs/wheel-robust --threshold 1 --json
```

All returned 0; the installed template was present and the robust gate passed.
The wheel run's verified manifest is
`b9e5ffdcf763de1b9d39bc9b592e5a41590002541e21634a07a610fd85fae0d4`.
The fresh checkout's `git status --short` was empty after all proofs; fixtures and
tracked files were unchanged.

## Docker reproduction

Docker Desktop was started with its `docker desktop start` command. From the fresh
checkout, these commands built an image and ran without container networking,
with a read-only root filesystem, no added capabilities and a confined runs mount.

```powershell
docker build -t dvi-sentinel:phase20 .
$proofRuns = (Resolve-Path -LiteralPath runs).Path
$containerArgs = @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m', '--mount', "type=bind,source=$proofRuns,target=/runs", 'dvi-sentinel:phase20')
docker @containerArgs dvi doctor --json
docker @containerArgs dvi run benchmarks/benign_noise-control.yaml --out /runs/docker-robust --seed 42 --event-budget 256 --json
docker @containerArgs dvi run examples/artifact_scenario.yaml --out /runs/docker-fragile --seed 42 --event-budget 256 --json
docker @containerArgs dvi ci-check /runs/docker-robust --threshold 1 --json
docker @containerArgs dvi ci-check /runs/docker-fragile --threshold 1 --json
if ($LASTEXITCODE -ne 1) { throw 'Expected measured failure exit 1' }
docker @containerArgs python examples/run_benchmarks.py --out /runs/docker-benchmarks/benchmark_report.json
```

Container Python 3.13.15 produced the same outcomes and expected exit codes.
The host verified both Docker bundles against their printed manifest hashes:
`e5484a9b5903e98a99feb3e6532189247ebcab8b03f95e6f52173ce8bc13d865` (robust) and
`d2e7789252d308b4fd79c621836747bdbe07cb2598f6a37b734905c358cdc717` (fragile).
For each run, these eight analysis files match native Python byte for byte:
`normalized_events.jsonl`, `variations.jsonl`, `observations.jsonl`,
`matches.jsonl`, `score.json`, `comparison.json`, `assumption_probes.jsonl` and
`differential_schema_report.json`. Both benchmark reports also match exactly:
SHA-256 `5bd60bd5d90e2685cb91dfc4aa46669e4a24d8bb48902bf8bb29f3108f220618`.
See [Docker notes](docker.md) for Linux bind-mount ownership and Compose usage.
