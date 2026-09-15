# V1 release verification

Version `1.0.0`, 2026-09-14. DVI Sentinel's supported scope is local,
synthetic/documentation-fixture detection-resilience analysis. V1.5/V2 capabilities
remain [roadmap items](roadmap.md).

## Visual evidence

The project owner reviewed the generated HTML report and confirmed in the build
conversation on 2026-09-14: **“Visual seems good.”** This resolves Phase 13's
previously missing rendered-readability check. It is human confirmation, not an
automated browser inspection, screenshot or accessibility certification. The report
template is unchanged in this release. Content, escaping, provenance, local links
and deterministic regeneration have separate executable tests.

## Release change and safety review

The final change promotes the package version from `0.1.0.dev0` to `1.0.0` in
package metadata, the version constant and the lockfile. It removes the obsolete
alpha classifier and updates release-status documentation. There are no dependency,
detector, parser, policy, report-template or runtime behavior changes.
Private workspace configuration remains excluded. The
[repository safety review](../RELEASE_SAFETY_REVIEW.md) remains applicable.

## Validation

Final local Python 3.13.15 verification: **418 tests passed**, one Windows symlink
privilege skip, **95% combined statement/branch coverage**, in 145.21 seconds.
Ruff lint/format, strict mypy on 50 source files, actionlint and lock validation passed.
The installed distribution/version equality test passed with `1.0.0`.

Executed from the repository root in PowerShell:

```powershell
.venv\Scripts\ruff.exe check .
.venv\Scripts\ruff.exe format --check .
.venv\Scripts\mypy.exe src/dvi_sentinel
.venv-tools\actionlint\actionlint.exe
uv lock --check
.venv\Scripts\python.exe -m coverage run -m pytest
.venv\Scripts\python.exe -m coverage report --fail-under=90
```

The environment was refreshed with `uv pip install --python
.venv\Scripts\python.exe --no-deps -e .`; `uv lock --offline` changed only the
project version. `uv` was available on the verification process's PATH.

Earlier full clean-checkout, README-reader, wheel-only and Docker proof is in
[reproduction](reproduction.md), with exact commands, expected 0/1 gate exits,
the compatible nine-miss regression and independently recorded manifest anchors.
The [build log](build_log.md) preserves the chronological phase evidence.

## Installed 1.0.0 wheel and artifacts

Built the release with `.venv\Scripts\python.exe -m build --outdir
runs/release-v1/preflight-dist`, then created a fresh runtime-only Python 3.12.14
environment with `uv venv .venv-release --python 3.12`. Installed the wheel using
`uv pip install --python .venv-release\Scripts\python.exe
runs/release-v1/preflight-dist/dvi_sentinel-1.0.0-py3-none-any.whl`;
`uv pip check --python .venv-release\Scripts\python.exe` passed.

All CLI invocations used that wheel with working directory `runs/release-v1`,
outside the repository root. Absolute fixture and output paths were supplied.
The retained `runs/release-v1/commands.json` records all 15 actual invocations,
arguments, working directories, outputs and exits. Results:

- Version reports `1.0.0`; doctor is ready; robust scenario validation passes.
- Robust and repeated robust runs detect both variants with no findings; compare
  and the robust CI gate exit 0. The fragile run detects 2/11 variants and its gate
  exits 1, as intended, with no unknowns.
- Regenerating the fragile report preserves all five JSON/Markdown/HTML/provenance/
  manifest files byte for byte.
- The benchmark suite passes 20 cases and 275 checks. Ten robust controls have no
  findings. Nine fragile cases yield safe minima; the intentional adapter semantic
  disagreement does not claim an invariant-preserving minimum.
- A compatible detector change drops detection from 11/11 to 2/11. Comparison
  reports nine newly missed cases and exits 1; regenerated reporting retains the
  comparison. The setup changes only the count limit in the existing synthetic rule.
- All five native bundles verify against manifest digests captured separately
  from their command outputs, including the updated regression report.

| Native output under `runs/release-v1/` | Verified manifest SHA-256 |
| --- | --- |
| `robust/` | `60edafb604b686dd177fa37ee90a68b1bf32d605c5a008f2873e3a22a83ad6e2` |
| `fragile/` | `b03e61a0b272539bbfbbf158b641bade970d93214b519459425e9bfbc8b00bfa` |
| `robust-repeat/` | `cabbc9fcc46a5ed7e89fd8d71461755dd3f2a67e139d14bb23460a7c9af66cce` |
| `regression-baseline/` | `eff08c082937724a787eb0479a95ad5e4c48cf02b42eeac8a6128aba45a9cf82` |
| `regression-current/` after report regeneration | `df991889983347c42f64673f57136a3fd370427dbbd2f2edeb56b6751be614cd` |

## Docker 1.0.0

`docker build -t dvi-sentinel:1.0.0 .` passed. Using the same restrictions and
commands documented in [reproduction](reproduction.md), with `runs/release-v1`
bound to `/runs`, the version, doctor, robust/fragile runs, expected 0/1 CI gates
and full benchmark suite passed under Python 3.13.15. Host verification accepted
both bundles against their printed manifest digests:

- Robust: `f46b72d114d271eba5c911c6662f68d79b764d6fcad1290c2bd0bf11c3054ed7`.
- Fragile: `52c46b0701f1f1a291eb5558d4f64bf3ada8c15ee1e2fcea349b4a9f7934bec9`.

For each native/Docker pair, normalized events, variations, observations, matches,
score, comparison, probes and differential-schema analysis match byte for byte.
The complete native and Docker benchmark reports also match:
`01cd6fec1402911d1c61882c6569c2a6a07444c25a3d45c64edb67eba391618d`.
The changed benchmark digest relative to development records includes the new
tool version. Full run manifests retain invocation/time provenance and therefore
are not expected to match across separate executions.

## Publication boundary

Final wheel/sdist builds are validated before publication. The annotated `v1.0.0`
tag identifies the release commit; its GitHub release carries the wheel, sdist and
SHA-256 inventory. Publication requires successful Python 3.12/3.13 CI for that
commit. Release notes record the actual commit and CI links rather than predicting
them here. The package is distributed through GitHub Releases; no PyPI publication
or signed supply-chain attestation is claimed.
