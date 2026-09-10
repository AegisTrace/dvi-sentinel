# Docker reproduction

The image installs the same Python package and contains the synthetic examples
under `/opt/dvi/examples`. Commands start in `/opt/dvi`. There is no server,
entrypoint wrapper, exposed port, extra service or live detector integration.
The default command is `dvi doctor`; arguments replace it, for example
`docker run --rm --network none dvi-sentinel:local dvi --help`.

The Dockerfile pins the official Python 3.13.15 slim Bookworm multi-platform index
by SHA-256. Runtime dependencies are exported from `uv.lock` with exact versions
and distribution hashes; pip checks those hashes before installing. Normal native
pip installation still uses the package's supported dependency ranges. Package
build isolation resolves Hatchling within its declared major-version bound, so
this is reproducible analysis, not a claim of bit-identical image layers or a
fully hermetic package build. Initial proof covers Linux amd64 on Docker Desktop.

The build needs access to the image registry and Python package index. Runtime
commands below disable networking. The image's default user/group is 10001:10001.
Compose drops all capabilities, disallows privilege escalation, makes the root
filesystem read-only, and provides a bounded 128 MiB temporary filesystem for
atomic report preparation. Its only persistent mount is repository `runs/` at
`/runs`. The allowlist in `.dockerignore` excludes Git metadata, environments,
prior artifacts and unrelated workspace files from the build context.

## Run the packaged example

Use the verified PowerShell commands in the README. On Linux, first prepare a
host directory owned by your ordinary user and let Compose use that identity:

```sh
mkdir -p runs
export DVI_UID="$(id -u)" DVI_GID="$(id -g)"
docker build -t dvi-sentinel:local .
docker compose run --rm dvi dvi doctor --json
docker compose run --rm dvi dvi run examples/foundation_scenario.yaml --out /runs/docker-proof --seed 42 --event-budget 256 --json
docker compose run --rm dvi dvi ci-check /runs/docker-proof --threshold 1 --json
```

Run these as a non-root host user. A bind mount replaces image-directory
permissions: if writing fails, make the chosen host directory writable by that
user. On Docker Desktop, the default UID was sufficient for the Windows host
mount. Do not mount the Docker socket or unrelated host directories into DVI.

The robust example detects all 31 generated variants and passes threshold 1.
Its run ID is `run:23edb6b6d7b011729fa4caa8` at the current development version.
Report HTML, Markdown, JSON and their evidence manifest persist on the host
after the container exits. A repeated run needs a new output path or explicit
`--overwrite`; unrelated or unverifiable directories cannot be replaced.

Compose is only a shortcut for those mount and confinement flags. Direct
PowerShell equivalent for the fixture run:

```powershell
$dviRunPath = (Resolve-Path runs).Path
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=128m --mount "type=bind,source=$dviRunPath,target=/runs" dvi-sentinel:local dvi run examples/foundation_scenario.yaml --out /runs/docker-direct --seed 42 --event-budget 256 --json
```

For custom local fixtures, add a read-only directory mount at `/fixtures` and
pass `/fixtures/scenario.yaml`. Fixture references remain relative to that
scenario directory and must pass the same path and synthetic-data policies as
native execution. Use `/runs/<name>` for output, not the read-only fixture mount.

## Verify and refresh

`docker compose config --quiet` validates the configuration. `dvi ci-check`
verifies the complete artifact contract before applying the declared thresholds.
For a native/container comparison, run the same scenario with identical seed and
budget, then use `dvi compare` on the two host run directories. Semantic analysis
should agree; wall-clock timestamps, recorded output arguments, optional checkout
commit and report provenance hashes may differ. A container has no `.git`
directory, so its recorded commit is explicitly unavailable.

Refresh the base-image tag and digest together after checking the official image
manifest with `docker buildx imagetools inspect python:<version>-slim-bookworm`.
Update dependencies through the normal project lock workflow, then regenerate:

```sh
uv export --locked --no-dev --no-emit-project --no-header --output-file requirements-container.txt
```

Review the exported changes and rerun the native tests, image build, doctor,
mounted fixture, artifact gate and native/container comparison. Digest pinning
requires deliberate refreshes to receive upstream fixes. This follows Docker's
[image pinning guidance](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions)
and [Compose service controls](https://docs.docker.com/reference/compose-file/services/).
