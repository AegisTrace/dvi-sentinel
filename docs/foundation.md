# Repository foundation

Phase 0 established packaging, a help/version CLI, quality tooling, a two-version
CI matrix, and a minimal non-root container. This page records that initial scope;
the current engines and commands are linked from the README.

The package lives in `src/dvi_sentinel`; `dvi` and
`python -m dvi_sentinel.cli.main` invoke the same Typer application. Unknown
commands exit 2; help, no arguments, and version exit 0. The version is explicit
and tested against installed package metadata. Help and version open no telemetry.

Runtime dependencies follow the frozen V1 stack. Development uses an explicit
`dev` extra, preserving standard pip installation. The uv lock records concrete
versions. CI now uses full commit pins for official GitHub actions, read-only
repository permissions, and no secrets; see [the completed CI gate](ci.md).

Run the README proof commands in an installed development environment. Tests
assert output and errors, not just successful imports. Container smoke commands:

```sh
docker build -t dvi-sentinel:foundation .
docker run --rm --network none dvi-sentinel:foundation dvi --version
docker compose run --rm dvi
```

The container exposes no ports or services. Full scenario mounts and artifact
reproduction are now documented in [Docker reproduction](docker.md). Scenario
validation and policy enforcement are documented in [the safety model](safety_model.md).
