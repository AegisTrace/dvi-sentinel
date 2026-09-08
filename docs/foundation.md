# Repository foundation

Phase 0 establishes packaging, a help/version CLI, quality tooling, a two-version
CI matrix, and a minimal non-root container. There is no detection engine yet.

The package lives in `src/dvi_sentinel`; `dvi` and
`python -m dvi_sentinel.cli.main` invoke the same Typer application. Unknown
commands exit 2; help, no arguments, and version exit 0. The version is explicit
and tested against installed package metadata. No telemetry files are opened.

Runtime dependencies follow the frozen V1 stack. Development uses an explicit
`dev` extra, preserving standard pip installation. The uv lock records concrete
versions. CI uses stable major versions of official GitHub actions, read-only
repository permissions, and no secrets; later CI hardening belongs to Phase 15.

Run the README proof commands in an installed development environment. Tests
assert output and errors, not just successful imports. Container smoke commands:

```sh
docker build -t dvi-sentinel:foundation .
docker run --rm --network none dvi-sentinel:foundation dvi --version
docker compose run --rm dvi
```

The container exposes no ports or services. Full scenario mounts and artifact
reproduction belong to Phase 16. The foundation does not enforce a scenario
policy because it does not yet accept scenarios; that contract belongs to Phase 2.
