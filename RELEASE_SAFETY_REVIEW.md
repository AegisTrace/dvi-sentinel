# Release safety review

Reviewed 2026-09-14 against `8d10c6667bcb62c74e48cfa230383f68082b4c6c`
(development candidate `0.1.0.dev0`). Scope: all 148 tracked files, with control-flow
review of input/output boundaries and runtime capabilities, plus examples, test
fixtures, comments, CLI help, report templates, Docker/CI and roadmap statements.

**Safety conclusion:** no prohibited capability or unresolved unsafe behavior was
identified within the declared V1 boundary. DVI Sentinel is a defensive,
fixture-based resilience harness. It evaluates synthetic local telemetry and
local detector models. The project owner confirmed Phase 13 visual readability
on 2026-09-14. Final version and packaging checks are recorded in
[release verification](docs/release_v1.md).

## Checks and evidence

| Area | Review and observed result |
| --- | --- |
| Execution and network capabilities | AST import/call inspection of 50 runtime modules and seven example scripts found no subprocess, network-client, socket, dynamic-code, unsafe-deserialization or native-code execution entrypoint. Manual review confirmed that `urllib.parse` only parses strings and `importlib` only reads package metadata/resources. The only socket import in 19 test modules installs the network-denial fixture. |
| Prohibited behavior | No exploit execution/generation, attack-payload or traffic generation, credential collection/testing, malware, persistence, privilege escalation, stealth, scanning, destructive target actions or live detector integration was found. The negative tests contain inert rejected keys and values, not executable attack examples. Deliberately fragile rules model local assumptions; they do not provide production bypass recipes. |
| Scenario boundary | Strict YAML/Pydantic allowlists, required true safety attestations, no executable expressions/templates/plugins, and only three local fixture formats/two local harness kinds. Unknown capabilities return explicit policy/harness errors. Structural rejection IDs `DVI-POL-004` through `008` supplement the allowlist; they are not the sole execution boundary. |
| File and content boundaries | Portable relative fixture paths, traversal/device/stream/UNC/symlink restrictions, root containment, regular-file and byte limits. YAML aliases, anchors, duplicate keys, invalid types and excessive nesting are rejected. Known network fields and URL-shaped values are checked against documentation space without DNS. See [policy details](docs/safety_model.md). |
| Transformations and observations | Read preflight and post-transformation calls in adapters, harnesses, variations, independent invariants, probes and reductions. Normalized fields and retained raw snapshots are checked. Rejected or invalid evidence cannot establish a safe measured miss. Missing detector fixtures and unsupported capabilities remain unknown. |
| Fixture immutability | Prepared all 22 shipped scenarios through strict parsing, normalization and policy. Before/after SHA-256 inventories matched for all 40 example/benchmark files. Runtime reads capture source bytes; generated events and outputs are separate values/files. |
| Output ownership | Reviewed staged writes, explicit CLI overwrite, complete prior-inventory verification, extra-file refusal, backup rollback, safe portable artifact paths and symlink/junction output rejection. Recursive cleanup is limited to generated stage/backup directories beside the checked output; it is not a scenario capability. Tests cover refusal and failed-publication recovery. |
| Reports and CLI | Inspected CLI help/options and report construction. Run commands are stored as inert argument arrays. HTML is autoescaped with strict template variables, embedded CSS, local evidence links, no script/remote assets and restrictive CSP. Markdown escaping and provenance pointers have executable tests. No rendered screenshot is claimed. |
| Secrets and dependencies | No required runtime secrets or credential store. Targeted private-key/AWS-access-key/GitHub-token pattern search found no matches in tracked working content. This is a limited pattern check, not a guarantee that arbitrary text contains no sensitive information. Runtime dependencies remain the approved five libraries; lock/container requirements use explicit package versions and hashes. |
| Docker and CI | Reviewed non-root UID/GID 10001, no exposed service/port, allowlisted build context, disabled runtime network, read-only root and dropped capabilities in Compose/reproduction commands. CI uses pinned official actions, read-only permissions and checkout without retained credentials; no repository secrets or privileged pull-request execution. Dependency installation/build are separate network-enabled maintenance steps. Actionlint passed. |
| Scope and wording | Reviewed source/fixture descriptions and current documentation. Claims are limited to declared synthetic observations, supported schema subsets and bounded search. Zeek, Z3, SARIF, supply-chain attestations, analytics engines and adaptive discovery remain research/roadmap only. No external-framework certification or production detection coverage is claimed. |

The code review was supported by `rg` searches for execution/network imports,
dynamic evaluation, file mutation, privilege/service configuration, credentials
and unfinished critical paths, then inspection of each relevant match. AST checks
were read-only audit commands, not a new runtime feature or a claim of formal
verification. The empty `ArtifactError` class is a concrete exception type;
the harness `Protocol` has two real implementations, not placeholder behavior.

## Executed verification

The audited runtime is unchanged from the [fresh-checkout proof](docs/reproduction.md):
418 tests passed, with one Windows symlink-creation privilege skip, and 95%
combined coverage. The real symlink test executes in Linux CI. The full suite
runs with Python socket/DNS operations denied. Both Python 3.12 and 3.13 CI jobs
passed at the audited commit, including lint/format/types, tests, packaging,
installed-wheel CLI execution and benchmarks:
[CI run 34801564878](https://github.com/AegisTrace/dvi-sentinel/actions/runs/34801564878).

Native and Docker execution passed all 20 benchmarks/275 checks, with ten robust
controls producing no findings. Robust/fragile gates returned 0/1; a compatible
detector change produced nine new misses and comparison exit 1. The host verified
container manifests; eight analysis files per run and the complete benchmark
report matched native bytes. Original fixture hashes and the clean checkout's
tracked files remained unchanged. This evidence supports the stated local
contracts, not an assertion that every possible input has been examined.

## Findings and remediation

No runtime remediation was required by this review. Existing constraints and
negative tests explicitly cover the reviewed execution and input boundaries.
The earlier Unicode JSONL record-boundary defect is fixed and has permanent
regressions; it did not introduce an execution capability. Historical phased
documentation still needs final presentation cleanup in Phase 22, which must
retain the same safety claims and be reviewed before release.

Phase 22 addendum (2026-09-14): reviewed the new README, architecture/ADRs,
roadmap, security/contribution/conduct policies and changelog. They retain the
fixture boundary and explicit nonclaims. Stale future-phase descriptions were
corrected; the sole Python change is a module docstring correction. Packaging
adds author/classifier/project-link metadata without a dependency or executable
behavior change. GitHub private vulnerability reporting was enabled and verified.
`AGENTS.md` remains deleted and is now ignored. No new safety issue was identified.

Legacy standalone example scripts write only their documented proof files under
`runs/` and may replace those proof files on repetition. They do not modify input
fixtures and do not offer the full bundle writer's ownership guarantees. Use the
documented CLI for manifest-backed runs and controlled replacement. The benchmark
script refuses an existing output file.

## Residual limits

- Synthetic/documentation provenance is an explicit declaration, not an automated
  classifier of arbitrary malicious content. Unknown vendor fields or encoded
  text are not certified harmless; no accepted string is executed.
- Filesystem roots must be trusted and local. Mounted remote drives, concurrent
  filesystem replacement, hostile Python callers using unchecked construction,
  OS compromise and power-loss durability are outside the application boundary.
- A Python socket guard is test instrumentation, not an OS sandbox. Docker's
  network restriction applies only when the documented runtime flags are used.
- Unkeyed hashes prove consistency against a trusted external digest, not
  authorship. Verification uses recorded observations rather than independently
  rerunning detectors. Findings/minima apply only to tested fixture relations.
- This review addresses the requested capability/safety boundary. It is not a
  penetration test, dependency CVE assessment, third-party certification or
  guarantee of production detector resilience.
- HTML integrity, escaping and links passed tests. Visual readability was
  separately confirmed by the project owner on 2026-09-14; this review does not
  claim an automated browser inspection or accessibility certification.
