# V2 development standard

V2 extends the tested V1 engine one card at a time, in the order recorded in
[V2 architecture](v2_architecture.md). The approved blueprint defines the technical
requirements within the fixed safety boundary. Scope targets count as complete
only when supported by implementation and verification evidence.

All updates are committed and published directly on `main`, the repository's only
branch. Do not create additional development branches. Preserve release tags as
the versioned record of published behavior.

## One-card engineering loop

1. Read the current card and restate its purpose in one sentence.
2. Record observable acceptance criteria before implementation. Inspect the V1
   contracts and name the exact files and compatibility boundaries affected.
3. Design the smallest complete extension. Reuse existing parsers, values,
   invariants, harnesses and artifact consumers before introducing another layer.
4. Implement measured behavior. Add strict typed models where the contract needs
   them; avoid untyped result dictionaries and duplicate parallel abstractions.
5. Add meaningful unit/property/negative tests. For user-visible behavior, execute
   at least one integration or CLI/example path using real local engine behavior.
6. Update docs and runnable synthetic examples. Generate relevant artifacts from
   those executions and verify contents, provenance and deterministic serialization.
7. Run targeted tests and the applicable lint/format/type checks. Fix failures,
   preserve real regression cases, then run the broader suite and package proof.
8. Review actual imports/calls and data flow against the fixed safety boundary.
   Name each module's allowed category and any residual limitations.
9. Commit one coherent conventional-commit unit, push and verify both supported
   Python CI jobs for that exact commit. Do not start the next card before green CI.
10. Write the completion record, including actual commands, outcomes, commit and
    CI reference. A command attempt or queued preview is not completion evidence.

Do not create future files, placeholder commands or interfaces just to mirror the
blueprint's target tree. A tiny unavoidable prerequisite change must be explained
and tested within the current card; it does not complete the future card. Later
cards may wire new evidence into an already tested contract without prebuilding it.

## Definition of done

A behavioral card needs working code, meaningful tests, docs, an executable example,
relevant artifact/CLI proof, deterministic outcomes, a safety review and explicit
limitations. Its claim must agree with the code and have a commit, successful push
and green CI. Documentation-only V2-00 does not need invented runtime tests or an
artificial example; it still requires link/claim checks and its stated proof commands.

No placeholder class, empty adapter, critical TODO, import-only test, object-creation
assertion masquerading as behavioral proof, swallowed error or fake report satisfies
the gate. A small Protocol stub is acceptable only as an exercised type boundary
with real implementations. Every production function has a test or executed consumer.

Each README feature must link to implemented documentation, a test, a command,
an example or a generated artifact. Planned and experimental behavior stays labeled.
No claims of complete schema/Sigma compliance, universal causal findings, guaranteed
resilience or production effectiveness follow from local fixture results.

## Safety review for every card

Allowed runtime categories are pure data model, bounded local fixture reader,
bounded local artifact writer, pure analyzer and CLI wrapper. Their precise limits
are defined in [V2 architecture](v2_architecture.md#fixed-boundary-and-vocabulary).
Name the categories used and inspect actual capability changes, not just docstrings.

Readers and writers retain validated local roots and finite size/count limits.
Scenarios, profiles and detector metadata never supply executable commands, queries,
plugins or network destinations. No live scanning, exploitation, payload generation,
credentials, malware, stealth, persistence, attack traffic, destructive target
actions, external detector service or bypass recipe is permitted. Tests must work
offline after dependencies are installed; never weaken a guard to make a test pass.

Safety/provenance failures block consumption. Missing evidence stays unknown and
cannot silently become equivalent, detected or a passing release gate. Optional
absence and an expected negative benchmark are distinct from missing required proof.

## Verification and reproducibility

Use the existing Python 3.12/3.13 stack, strict mypy and at least 90% combined
statement/branch coverage. Standard checks from an installed development environment:

```sh
ruff check .
ruff format --check .
mypy src/dvi_sentinel
python -m pytest
python -m build
```

Behavioral cards also use `python -m coverage run -m pytest` and
`python -m coverage report --fail-under=90` when validating the coverage gate.
Use targeted tests during development; rerun broader checks after meaningful changes
or failures, not to inflate an evidence list. Preserve seeds and failing fixtures.
Every bug fix adds a behavioral regression test.

Golden outputs and expected benchmark results are independent oracles. Do not update
an expected result merely to accept what the engine currently emits. Check semantics,
denominators, unknowns, bounded search, tampered artifacts and robust controls.
Known mathematical values and primary documentation support numeric/profile tests.
Timing measurements are observations, not universal performance or confidence claims.

Existing V1 tests, public commands and artifact handling remain regression constraints.
A changed contract needs versioning/migration tests and a documented reason. Add a
dependency only for a demonstrated, tested use case; optional libraries cannot be
required to run the core. No runtime LLM, cloud, SIEM/EDR or browser automation dependency.

## Required completion record

Use these fields for each card; say not applicable with a reason when appropriate:

```text
Card:
Purpose:
Acceptance criteria:
Files changed:
Behavior implemented:
Tests added:
Docs/examples updated:
Artifacts generated:
Commands run:
Results:
Safety review:
Known limitations:
Commit:
CI status:
Next card:
```

The [card evidence record](v2_build_log.md) preserves implementation decisions and
proof. Full local command/output records may live under ignored `runs/v2/`; never
commit environments, personal telemetry, secrets, generated run bundles or private configuration.
Preserve the V1 release tag and real history. Release V2 only after the final gate,
including a genuine rendered report inspection, passes on the release commit.
