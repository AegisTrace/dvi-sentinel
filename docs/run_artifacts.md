# Run artifacts and integrity

`RunEvidence` assembles completed local analyses from captured input bytes,
the actual variation plan, and one harness observation per case. The builder
requires all input files to normalize successfully; rejected input is an error,
not a completed run with fabricated metrics. Unknown detector observations are
preserved as unknown matches. No detector is launched during artifact verification.

Run this executed example from the repository root:

```sh
python examples/write_run_artifacts.py
```

It writes `runs/artifact-proof/` with real count-threshold findings, assumption
probes, differential results, and a shrunk counterexample. Repeating the example
explicitly replaces a verified prior output. The [integrated CLI](cli.md) produces
the complete bundle and reports in one `dvi run` invocation.

| File | Contract |
| --- | --- |
| `run.json` | Schema/tool version, deterministic run/scenario IDs, seed, UTC start/end, invocation, complete scenario, planning metadata, configuration/input/detector/plan digests, fixture and variation fingerprints, safety attestation, optional supplied git commit |
| `score.json` | Frontier metrics with actual denominators, per-family boundaries, evidence findings |
| `variations.jsonl` | Versioned case wrappers with events, lineage, parameters, distances, invariant checks |
| `normalized_events.jsonl` | Original canonical telemetry, including raw payload/digest and adapter provenance |
| `observations.jsonl` | Actual local harness results, issues, detections and rule traces |
| `matches.jsonl` | Explained matches in variation-plan order |
| `assumption_probes.jsonl` | Versioned counterfactual evidence, possibly empty when not requested |
| `comparison.json` | Compatible baseline snapshot with every assessed case |
| `fixtures/*` | Exact captured telemetry bytes and detector-result fixture when used |
| `differential_schema_report.json` | Optional representation comparison and original/normalized source evidence |
| `minimal_case.json`, `minimal_case.md`, `shrinking_trace.jsonl`, `root_cause.json` | All four present when shrinking was used |
| `manifest.json` | Sorted portable paths, byte lengths, SHA-256 hashes, tool/run/schema identity |

JSON objects are canonical, sorted, compact UTF-8 with a trailing LF. JSONL has one
typed record per line. Original fixture bytes are retained exactly, including
their original line endings. Manifest paths are portable lowercase relative
paths; absolute, traversal, backslash, device and ambiguous paths are rejected.

The manifest omits its own hash to avoid recursion. `write_artifacts` returns its
SHA-256; save this outside the bundle and pass it to
`verify_artifacts(path, expected_manifest_digest=...)` as an integrity anchor.
Unkeyed hashes detect changes, not authorship: a coherent rewrite of a bundle
and its manifest requires an independently trusted anchor to detect. Verification
checks types, input normalization, variation invariants, observation-derived
matches, score calculations, comparison evidence, and optional analysis input
identity. It does not independently rerun detectors or certify probe/root-cause
claims; their recorded observations remain the evidence under inspection.

Identical inputs, tool version, scenario, seed and budgets produce identical
analysis bytes. `started_at` and `finished_at` are volatile; consequently
`run.json` and its manifest hash change. An explicitly different invocation or
supplied git commit also changes run provenance. The run ID excludes these fields
and is derived from the full scenario, plan and detector digests. Fixture paths
inside the scenario are configuration, so changing them changes scenario identity.

Writes are staged in a sibling directory, flushed, verified, then published by a
directory rename. Existing destinations are refused unless `overwrite=True` and
the entire prior directory verifies, including an inventory check. Unlisted files
and even empty directories prevent overwrite. For replacement, the prior directory
is renamed to a generated backup; publication errors restore it. A process crash
between these two renames can leave that backup for recovery, but does not expose
a partially written bundle. This is intended for a trusted local filesystem with
one writer; it is not a hostile concurrent-filesystem sandbox or a durability
guarantee across power loss. Symlink/junction output paths are rejected.

Limits: 128 artifacts, 32 MiB per artifact, 128 MiB total, 1 MiB manifest,
and 2 MiB per captured source fixture. The artifact writer never executes the
saved invocation or reads an arbitrary git working tree; callers may supply a
known 40-character commit ID.

## V2 artifact lineage (opt-in)

V2-15 adds an explicit schema-2 bundle extension. Existing schema-1 bundles and
CLI output remain supported; no DAG is inferred when reading legacy evidence.
Call `with_artifact_lineage(contents, declarations=...)` before `write_artifacts`
to upgrade freshly assembled run evidence. Then `write_reports` adds schema-2
reports and refreshes the DAG using the same staged, verified publication path.
The [runnable example](../examples/artifact_lineage.py) exercises all twelve
required kinds using a real run, independent oracle decisions and the existing
V1 benchmark suite:

```sh
python examples/artifact_lineage.py --out runs/v2/artifact-lineage-proof
```

The destination must be new. Timestamps are fixed synthetic fixture metadata in
this example so source and installed-wheel runs can be compared byte-for-byte.
It does not implement the planned V2-16 benchmark suite or V2-18 CLI integration.

| File | V2 contract |
| --- | --- |
| `scenario.json` | Canonical scenario copied from the verified run configuration; declared source root |
| `provenance_dag.json` | Schema-1 DAG inside a schema-2 bundle; sorted file nodes with artifact kind, content hash/size, source declaration, parent content/lineage hashes and derived lineage identity |
| `artifact_lineage.json` | Exact DAG byte hash and sorted transitive ancestor paths for every node |
| `integrity_report.json` | Recomputed bundle-context result, DAG byte hash, checked count, invalidated paths and explained issue codes |

The manifest covers these control files and every payload. The DAG covers every
payload except the manifest and its three integrity controls: including their
own hashes would create recursion. These exclusions are exact fixed names, not
caller-selected paths. Schema-2 manifests require all three controls and the
scenario capture. Schema-1 manifests reject the controls rather than silently
ignoring an extension. Keep an external final manifest pin to detect a coherent
rewrite, including a complete version downgrade.

### Parent identities and required kinds

Each node's lineage SHA-256 hashes its canonical artifact entry, kind, source flag
and ordered parent references. Each parent reference contains both its byte hash
and its lineage hash. A changed ancestor therefore changes every descendant's
lineage identity even when the descendant's payload bytes are unchanged. Nodes,
parents, ancestors, roots and diagnostics use deterministic ordering; DAGs reject
cycles, duplicate paths, unknown kinds, mismatched parent hashes and missing nodes.

The supported kinds include scenario, input fixture, normalized events, schema
projection, variation case, oracle decision, match result, score result,
counterfactual result, shrunk case, report and benchmark result. Auxiliary kinds
identify run metadata, observations, configuration and analysis. The DAG operates
at file granularity: a JSONL node binds all its records. Existing run variation
fingerprints and report file/line/pointer references retain finer case/evidence
identity; there is no claim that every JSONL record is a separate DAG vertex.

Core dependency recipes are reconstructed by the verifier. Normalized events
reference captured telemetry and scenario; variations reference normalization and
scenario; observations reference variations and detector inputs; matches reference
observations, variations and scenario. Scores bind matches, variations, probes and
optional differential evidence. Shrink outputs bind their source case/observations,
and human shrink views bind the recorded minimum. Reports bind their evidence;
HTML/Markdown bind the typed JSON report. The run metadata binds its captured
configuration, fixtures, normalization and variation plan without creating a cycle.

Additional artifact producers must supply `LineageSpec` declarations. A declaration
names a portable local path, kind, source flag and sorted parent paths. Only
scenario, input-fixture and configuration kinds may be declared source roots;
derived nodes require parents at publication. Unknown extras are never guessed
from their filenames. The supplied bytes must exactly cover the declarations.
For optional producer artifacts the declared relationship is integrity metadata,
not an independent proof that their algorithms were executed correctly. The
example captures every input listed by the actual benchmark results and checks
its hash; benchmark/oracle parents are explicit producer declarations.

### Integrity decisions and confinement

`verify_lineage(dag, contents, context="inspection")` is a pure inspection API over
bounded in-memory bytes. An unreferenced source or parentless derived artifact is
an `orphan` warning. Bundle context treats an orphan as an error and propagates
failure to descendants. Missing/changed bytes and untracked artifacts are always
errors. Every descendant of an invalid parent is marked `parent_invalid`, even
when its own bytes still match. The inspection mode is never used by publication,
report consumption or bundle verification.

`verify_artifacts` checks lineage even when file hashes already failed, returning
transitive diagnostics. It recomputes both materialized views, verifies the fixed
run dependency recipes and scenario capture, and checks report summaries and
rendered views. Core V1 semantic/score verification still runs on intact evidence;
no detector is executed by verification. The on-disk integrity report is evidence
of the last verified publication, not a live status file. Later tampering is reported
by the verifier without overwriting that evidence.

DAG paths never initiate reads. The store reads only validated manifest entries
under its validated local output root, using the existing byte limits. It rejects
links/junctions in path components, checks inventory, and bounds the actual captured
bytes as well as declared sizes. All control files count against 128 artifacts,
32 MiB per file and 128 MiB total; the manifest remains limited to 1 MiB.
Pure DAG inputs allow at most 128 nodes and 128 parents per node. Verification can
report up to 256 invalidated paths when two bounded inventories are disjoint.

Hashes establish consistency, not authorship. A fully recomputed rewrite requires
an independent manifest pin to detect. This remains a trusted local filesystem,
single-writer contract, not protection against hostile concurrent path replacement.
See [V2 report provenance](report_v2.md) for the noncircular report summary.
