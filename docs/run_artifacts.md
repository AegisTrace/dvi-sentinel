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
