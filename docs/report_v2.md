# V2 report provenance

V2-15 extends the existing report renderer with a provenance summary for schema-2
artifact bundles. The complete V2-17 report layout and combined V2-18 command flow
remain planned. [V1 reports](reports.md) retain their existing sections and legacy
schema-1 support. [Artifact lineage](run_artifacts.md#v2-artifact-lineage-opt-in)
defines the DAG, bounded local reads and integrity decisions.

`build_reports` first verifies the input bundle. For a schema-2 bundle it emits a
schema-2 `ReportDocument` containing a typed `lineage` field with:

- `dag_artifact`: the fixed local name `provenance_dag.json`;
- `evidence_sha256`: the exact canonical evidence-DAG byte hash, including final LF;
- `artifacts`, `parent_links`, and sorted declared `roots`;
- the explicit scope `evidence_excluding_reports_and_integrity_controls`.

Markdown and self-contained HTML show the artifact path, digest, counts and scope
in an **Artifact lineage and integrity** section. The renderer retains existing
escaping, requires no remote assets or scripts, and never executes saved commands.
A legacy report has no lineage summary; a schema-2 report requires one.

## Avoiding circular hashes

The evidence digest covers the DAG projected without `report.json`, `report.md`,
`report.html`, `provenance.json` and `regression.json`. The full DAG already excludes
its three integrity controls and the manifest. A baseline snapshot and thresholds
remain evidence and are included when regression is requested. Additional producer
evidence must not depend on a presentation file, since that would break the
independent evidence projection.

The report references this evidence digest and the full DAG's filename. The final
DAG then includes the report files and their parent hashes. The final manifest
hashes everything, including that DAG and its two materialized views. No report
claims to contain the full hash of a DAG that includes its own bytes.

`write_reports` preserves the explicit declarations of additional producer
artifacts, rebuilds fixed report dependencies, regenerates the controls and
publishes through the existing atomic bundle writer. Repeating it with explicit
overwrite yields identical bytes for identical inputs. A changed baseline is
captured before the evidence digest is calculated. The verifier checks the
summary against the DAG and renders JSON back to Markdown/HTML to detect divergent
views even if a caller recomputes file hashes.

To upgrade an existing legacy bundle, first verify it, assemble its evidence
without the old presentation files, add lineage, and regenerate reports. For a
legacy regression report, also omit the old `regression_baseline.json` and
`regression_thresholds.json` during this initial upgrade, then supply the original
verified baseline bundle and thresholds to `write_reports`. Unused source roots
are rejected; this API does not automatically migrate an archived baseline when
its original bundle is unavailable. Adding lineage around a schema-1 report is rejected; it must not imply that an old report
already contained a verified summary.

## Limits and interpretation

The summary counts files and declared parent links, not independent scientific
evidence or confidence. It makes no claim about authorship, production detection,
or detector replay. Core run dependencies are rederived; extra producer lineage
is an explicit declaration. Keep the final manifest digest independently to
protect against a coherent rewrite. A saved integrity report describes publication;
run `verify_artifacts` to inspect the current bytes.

The [lineage example](../examples/artifact_lineage.py) creates real synthetic run,
oracle and V1 benchmark evidence and exercises report generation. Tests in
[artifact integration](../tests/test_artifacts.py) and
[graph contracts](../tests/test_v2_graph.py) cover parent tampering, missing parents,
version migration, external pins, deterministic identities, bounded reads and
report regeneration.
