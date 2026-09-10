# Reports and direct provenance

Reports consume a verified run bundle. They do not invoke detectors, change
observations, or execute recorded reproduction arguments. `build_reports(path)`
returns deterministic bytes; `write_reports(path)` adds them through the artifact
store's verified staged replacement. Existing reports require `overwrite=True`.
The final manifest covers both the original evidence and generated reports.

From the repository root:

```sh
python examples/write_run_artifacts.py
python examples/render_report.py
```

Open `runs/artifact-proof/report.html` locally. It embeds its CSS and needs no
server, JavaScript, fonts, images, CDN or internet connection. Semantic headings,
table captions/column headers, focusable scrolling regions, keyboard navigation,
responsive layout and a print stylesheet support inspection. HTML values are
autoescaped; Markdown text escapes markup, links, tables and raw HTML.

The outputs are:

- `report.json`: typed scenario/run metadata, full frontier, cases/matches,
  probes, optional schema/minimal/regression results, provenance and limitations.
- `report.md`: human summary with measured denominators, case reason codes and
  local artifact links.
- `report.html`: the same human sections in a restrained local document.
- `provenance.json`: source artifact hashes, normalized event IDs and record/raw
  digests, and direct references for each classified finding.

Both human formats include scenario and safety, fixture/input digests, all
frontier metrics, family boundaries, classified findings, case outcomes,
counterfactual hypotheses/results, schema disagreements, optional shrinking and
ablation evidence, optional regression, reproduction arguments, and limitations.
Missing optional analyses are labeled as not requested/measured. An unknown
observation never becomes a measured pass or miss. Raw candidate-level comparisons
remain inspectable in the linked machine artifacts.

Pass `previous=Path(...)` to supply a verified baseline bundle. The report calls
the existing compatibility-aware comparator, preserving incompatible/unknown
results rather than inventing deltas. It captures `regression_baseline.json`,
`regression_thresholds.json`, and `regression.json` for reproducible rerendering.
Optional `ComparisonThresholds` are saved, including non-default limits. A later
render uses those captured inputs without depending on the old directory.

Provenance references use portable relative artifact paths and the artifact's
SHA-256. A JSONL reference additionally gives a one-based `line`; `pointer` is a
JSON Pointer within that selected record. A JSON reference uses a pointer within
the file. Empty pointers reference the whole selected value/file. Each finding
links to its scenario/configuration and score record, relevant original event
IDs, captured fixtures, and the measured variation/match, probe counterfactual,
or schema case. Event provenance indexes record and raw digests once rather than
duplicating full event payloads per finding.

The provenance `evidence_digest` hashes its sorted source inventory, excluding
the four report outputs and the manifest to avoid recursive hashes. When present,
captured regression inputs/results are part of that inventory. Adding reports
therefore leaves source evidence hashes unchanged, and rerendering the same
bundle with the same thresholds is byte-identical. Changed run timestamps still
change the run metadata hash and hence report provenance.

Recorded commands are JSON argument arrays for unambiguous cross-platform
inspection, not shell strings or clickable actions. Reproduction assumes the
original checkout or a reconstruction using the captured fixture mapping and
complete configuration. Integrity does not establish authorship or universal
causality. JUnit, SARIF and knowledge graphs remain outside V1.
