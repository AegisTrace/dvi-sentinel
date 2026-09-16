# Examples

Start with the [main quickstart](../README.md#run-a-finding) and the
[fresh-checkout proof](../docs/reproduction.md). `dvi run` produces a complete
verified bundle and reports; `benchmarks/` pairs known fragility with controls.

Inspect the CLI with `dvi --help` and `dvi --version`.
`canonical_event.json` is a validated synthetic flow event using documentation
addresses. Load it with `TelemetryEvent.model_validate_json` to inspect its UTC
timestamp and retained source timestamp. It is an event-model example, not a
scenario or generated network traffic.

The standalone Python scripts illustrate individual engine APIs. They write
documented proof files beneath `runs/` and some replace those files on repetition.
Use the CLI for controlled bundle replacement and provenance verification.

The V2 development [semantic ontology example](semantic_ontology.py) emits known and
incomplete signals with real bindings and loss findings. Run
`python examples/semantic_ontology.py --out runs/v2/ontology-proof` using a new output
directory. See [the ontology contract](../docs/semantic_ontology.md); these standalone
analysis files are distinct from a verified V1 run bundle.

The [semantic algebra example](semantic_algebra.py) evaluates a known DNS signal
against a candidate missing its required question. Run
`python examples/semantic_algebra.py --out runs/v2/algebra-proof` using a new output
directory. It writes `semantic_plan.json` and `algebra_decisions.jsonl`, preserving
unknown decisions and the observed support change from 1.0 to 0.75. See the
[algebra contract](../docs/semantic_algebra.md) for each relation and metric's limits.

The [schema profile example](schema_profiles.py) projects a synthetic flow into all
seven declared subsets and emits the profile definitions, mapping/loss evidence,
alias graph and roundtrip summary. Run
`python examples/schema_profiles.py --out runs/v2/profile-proof` with a new directory.
See [the profile contract](../docs/schema_profiles.md) for native-field references,
explicit extensions, time/severity losses and the Sigma metadata boundary.
