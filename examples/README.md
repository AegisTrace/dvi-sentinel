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
