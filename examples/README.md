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

The [detection intent example](detection_intent.py) parses a native declaration,
analyzes one matching and one incomplete DNS event, and writes four deterministic
intent/loss artifacts beneath a new directory. Run
`python examples/detection_intent.py --out runs/v2/intent-proof` and read the
[intent contract](../docs/detection_intent.md) for supported operators, unknowns,
metadata scope and pending sequence limits.

The [temporal correlation example](temporal_correlation.py) evaluates a shuffled
flow and validated alert using UTC ordering, a finite window, shared entity and
correlation evidence, and a declared sequence. Run
`python examples/temporal_correlation.py --out runs/v2/temporal-proof` and read the
[temporal contract](../docs/temporal_correlation.md) for predicate semantics,
precision warnings and bounded artifacts.

The [oracle consensus example](oracle_consensus.py) runs a delayed local harness
alert and a timely control through nine evidence checks. Run
`python examples/oracle_consensus.py --out runs/v2/oracle-proof` for four artifacts
per case. The [oracle contract](../docs/oracle_consensus.md) explains integrity
gates, diagnostic disagreement and the finite meaning of confidence.

The [constraint exploration example](constraint_exploration.py) covers feasible
pairs across four transformation dimensions and runs the selected cases against
robust and sensor-dependent local rules. Run
`python examples/constraint_exploration.py --out runs/v2/exploration-proof` for
four artifacts with coverage, constraints, skips, trace hashes and case evidence.
The [exploration contract](../docs/constraint_exploration.md) defines bounds,
coverage denominators and the scope of the existing transformation catalog.

The [semantic coverage example](semantic_coverage.py) measures twelve discovery
dimensions for timely, late and duplicate observations. Run
`python examples/semantic_coverage.py --out runs/v2/coverage-proof` for the real
coverage, growth, queue and retention artifacts. The
[coverage contract](../docs/semantic_coverage.md) explains novelty, unknowns and
the scope of its evidence-resolution gate.

The [cross-representation example](cross_representation.py) executes eight existing
fixture/profile paths and compares all 64 pairs for a synthetic event. Run
`python examples/cross_representation.py --out runs/v2/representation-proof` for
four artifacts with actual field/meaning differences, context loss and unknowns.
The [comparison contract](../docs/cross_representation_testing.md) explains the
distinction between pairwise agreement, source fidelity and unsupported evidence.

The [counterfactual example](counterfactuals.py) executes single-change, combined-change
and robust local controls. Run
`python examples/counterfactuals.py --out runs/v2/counterfactual-proof` for four
artifacts per control. The [counterfactual contract](../docs/counterfactual_causality.md)
explains proper-subset minimality, descriptive paired effects, conditional language
and explicit execution budgets.
