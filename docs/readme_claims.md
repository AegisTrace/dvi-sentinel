# README claims and executable evidence

The README distinguishes V1 history, implemented V2 behavior and future work. This
index records the evidence behind its claims; future behavior belongs in the
[roadmap](roadmap.md). The original V2-20 measurements below are retained as dated
evidence; version 2.0.0 verification is in the [release record](release_v2.md).

## Measured examples

| Claim | Executable source | Observed result and scope |
| --- | --- | --- |
| Quickstart control passes | [V2 CI scenario](../examples/v2/ci/scenario.yaml), [proof verifier tests](../tests/test_ci_proof.py) | Seed 42 and event budget 256: seven detected planned variants, no misses/unknowns/invalids; threshold 1 and max-unknown 0 pass. Baseline excluded from counts. |
| Correlation metadata can be a brittle dependency | [Fragile rule](../benchmarks/correlation_key-fragile.yaml), [control](../benchmarks/correlation_key-control.yaml), [expert tests](../tests/test_v2_benchmarks.py) | Both baselines detect. Fragile/control planned-variant detection is 0/1 versus 1/1. The fragile case records correlation-key and optional-field findings. The local minimum retains two events, removes one key, and adds no events, shift or inversion. |
| Expert suite has 32 cases across 16 categories | [Suite declarations](../benchmarks/v2/suite.json), [benchmark tests](../tests/test_v2_benchmarks.py) | Direct full-suite CLI execution passed all 224 expected/observed checks. Diagnostic unknowns and invalid evidence are accepted only where explicitly expected; this is not a deployment gate. |
| Preview comes from an actual advanced report | [Report example](../examples/advanced_report.py), [report tests](../tests/test_v2_reports.py) | Verified schema-3 report: two detected and nine missed variants; oracle consensus lacks evidence, shrinking is unknown, confidence is insufficient sample. [Capture and hashes](example_report.md#capture-and-provenance). |
| Recorded quality results | [V2-19 record](v2_build_log.md#v2-19---cicd-and-release-hardening), [exact final CI](https://github.com/AegisTrace/dvi-sentinel/actions/runs/37587040180) | 1,248 tests per supported Python version, 94.90% combined coverage; both Python jobs and restricted container passed. These figures identify that verified state. |

The full benchmark report produced during this review has SHA-256
`9c51c7663be56d3a249d48ed98f2f76ef025107e4caf3b4160b775bcf75dc05d`, matching the
V2-19 source, wheel, container and hosted CI evidence. Benchmark acceptance is
derived from independent declared expectations after actual engine execution.

## Implemented feature groups

| README feature | Runnable example | Behavioral tests / contract |
| --- | --- | --- |
| Ontology and evidence bindings | [Semantic ontology](../examples/semantic_ontology.py) | [Ontology tests](../tests/test_v2_ontology.py) |
| Seven semantic relations | [Semantic algebra](../examples/semantic_algebra.py) | [Algebra tests](../tests/test_v2_semantic_algebra.py) |
| Seven documented schema subsets | [Schema profiles](../examples/schema_profiles.py) | [Mapping tests](../tests/test_v2_mapping.py); no full standard compliance claim |
| Bounded rule intent | [Detection intent](../examples/detection_intent.py) | [Intent tests](../tests/test_v2_intent.py); no complete Sigma compiler |
| Ten temporal predicates | [Temporal/correlation](../examples/temporal_correlation.py) | [Temporal tests](../tests/test_v2_temporal.py) |
| Nine evidence oracles | [Oracle consensus](../examples/oracle_consensus.py) | [Oracle tests](../tests/test_v2_oracles.py); disagreement and unknowns remain visible |
| Bounded constraint exploration | [Exploration](../examples/constraint_exploration.py) | [Constraint tests](../tests/test_v2_constraints.py) |
| Semantic coverage | [Coverage](../examples/semantic_coverage.py) | [Coverage tests](../tests/test_v2_coverage.py) |
| Cross-representation analysis | [Representation controls](../examples/cross_representation.py) | [Comparison tests](../tests/test_v2_cross_representation.py) |
| Local counterfactuals | [Counterfactual controls](../examples/counterfactuals.py) | [Counterfactual tests](../tests/test_v2_counterfactuals.py); conditional effects only |
| Oracle-aware shrinking | [Four controls](../examples/oracle_shrinking.py) | [Shrinking contract](failure_shrinking.md); finite reductions stop on unresolved evidence |
| Conditional statistics | [Confidence](../examples/statistical_confidence.py) | [Confidence tests](../tests/test_v2_confidence.py) |
| Compatible regression history | [Regression memory](../examples/regression_memory.py) | [History tests](../tests/test_v2_regression_memory.py) |
| Evidence-linked knowledge graph | [Graph](../examples/knowledge_graph.py) | [Graph tests](../tests/test_v2_graph.py); remedies remain untested |
| Provenance DAG | [Artifact lineage](../examples/artifact_lineage.py) | [Artifact contract](run_artifacts.md#v2-artifact-lineage-opt-in); hashes do not authenticate origin |
| Eighteen-section advanced report | [Advanced report](../examples/advanced_report.py) | [Report tests](../tests/test_v2_reports.py) |
| Ten V2 analysis commands | [All-command example](../examples/v2_cli.py) | [CLI tests](../tests/test_v2_cli.py); explicit stages, not automatic run orchestration |
| Installed-package and offline-container gate | [Retained-proof verifier](../examples/verify_ci_proof.py) | [CI workflow](../.github/workflows/ci.yml), [verifier tests](../tests/test_ci_proof.py) |

The fixed fixture-only boundary is defined by the [safety model](safety_model.md)
and [security policy](../SECURITY.md). The [development standard](development_standard.md)
requires evidence before marking a card complete. V2 release status remains planned
until the final [release gate](v2_architecture.md#artifacts-presentation-and-release).
