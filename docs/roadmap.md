# Roadmap

V1 implements the released local fixture workflow documented in the README, with
evidence in [release verification](release_v1.md). The owner supplied a new V2
blueprint on 2026-09-15. Its [architecture contract](v2_architecture.md) now defines
the active development sequence; the earlier V1.5/V2 labels below are historical
research groupings, not separate promised releases.

V2 is in development. The [semantic ontology library](semantic_ontology.md) has
working extraction, binding, loss and export behavior. The [semantic algebra](semantic_algebra.md)
evaluates seven bounded relations with explicit unknowns and evidence-support traces.
The [schema profile library](schema_profiles.md) adds seven explicit local subsets
with field/loss reports and measured roundtrips. The [detection intent parser](detection_intent.md)
adds bounded native/Sigma-subset/V1 metadata parsing and event evidence loss reports.
The [temporal and correlation engine](temporal_correlation.md) adds ten bounded
predicates with stable UTC ordering and explicit missing-evidence/precision unknowns.
Oracles,
oracles, constrained exploration, coverage, counterfactuals, uncertainty, graphs
and report integration must each earn an implemented claim through their card's
tests and proof. The items below remain unsupported until explicitly delivered.

## Earlier V1.5 research group

| Direction | Evidence needed before adoption |
| --- | --- |
| Adaptive/greybox semantic search and broader coverage | A bounded local benchmark showing useful findings beyond the fixed catalog while preserving independently checked semantics and repeatability. |
| Statistical confidence and drift memory | A defensible sampling model, recorded history/identity and explicit limits on uncertainty claims. |
| Richer evidence relationships | A real reader/query need that existing provenance references cannot express; avoid adding a graph just to export one. |
| JUnit/SARIF output | A tested consumer use case, faithful mapping of unknowns and local evidence references, and no implied code vulnerability finding where only fixture fragility was measured. |

## Further candidates and explicit nonclaims

| Direction | Evidence needed before adoption |
| --- | --- |
| Z3 constraints | A concrete bounded constraint problem that simpler generation cannot solve, with explainable solver results and resource limits. |
| Full OCSF/ECS exports and full Zeek support | Versioned mappings, loss reporting and a fixture conformance suite for the claimed subset/version. No live collection is implied. |
| GraphML and DuckDB/Polars analytics | A measured artifact-volume/query bottleneck and reproducible performance evidence that justifies the dependencies. |
| CycloneDX, SLSA, Sigstore and OpenSSF release tooling | A defined supply-chain threat model, maintained build/release identities and verifiable outputs. Current SHA-256 manifests are not signed attestations or an SBOM. |

The fixture-only defensive boundary remains fixed: no live scanning, exploitation,
payloads, credentials, stealth, persistence, scenario shell hooks or bypass recipes.
New capabilities require their own tests, safety review, documentation and scoped
implementation. V1 contains no placeholder implementations for these items.

The current V2 blueprint calls for OCSF-like, ECS-like, OpenTelemetry-like,
Zeek-like and Sigma-metadata projections with explicit loss reporting. It does
not authorize full standard-compliance claims, production integrations or a full
Sigma compiler. Z3, NetworkX and analytics dependencies need a demonstrated use
case; they are not required merely because they appear in this roadmap.
