# Roadmap

V1 implements the local fixture workflow documented in the README. Its evidence
is recorded in [release verification](release_v1.md). The items below are research
directions, not supported features or delivery commitments.

## V1.5 candidates

| Direction | Evidence needed before adoption |
| --- | --- |
| Adaptive/greybox semantic search and broader coverage | A bounded local benchmark showing useful findings beyond the fixed catalog while preserving independently checked semantics and repeatability. |
| Statistical confidence and drift memory | A defensible sampling model, recorded history/identity and explicit limits on uncertainty claims. |
| Richer evidence relationships | A real reader/query need that existing provenance references cannot express; avoid adding a graph just to export one. |
| JUnit/SARIF output | A tested consumer use case, faithful mapping of unknowns and local evidence references, and no implied code vulnerability finding where only fixture fragility was measured. |

## V2 candidates

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
