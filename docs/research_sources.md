# Research sources and implementation boundaries

These primary sources explain DVI's design influences. They are references, not
runtime integrations or certifications. Sources were checked on 2026-09-14;
versioned Suricata documentation is pinned below. No upstream schema, rule corpus
or paper is redistributed here. The implementation links identify the narrower
contracts that can actually be inspected and tested.

## Event and detection vocabulary

| Influence and borrowed idea | What DVI implements | What DVI does not claim |
| --- | --- | --- |
| [OCSF schema](https://github.com/ocsf/ocsf-schema): separate event categories, typed attributes and reusable objects from vendor spelling. | DVI-native `EventSemantics`, `NetworkEndpoint`, `TelemetryEvent` and `DetectionEvent`, with four local categories and retained raw evidence; see [event model](event_model.md). | OCSF class IDs, profiles, schema validation, import/export or conformance. DVI's categories and severity numbers are its own. |
| [ECS source fields](https://www.elastic.co/docs/reference/ecs/ecs-source): give network endpoints explicit structure. | Typed source/destination IP addresses and ports; adapters map supported aliases to these values. | ECS field-set coverage, Elasticsearch integration, ECS export or lossless ingestion of arbitrary ECS documents. |
| [OpenTelemetry logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/): distinguish occurrence time, observation time and source representation. | Required UTC `timestamp`, optional `observed_at`, and original timestamp text in `RawSource`. | OTLP, collectors, trace-context propagation or nanosecond fidelity. DVI accepts at most microsecond precision and uses a separate severity scale. |
| [Suricata 8.0.4 EVE JSON format](https://docs.suricata.io/en/suricata-8.0.4/output/eve/eve-json-format.html): event-type-specific records carry network, alert, DNS and HTTP meaning. | A documented synthetic alert/flow/DNS/HTTP subset, explicit severity mapping, raw snapshots, and local re-encoding comparisons; see [adapters](adapters.md) and [differential testing](differential_testing.md). | Running Suricata, interpreting its rules, processing packets, full EVE compatibility or validating production sensor behavior. Synthetic `dvi_*` fields are DVI fixture conventions. |
| [Sigma rules specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) and [pySigma documentation](https://sigmahq-pysigma.readthedocs.io/en/latest/): keep rule identity, title, tags and source context distinct from detection conditions and conversion. | Local rule IDs/titles, detector/signature identity, labels/tags, source metadata and explicit matching criteria; see [harness](detector_harness.md) and [matching](matching.md). | Sigma parsing, condition-language compatibility, pySigma backends/pipelines, query conversion or rule deployment. Neither is a dependency; the local rule DSL is DVI-specific. |
| [MITRE ATT&CK data sources](https://attack.mitre.org/datasources/): describe which observable data can support detection reasoning. | Optional technique strings on detections/expectations and evidence references. Matching checks declared strings; it does not fetch or validate a knowledge base. | ATT&CK coverage, technique execution, emulation, validated mappings or detection-strategy implementation. MITRE deprecated data sources in v18 (October 2025); this is historical vocabulary, not a claim that DVI implements the current ATT&CK object model. |
| [MITRE D3FEND project description](https://d3fend.mitre.org/about/): explain defensive capabilities through their evidence and operating conditions. | Evidence-linked descriptions of local fragility, preservation checks and bounded ablation results; see [frontier](resilience_frontier.md) and [shrinking](failure_shrinking.md). | D3FEND ontology ingestion, graph reasoning, technique-ID mappings, control-effectiveness certification or MITRE endorsement. DVI's fragility taxonomy is independently defined. |

## Testing methods

| Influence and borrowed idea | What DVI implements | What DVI does not claim |
| --- | --- | --- |
| [Hypothesis API](https://hypothesis.readthedocs.io/en/latest/reference/api.html) and [failure replay](https://hypothesis.readthedocs.io/en/latest/tutorial/replaying-failures.html): generate examples from declared domains, shrink failing inputs and preserve reproducible failures. | Development-only properties for boundaries, parsing, determinism, matching, metrics and artifacts; a deterministic profile with bounded examples and reproduction blobs. See [testing](testing.md). | Exhaustive verification, stable generated examples across dependency versions, or a Hypothesis dependency in the runtime engine. DVI's user-facing counterexample shrinker is separately implemented. |
| [Chen et al., Metamorphic Testing: A Review of Challenges and Opportunities (2018)](https://nottingham-repository.worktribe.com/output/925152/metamorphic-testing-a-review-of-challenges-and-opportunities): relate outputs across inputs whose relevant relationship is known, addressing limited test oracles. | Declared safe transformations, independent preservation checks, baseline/candidate matching, representation probes and robust controls. [Benchmarks](benchmarks.md) assert the resulting evidence against separate expectations. | Automatically discovering semantic equivalence, knowing the correct output for every detector, or proving that fixture relations hold in a production environment. The scenario author must declare the intended relation correctly. |
| [Kuhn, Kacker and Lei, NIST SP 800-142 (2010)](https://csrc.nist.gov/pubs/sp/800/142/final): cover interactions among selected parameter values without enumerating every full combination. | An eight-row test matrix covering every pair of values for seven binary planner parameters, with an assertion that verifies the pair coverage before exercising real plans and detectors. | ACTS integration, general covering-array generation, exhaustive higher-order interactions, NIST certification or operational detection coverage. This is a test-suite technique, not an additional search strategy. |

## Future research only

Full Zeek support, full OCSF/ECS export, Z3 constraints, SARIF/JUnit output,
CycloneDX/SLSA/Sigstore/OpenSSF release tooling, DuckDB/Polars analytics and
broader semantic coverage/adaptive search remain outside V1. Mentioning them
creates no implemented interface or support promise. The first requirements for
any future addition are a concrete local use case, executable evidence and the
same fixture-only safety boundary. See [engineering tradeoffs](engineering_notes.md).
