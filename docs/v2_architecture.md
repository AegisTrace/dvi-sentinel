# V2 architecture contract

V2 is in development. This document records the scope lock from the owner's
2026-09-15 blueprint. Development on `main` now includes the
[V2-01 semantic ontology](semantic_ontology.md), [V2-02 semantic algebra](semantic_algebra.md),
[V2-03 schema profiles](schema_profiles.md), [V2-04 detection intent](detection_intent.md),
[V2-05 temporal correlation](temporal_correlation.md) and
[V2-06 oracle consensus](oracle_consensus.md) and
[V2-07 constraint exploration](constraint_exploration.md) and
[V2-08 semantic coverage](semantic_coverage.md) and
[V2-09 cross-representation testing](cross_representation_testing.md) and
[V2-10 counterfactual mining](counterfactual_causality.md) and
[V2-11 oracle-aware shrinking](failure_shrinking.md);
subsequent cards remain planned.
V1 was released as `v1.0.0` at `cf353e03474da32ddb59029d1b33759e44fbd900`;
its release and both CI runs were verified before V2 work began. The
[V1 architecture](architecture.md) remains the implemented foundation.

The target is local analysis of where declared defensive detections depend on
brittle schema, timing, correlation or evidence assumptions. New claims need
executable fixtures and independent checks, not names for future modules.

## Fixed boundary and vocabulary

All cards are local-only, defensive-only and synthetic/documentation-fixture-only.
Allowed work is bounded fixture reading, inert event transformations, local
declarative detector logic, pure analysis and explicit local artifact writing.
Dependency installation, builds and repository CI may access their normal package
or hosting services; DVI's runtime and tests need no network after installation.

No card may add live targets, production-network access, scans, attack chains,
exploits, payloads, malware, credentials, stealth, persistence, destructive target
actions, compromise automation, bypass recipes, scenario command execution or
external detector services. No LLM, cloud, SIEM/EDR client or browser automation
dependency belongs in the required runtime. Existing safety checks remain enforced
before and after transformations; synthetic declarations are not a content classifier.

Each new module must fit one of these categories, named in its review:

| Code | Category | Boundary |
| --- | --- | --- |
| D | Pure data model | Validated typed values; no filesystem, network or subprocess I/O. |
| R | Bounded local fixture reader | Reuse validated path, size, count and parsing boundaries. |
| W | Bounded local artifact writer | Write only beneath an explicit validated output directory. |
| A | Pure analyzer | Operate on already validated values/artifacts; no implicit I/O. |
| C | CLI wrapper | Invoke approved internal functions and preserve structured errors. |

Documents and tests are reviewed against the same boundary. A module cannot hide
extra I/O behind a category label. Inspect its actual imports, calls and consumers.

Status vocabulary is precise: **implemented** means the card has passed code,
tests, examples, safety review, commit/push and CI; **experimental** means executable
behavior with explicitly limited evidence and no release claim; **roadmap** means
no supported runtime promise. A future filename, artifact name or diagram does not
make a capability implemented.

## Extend V1 at its existing boundaries

| Existing boundary | Planned extension | Compatibility requirement |
| --- | --- | --- |
| `models.py`, `serialization.py` | Semantic signal/evidence projections above `TelemetryEvent` | Preserve canonical events and raw hashes; separate semantic identity from event identity and source provenance. |
| `adapters.py`, `adapter_mapping.py`, `fixture_encoding.py` | Versioned profile projections and loss-aware roundtrips | Keep JSONL/CSV/EVE input contracts; identify unsupported fields and alias ambiguity explicitly. |
| `harness_models.py`, `harness.py`, `matching.py` | Intent and bounded temporal/correlation reasoning | Keep the two local harnesses and V1 outcomes; never compile or execute scenario text as code. |
| `invariants.py`, `variations.py`, `probes.py` | Executable relations, constraints and coverage retention | Keep independent preservation checks, stable seeds, finite budgets and explicit rejected/skipped cases. |
| `shrinking.py`, `reductions.py` | Counterfactual sets and consensus-preserving minimization | Re-evaluate actual local detections and invariants; preserve finding class and stop on uncertainty. |
| `scoring.py`, `comparison.py` | Statistical uncertainty and compatible run history | Preserve V1 denominators and incompatibility checks; missing evidence cannot become a passing gate. |
| `artifact_store.py`, `run_artifacts.py`, `provenance.py` | Typed evidence graph and parent-child lineage | Preserve trusted-root and manifest rules; version extensions and test legacy bundle handling. |
| `reports.py`, `workflow.py`, `cli/` | Integrated V2 artifacts, local reports and commands | Existing commands remain; consumers verify evidence before rendering or comparing. |

Do not replace working V1 systems wholesale. Any change to a public input, output,
error, artifact version or semantic interpretation needs migration/regression tests
and an explicit compatibility decision. Existing V1 benchmark controls stay active.
The package version does not imply an artifact schema change; version each changed
artifact contract deliberately rather than relabeling all V1 files.

## Ordered cards and acceptance focus

Every row inherits the fixed local-only boundary above. Category codes name the
permitted implementation roles, not approval for unbounded readers or writers.
Only the current card may create its modules; the table is a plan, not scaffolding.

| Card | Extension and acceptance focus | Local roles |
| --- | --- | --- |
| V2-00 | Scope/status separation, architecture, development standard and release criteria; no runtime change. | Documentation |
| V2-01 | Semantic signals, evidence/field bindings, equivalence, explicit loss/unknown states and deterministic ontology exports. | D, A, W |
| V2-02 | Executable preservation, requirements, contradiction, implication, equivalence, weakening and explanation relations. | D, A, W |
| V2-03 | DVI, OCSF-like, ECS-like, OpenTelemetry-like, EVE, Zeek-like and Sigma-metadata projections with roundtrip/loss proof. | D, R, A, W |
| V2-04 | Bounded local intent inputs and unsupported-condition, logsource, field, severity, time and correlation analysis. **Implemented on main; see [intent contract](detection_intent.md).** | D, R, A, W |
| V2-05 | Bounded sequence/window/correlation predicates, stable ordering and explicit evidence/precision uncertainty. **Implemented on main; see [temporal contract](temporal_correlation.md).** | D, A, W |
| V2-06 | Independent safety, schema, semantic, temporal, differential, detection, statistical, evidence and provenance decisions; preserved disagreement. **Implemented on main; see [oracle contract](oracle_consensus.md).** | D, A, W |
| V2-07 | Finite pairwise/t-way exploration, invalid-combination pruning, deterministic budgets and explained skips. **Implemented on main; see [exploration contract](constraint_exploration.md).** | D, A, W |
| V2-08 | Measured semantic coverage, novelty retention and reproducible growth without duplicate inflation. **Implemented on main; see [coverage contract](semantic_coverage.md).** | D, A, W |
| V2-09 | Cross-representation relations with field-linked losses and explicit unsupported profile features. **Implemented on main; see [comparison contract](cross_representation_testing.md).** | D, A, W |
| V2-10 | Single/combined safe counterfactuals, minimal tested failure sets and conditional local effect rankings. **Implemented on main; see [counterfactual contract](counterfactual_causality.md).** | D, A, W |
| V2-11 | Bounded reductions preserving semantics, finding class and oracle consensus with a complete attempt trace. **Implemented on main; see [shrinking contract](failure_shrinking.md).** | D, A, W |
| V2-12 | Wilson and seeded bootstrap intervals, denominator/sample warnings, seed stability and stated calibration limits. | D, A, W |
| V2-13 | Explicit local baseline registry, compatible history and confidence-aware drift/regression classifications. | D, R, A, W |
| V2-14 | Deterministic typed graph with findings connected to source evidence and recommendations to supported causes. | D, A, W |
| V2-15 | Parent-child artifact DAG, tamper propagation, missing-parent decisions and bounded bundle verification. | D, R, A, W |
| V2-16 | Real fragile/control fixtures across all 16 specified benchmark families, with independent acceptance oracles. | D, R, A, W, C |
| V2-17 | Verified-bundle JSON/Markdown/HTML reports, explicit absent sections and a self-contained report archive. | D, A, W |
| V2-18 | Integrated ontology, mapping, intent, temporal, oracle, exploration, explanation, confidence, graph and benchmark CLI. | C, R, W |
| V2-19 | Python 3.12/3.13 CI, installed-wheel V2 proof, offline tests and bounded artifact retention. | CI/configuration |
| V2-20 | Claims tied to executed examples, benchmarks, genuine report output and clear V1/V2 status. | Documentation |
| V2-21 | Full release proof, visual inspection, claim/safety audits, verified artifacts and green published commit. | Release verification |

## Dependency decisions

The blueprint order is fixed; later-card concepts are not permission to prebuild
their engines. V2-06 can assess currently available evidence using V1 manifests
and measured observations. Until V2-12 supplies statistical estimates or V2-15
supplies DAG evidence, an oracle must say what it checked and report unavailable
requirements as unknown/not-applicable. It must not invent confidence or lineage.
Those later cards add their real evidence through the existing oracle contract.

Engine cards use tested library/example paths and genuine artifacts before the
combined V2 CLI arrives. V2-16's benchmark exit behavior requires a small executable
runner at that card; V2-18 integrates that proven runner into the main command set.
There is no need for empty CLI commands to reserve names beforehand.

Profile projections describe their exact local subset, revision, mapped fields,
losses and unsupported content. Sigma-style metadata is a detection-description
projection, not a packet/event interchange standard or full Sigma compiler. A
missing relation cannot be filled by guessing a vendor field or detection meaning.
Consult versioned primary documentation when each profile is implemented.

## Semantic and uncertainty contracts

Semantic identity depends on an explicit projection and evidence contract. Changes
to action, role, resource or required evidence must not disappear behind a digest.
Representation-only metadata may be excluded only when it is not bound as required
evidence. Keep source/event identity and raw digests in evidence bindings so semantic
equivalence never implies identical provenance. Missing required fields and ambiguous
bindings remain loss/unknown, even when two incomplete projections hash equally.

Oracle results need stable subject IDs, reason codes, evidence references and
explained confidence. Safety rejection and provenance integrity failure block use;
other disagreements stay visible. Multiple correlated checks of the same fact do
not constitute independent corroboration. Consensus must identify what supports
the finding and what remains uncertain.

Finite deterministic fixture rows are not automatically independent statistical
samples. Confidence calculations must declare the sampling unit, denominator,
assumptions, seed and limits. Report descriptive fixture rates separately from any
inferential interval. Unknown observations, tiny samples or unstable seeds must not
be silently discarded to improve a score. Counterfactual rankings describe local
tested associations; they do not establish universal causes or bypasses.

Search and shrinking declare event, case, combination and evaluation limits before
execution. Exhaustion is a result with reasons, not evidence that all cases passed.
No new reader/writer may weaken V1 path confinement or consume unverified bundles.

The implemented [statistical confidence contract](statistical_confidence.md) adds
per-seed Wilson rates, latency bootstrap, paired unit agreement and regression
effect bounds. Models and report validation rederive numerical evidence from
pinned observations; the pure analyzer reuses V1 matching/scoring/comparison and
authoritative safety/provenance oracles. No execution or dependency is added.

## Artifacts, presentation and release

Emit artifacts only from actual validated inputs and measured analysis. A required
output that cannot be produced is a failed/unknown requirement; an optional absent
section needs an explicit reason. Do not manufacture static JSON to satisfy a file
inventory. Artifact parents, bytes, schema versions and digests must be independently
checkable. A DAG proves recorded derivation/consistency, not authorship or a rerun
of the detector. Reports must avoid circular self-hash dependencies.

Reports explain what was tested, expected, changed and preserved; the finding and
minimum; supporting/disagreeing evidence; confidence and limits; and reproduction.
All HTML/Markdown content is escaped where appropriate. Rendering needs no remote
fonts, scripts, CDN, graph service or external asset. Generated screenshots must
come from a verified run, with human and automated inspection attributed accurately.

V2 release requires Ruff, format, strict mypy, full pytest and at least 90% combined
coverage; wheel/sdist build and isolated installation; existing and new CLI proofs;
robust and fragile benchmark controls; compatible regression and unknown-state
checks; Docker reproduction with networking disabled; manifest and DAG verification;
actual rendered HTML inspection; and README/SECURITY/CHANGELOG/safety audits.
Python 3.12 and 3.13 CI must pass for the release commit. No tag is allowed while
a required artifact, implementation, safety decision, example or visual check is
unverified. Subjective portfolio scores in the source blueprint are aspirations,
not measurements or release evidence.

See the [development standard](development_standard.md) for the one-card loop and
[card record](v2_build_log.md) for concrete acceptance/proof. The original blueprint
is planning input; this document records the adopted technical scope and its
verification requirements. All repository updates are made directly on `main`.
