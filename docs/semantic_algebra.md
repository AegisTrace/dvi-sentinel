# Semantic detection algebra

The V2 development library evaluates seven bounded relations over the
[semantic ontology](semantic_ontology.md). Each result retains its input identities,
field checks, expected/observed values, reasons, disposition and evidence-support
fraction. It evaluates declared local fixture contracts; it does not run a detector.

## Values and evaluation

`Signal` and `Evidence` are roles for `OntologyExtraction`, retaining the full signal,
bindings, losses and event/raw digests. A bare semantic hash is insufficient because
equally incomplete contexts can share a hash. `Invariant` extends `SemanticInvariant`
with the reference context and sorted, unique protected fields. `Transform` extends
`SemanticTransform` with its actual source and destination contexts.

Use `bind_invariant(reference, fields)` and `bind_transform(source, destination)`.
Invariant identity binds the reference and protected fields. Transform identity binds
both full contexts; validation recomputes changed semantic fields and checks event
references. Changing metadata may leave meaning unchanged while changing provenance.

`Relation` names the operation and its subjects. `AlgebraDecision` records
`truth` (`true`, `false`, `unknown`), checks, effect and an `OracleResult` for this
single evaluator. The oracle decision maps these truths to `pass`, `fail`, `unknown`.
These are answers to the named predicate, not release-gate or detector verdicts.
Independent multi-oracle evaluation remains a later card.

| Function | Question and decision rule |
| --- | --- |
| `preserves(transform, invariant)` | Do the actual destination values retain the declared reference fields? All checks must be known and equal. A known mismatch is false; unresolved evidence cannot prove preservation. |
| `requires(signal, evidence)` | Does candidate evidence satisfy the reference's required fields? Required identity-bound values must match; other required fields need a resolved value. A declared confidence threshold uses numeric comparison. Missing bindings or unresolved values remain unknown. |
| `contradicts(evidence, invariant)` | Is there a known mismatch with a protected reference value? One known contradiction is true even if a different field is missing. Missing evidence alone is unknown. An unknown reference cannot establish a contradiction. |
| `implies(signal_a, signal_b)` | For known contexts with matching core meaning, does A have at least B's evidence requirements, precision, confidence and correlation constraints, and all B's bound values? This directional contract relation is not unrestricted logical inference. |
| `equivalent(signal_a, signal_b)` | Do both known ontology projections have equal meaning? Reuses ontology equivalence; equally missing values never prove equivalence. |
| `weakens(transform, signal)` | Does the destination have a lower required-evidence support fraction than the actual known source? An observed loss can prove weakening even when that loss makes the destination unknown. Equal support in an unknown context remains unknown. |
| `explains(finding, evidence)` | Is this exact recorded finding associated with the event and are its referenced bindings available? A missing-value binding can explain a missing-value finding. Unrelated findings are false; unavailable references are unknown. |

`explains` verifies the association and available references. It does not independently
reconstruct every upstream loss classification or authenticate the original source.
The single evaluator cannot provide independent corroboration of itself.

An effect of `suppressed_false_positive` means that a known contradiction blocks the
reference signal assertion for this comparison. It does not count measured detector
false positives. Other true relations have effect `supported`; false and unresolved
relations have `not_supported` and `unknown`. `oracle.blocking` is false only for
`supported`. Consumers must interpret each named predicate before combining results:
for example, `contradicts == false` means no known contradiction was found.

## Protected fields and missing evidence

Protected fields can name a top-level `SignalMeaning` field: `category`, `action`,
`outcome`, `entities`, `source_destination_relation`, `protocol`, `resource`,
`time_role`, `timestamp_precision_digits`, `evidence_requirements`,
`confidence_requirement`, `correlation_requirement` or `evidence`. Use
`evidence.<binding-name>` to protect an individual binding, including one excluded
from semantic identity. Unsupported names produce explicit unknown checks. Selectors
are inert names, never expressions, attribute access, queries or executable paths.

Comparisons retain canonical JSON values. An absent snapshot is distinct from a
literal JSON `null` or empty list in a known semantic field. A changed resource or
evidence list involving an unresolved/missing member cannot prove contradiction.
Likewise, unavailable protocol, outcome or source/destination endpoints do not become
known mismatches. A known mismatch in another selected field remains visible.

Required identity-bound fields compare their known reference values. Required fields
excluded from identity, such as default event time, require presence without requiring
an identical timestamp. Field-linked losses remain unknown. The reference's numeric
confidence requirement compares against observed source confidence, rather than an
exact baseline sample value. Broader unresolved context prevents an otherwise positive
preservation, requirements, implication or equivalence claim.

## Evidence-support confidence

Every oracle records `confidence_basis = satisfied_required_evidence_fraction`:

```text
numerator   = reference-required fields whose checks are true
denominator = all reference-required fields, including false and unknown checks
value       = numerator / denominator, or null when the denominator is zero
```

This is a descriptive support fraction. It is not a probability, statistical interval,
source-reported confidence, or the certainty that the relation is true. Four resolved
required fields with an unrelated unresolved warning can produce support `4/4` while
the relation remains unknown. An empty required contract produces `0/0`, value `null`,
and cannot establish a positive requirements or weakening decision.

`weakens` retains both fractions. In the example, dropping the required DNS question
changes support from `4/4 = 1.0` to `3/4 = 0.75`; the drop stays in the denominator.
The candidate is unknown, not a known contradiction. It can still explain why the
declared signal has less supporting evidence.

## Runnable proof and artifacts

From a development installation, choose a new local output directory:

```sh
python examples/semantic_algebra.py --out runs/v2/algebra-proof
```

The [example](../examples/semantic_algebra.py) constructs a synthetic DNS event and
a copy without its question. Its measured decisions are:

| Relation | Truth |
| --- | --- |
| preserves | unknown |
| requires | unknown |
| contradicts | unknown |
| implies | unknown |
| equivalent | unknown |
| weakens | true |
| explains | true |

`evaluate_plan(transform, invariant)` evaluates six core relations plus one
`explains` row per actual destination finding. A robust fixture with no findings has
six rows; it does not acquire a fabricated explanation. `algebra_artifacts(plan)`
validates and re-evaluates the entire plan before serializing:

- `semantic_plan.json`: schema version `1`, full transform/reference evidence,
  invariant and measured decisions.
- `algebra_decisions.jsonl`: the same decisions as canonical individual records.

Repeated evaluation of the same validated input produces identical bytes. Changed
decisions, explanations or references are rejected when they disagree with replay.
Consumers loading a saved plan should use `SemanticPlan.model_validate_json` followed
by `algebra_artifacts` to check it against its recorded evidence. Model validation alone
checks structure and internal consistency, not a fresh evaluation of every result.

## Boundaries and verification

The models are immutable data; the analyzer has no filesystem/network/subprocess I/O.
It revalidates ontology contexts, enforces at most 64 bindings and 256 findings per
context, bounds serialization at 32 MiB per artifact, and reapplies fixture policy to
exposed signal and binding values. Invariants have 1-128 unique protected fields;
plans have 6-262 decisions. No new dependency is required.

The example writes two fixed filenames beneath a new local directory. It rejects
network paths, symlink/junction ancestors and existing destinations. These standalone
analysis files are not a verified V1 run bundle or a V2 provenance DAG. Hashes and
replay establish consistency with recorded evidence, not authenticity of source
assertions or omitted raw content. Use trusted upstream extraction and source evidence.

[Behavioral tests](../tests/test_v2_semantic_algebra.py) cover preservation and known
violations, unknown controls, directional implication, weakening denominators,
equivalent representations, real finding associations, input bounds, tampering,
deterministic replay and the executed example. Combined CLI integration, independent
oracles, temporal reasoning and statistical uncertainty remain later cards.
