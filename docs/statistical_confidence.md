# Statistical confidence

The opt-in V2 confidence layer adds conditional uncertainty to actual V1 case
assessments. It keeps V1 scores and regression decisions, and attaches separate
estimates to each seed's run, families and actual findings. It does not infer an
independent sampling mechanism from a deterministic fixture suite.

## Run the local proof

```sh
python examples/statistical_confidence.py --out runs/v2/confidence-proof
```

The [example](../examples/statistical_confidence.py) executes robust and
sensor-dependent local rules over 32 metadata cases and a baseline for each
of three seeds. Each cohort includes 16 sensor changes and 16 unchanged controls;
its rates describe that declared mixture. The robust detector detects every variant; the changed detector
misses 16. The V1 comparison remains regressed. Every seed has a paired detection
rate change of -0.5 with a negative uncertainty interval. Finite fixture estimates
remain `low_confidence`; each actual finding has a one-case denominator and is
`insufficient_sample`. Matching seeds do not multiply the sample size.

The [tests](../tests/test_v2_confidence.py) also measure explicit fixture schedules
with equal aggregate rates but opposite case outcomes. Their stability score is
zero. Small regressions retain the V1 failure even when the effect interval
includes zero.

## API and evidence boundary

```python
from dvi_sentinel.confidence import analyze_confidence, confidence_artifacts

# request is a validated ConfidenceInput; producer_pin was retained before use.
report = analyze_confidence(request, expected_digest=producer_pin)
artifacts = confidence_artifacts(request, expected_digest=producer_pin)
```

`ConfidenceInput` contains current runs, optional previous runs and settings.
Each `ConfidenceRun` pairs a V1 `ComparisonSnapshot` with exactly one
`ConfidenceEvidence` per case: actual `OracleEvidence` and its separately retained
SHA-256 pin. The complete request must also be pinned. Missing request pins produce
`unknown`; changed pins or authoritative failures produce `unsafe_rejected`.
Blocked reports omit the input and all estimates.

Every observation passes the existing safety and provenance oracles before
matching or statistics. Case event digests must match the retained events, and
each assessment's match must equal a recomputation from its actual expectation,
observation, parser status and preservation result. A match without its observation,
an observation without its expected match, or altered input hashes is rejected.
An absent observation and absent match remain unknown. Preservation evidence and
producer configuration identities are supplied V1 results, not transformation
replay or authenticated declarations. Content pins prove integrity, not authorship.

The analyzer has no detector execution, I/O, callback or network capability. It
accepts canonical V1 variant snapshots only; probes, differential snapshots,
repetitions and representations are outside this extension. The example uses the
existing local harness to produce its evidence before analysis.

## Denominators and intervals

Baseline cases are excluded, exactly as in V1 scoring. A run group contains its
variants; each family contains its own variants; a finding group contains only
the case supporting that actual V1 finding. No family sample size is presented
as finding-specific confidence. Seeds are analyzed separately.

For detection and miss intervals, `n = detected + missed`. Unknown and invalid
counts remain visible in the original `VariantMetrics`; V1's existing valid-case
rates are unchanged. With `n = 0`, interval endpoints and classification are
unknown. Small resolved samples (`n < 20`) always warn.

The two-sided Wilson interval uses observed proportion `p = k/n`, normal quantile
`z = Phi^-1((1+c)/2)`, center `(p + z^2/(2n))/(1 + z^2/n)` and half-width
`z*sqrt(p*(1-p)/n + z^2/(4n^2))/(1 + z^2/n)`. Bounds stay within [0, 1], including
exact zero/one boundary endpoints. This is an approximate binomial score interval,
not the Wald interval. See the [NIST Wilson reference](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).

Resolved rates condition on known outcomes. To make missingness visible, separate
detection identification bounds range from `detected/eligible` to
`(detected + unknown)/eligible`, where `eligible = detected + missed + unknown`.
These are worst-case missing-outcome bounds, not confidence intervals. Invalid
cases are outside both denominators.

Latency uses only actual nonnegative delays from detected cases, as in V1.
Misses, unknowns and late alerts classified as misses are excluded. The artifacts
label that conditioning and always warn about selection. They retain observed
delays and the mean, median and p95. Quantiles use V1's linear interpolation at
`(n-1)*fraction`.

A private `random.Random(seed)` resamples sorted observed delays with replacement,
using the original number of observations per replicate. The configured number
of replicates never becomes a sample denominator. Pointwise percentile endpoints
use `(1-c)/2` and `(1+c)/2` of the retained replicate estimates. Fewer than two
observed delays produce no bootstrap interval; constant samples warn about
degenerate bounds. A singleton still has its observed point estimate.

The percentile method is an uncorrected empirical IID bootstrap. Small samples,
dependence, tail estimation and degenerate distributions can yield poor coverage;
this implementation does not claim BCa correction or simultaneous coverage across
metrics/groups. Bootstrap foundations are described by
[Efron and Tibshirani (1986)](https://doi.org/10.1214/ss/1177013815).

## Seed stability and classification

Logical units are identified by family, variation distance and actual case input
digest, independently of seed-specific case IDs. Seed cohorts require equal tool,
scenario, source, variation configuration and detector digests, as well as matching
unit/expectation bindings. Missing or duplicate units, changed configurations,
empty cohorts or a single seed leave stability unknown with reasons.

For comparable cohorts, possible pairs equal units times `choose(seeds, 2)`.
Only pairs with two resolved outcomes contribute to agreement. The score is
same-outcome pairs divided by resolved pairs; unavailable pairs are explicit.
Partial observations cannot establish complete stability. Finding stability tracks
the corresponding unit across every seed, including seeds where that case detects
and therefore has no finding.

Classification follows these rules in order. They are transparent policy
thresholds about conditional estimator precision, not probabilities that a finding
is true, causal confidence or a release gate.

| Condition | Class |
| --- | --- |
| No resolved denominator | `unknown` |
| Measured seed agreement below 0.8 | `unstable_across_seeds` |
| Fewer than 20 resolved cases | `insufficient_sample` |
| Unknown/invalid cases, duplicate inputs, incomplete seed stability or no declared IID assumption | `low_confidence` |
| At least 100 resolved cases, Wilson width at most 0.2, at least three seeds and agreement at least 0.9 | `high_confidence` |
| At least 30 resolved cases, Wilson width at most 0.35 and agreement at least 0.8 | `moderate_confidence` |
| Otherwise | `low_confidence` |

`independent_trials_assumed` defaults to false. Setting it to true is an explicit,
unverified modeling assumption; it always carries a warning. Distinct event hashes
do not prove independence, and seeds are not independent additional trials. Labels
apply to the resolved detection estimator; they do not certify latency precision.
The calibration note is retained in every report. No empirical coverage calibration
or population-validity claim has been established.

## Regression effect uncertainty

Previous/current batches require identical seed sets. Each seed keeps the complete
existing `compare_snapshots` result and its default V1 threshold decisions. An
incompatible V1 pair produces no effect estimates. Changed case expectations also
prevent effect estimates, with a reason, while retaining the original V1 decision.

For each compatible current cohort, pair cases by their existing IDs. Pairs where
either outcome is unknown/invalid are counted as unavailable. Among resolved pairs,
record recoveries (miss to detection), losses (detection to miss) and unchanged
outcomes. The effect is `(recoveries - losses)/resolved_pairs`.

The approximate paired envelope uses two Wilson intervals at marginal confidence
`(1+c)/2`: one for the recovery fraction and one for the loss fraction. Subtract
their cross-endpoints, `[L_recovery-U_loss, U_recovery-L_loss]`, clipped to [-1, 1].
This is our conservative envelope construction using the
[Bonferroni simultaneous-interval principle](https://itl.nist.gov/div898/handbook/prc/section4/prc473.htm).
It accommodates dependence between recovery/loss indicators within a pair, while
still assuming independent trial pairs for a population interpretation. Wilson
coverage is approximate, so the envelope is not an exact coverage guarantee.

Direction labels describe whether these numerical endpoints are negative,
positive, contain zero or are unavailable. They never cancel V1 regressions.
Even all-unchanged finite observations have a nonzero-width interval. Intervals
are pointwise per cohort; there is no adjustment across all findings or families,
and selection of discovered findings limits inferential interpretation.

## Artifacts, validation and bounds

| Artifact | Contents |
| --- | --- |
| `confidence.json` | Pinned input, authoritative gates, groups, stability, comparisons, warnings and calibration note |
| `seed_stability.json` | Linked per-seed rates, pair accounting, scores and reasons |
| `score_distribution.json` | Group metrics, intervals, observed latency and bootstrap replicates |
| `statistical_warnings.json` | Group warning codes/explanations and calibration note |

Full report validation rechecks gates and rederives groups, matching, bootstrap
replicates, stability, classifications, warnings and V1 comparison decisions from
retained input. It rejects self-consistent but altered numerical evidence. Export
views carry the same input digest; they are slices of the full report, not standalone
proof of provenance. Reproduce from pinned producer evidence to establish origin.

Bounds are eight runs per side, 128 records per run (including at most one baseline),
512 total records, eight events and eight detections per record, 4 MiB complete
input and 32 MiB combined output. Observed delays are at most one day. Bootstrap
resamples are 100..1000 (default 400), seed is 0..2^63-1 (default 42), and confidence
level is 0.8..0.99 (default 0.95). Seeds/cases are canonicalized before hashing;
bootstrap reproduction is version-local and tested across Python 3.12/3.13.

Data models are category D, numerical/analyzer modules category A, and the example
writer category W. It writes fixed filenames exclusively into a new validated local
directory. No dependency is added. These outputs are separate library evidence;
V2 CLI/report integration and release certification remain later cards.
