"""Bounded evidence, explicit denominators and linked uncertainty records (D)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from dvi_sentinel.comparison_models import ComparisonResult, ComparisonSnapshot
from dvi_sentinel.confidence_math import latency_points, paired_difference_bounds, wilson_bounds
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.oracle_models import OracleEvidence, OracleResult
from dvi_sentinel.score_models import VariantMetrics
from dvi_sentinel.scoring import percentile
from dvi_sentinel.serialization import canonical_json

Count = Annotated[StrictInt, Field(ge=0, le=1_000_000_000)]
Level = Annotated[float, Field(gt=0, lt=1, allow_inf_nan=False)]
Finite = Annotated[float, Field(allow_inf_nan=False)]
Side = Literal["previous", "current"]
ConfidenceClass = Literal[
    "high_confidence",
    "moderate_confidence",
    "low_confidence",
    "insufficient_sample",
    "unstable_across_seeds",
    "unknown",
]
Scope = Literal["run", "family", "finding"]


class ConfidenceSettings(ValueModel):
    confidence_level: Annotated[float, Field(ge=0.8, le=0.99, allow_inf_nan=False)] = 0.95
    bootstrap_seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)] = 42
    bootstrap_resamples: Annotated[StrictInt, Field(ge=100, le=1000)] = 400
    independent_trials_assumed: StrictBool = False


class ConfidenceEvidence(ValueModel):
    evidence: OracleEvidence
    expected_digest: Sha256

    @model_validator(mode="after")
    def bounded(self) -> Self:
        row = self.evidence
        if len(row.events) > 8 or (row.observation and len(row.observation.detections) > 8):
            raise ValueError("DVI-CONFIDENCE-BOUNDS: at most eight events/detections per record")
        if row.repetitions or row.representations:
            raise ValueError("DVI-CONFIDENCE-EVIDENCE: each record is one canonical observation")
        return self


class ConfidenceRun(ValueModel):
    snapshot: ComparisonSnapshot
    evidence: Annotated[tuple[ConfidenceEvidence, ...], Field(max_length=128)]

    @field_validator("snapshot")
    @classmethod
    def ordered_snapshot(cls, value: ComparisonSnapshot) -> ComparisonSnapshot:
        return value.model_copy(
            update={"assessments": tuple(sorted(value.assessments, key=lambda r: r.case_id))}
        )

    @field_validator("evidence")
    @classmethod
    def ordered_evidence(
        cls, rows: tuple[ConfidenceEvidence, ...]
    ) -> tuple[ConfidenceEvidence, ...]:
        return tuple(sorted(rows, key=lambda row: row.evidence.subject_id))

    @model_validator(mode="after")
    def linked(self) -> Self:
        snapshot = self.snapshot
        if snapshot.schema_version != "1" or snapshot.probes or snapshot.differential:
            raise ValueError("DVI-CONFIDENCE-SCOPE: require V1 canonical variant snapshots")
        if (
            len(snapshot.assessments) > 128
            or sum(r.family == "baseline" for r in snapshot.assessments) > 1
        ):
            raise ValueError("DVI-CONFIDENCE-BOUNDS: at most 128 cases and one baseline per run")
        ids = [row.evidence.subject_id for row in self.evidence]
        if len(set(ids)) != len(ids) or set(ids) != {row.case_id for row in snapshot.assessments}:
            raise ValueError("DVI-CONFIDENCE-EVIDENCE: require exactly one proof per assessment")
        return self


class ConfidenceInput(ValueModel):
    schema_version: Literal["1"] = "1"
    current: Annotated[tuple[ConfidenceRun, ...], Field(min_length=1, max_length=8)]
    previous: Annotated[tuple[ConfidenceRun, ...], Field(max_length=8)] = ()
    settings: ConfidenceSettings = ConfidenceSettings()

    @field_validator("current", "previous")
    @classmethod
    def ordered_runs(cls, runs: tuple[ConfidenceRun, ...]) -> tuple[ConfidenceRun, ...]:
        if len({r.snapshot.seed for r in runs}) != len(runs):
            raise ValueError("DVI-CONFIDENCE-SEEDS: seed identities must be unique per side")
        return tuple(sorted(runs, key=lambda r: r.snapshot.seed))

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if sum(len(run.evidence) for run in (*self.previous, *self.current)) > 512:
            raise ValueError("DVI-CONFIDENCE-BOUNDS: at most 512 total records")
        if len(canonical_json(self).encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("DVI-CONFIDENCE-BOUNDS: complete request exceeds 4 MiB")
        return self


class RateInterval(ValueModel):
    numerator: Count
    denominator: Count
    confidence_level: Level
    lower: Finite | None
    upper: Finite | None
    method: Literal["wilson_score"] = "wilson_score"

    @model_validator(mode="after")
    def computed(self) -> Self:
        if (self.lower, self.upper) != wilson_bounds(
            self.numerator, self.denominator, self.confidence_level
        ):
            raise ValueError("DVI-CONFIDENCE-WILSON: endpoints differ from counts")
        return self

    @classmethod
    def from_counts(cls, count: int, total: int, level: float) -> Self:
        lower, upper = wilson_bounds(count, total, level)
        return cls(
            numerator=count, denominator=total, confidence_level=level, lower=lower, upper=upper
        )


class LatencyEstimate(ValueModel):
    metric: Literal["mean", "p50", "p95"]
    estimate: Finite | None
    lower: Finite | None
    upper: Finite | None
    resampled_estimates: Annotated[tuple[Finite, ...], Field(max_length=1000)]


class LatencyBootstrap(ValueModel):
    samples_ms: Annotated[tuple[Finite, ...], Field(max_length=128)]
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    requested_resamples: Annotated[StrictInt, Field(ge=100, le=1000)]
    confidence_level: Level
    estimates: tuple[LatencyEstimate, LatencyEstimate, LatencyEstimate]
    conditioning: Literal["detected_alerts_only"] = "detected_alerts_only"
    method: Literal["empirical_iid_percentile_pointwise"] = "empirical_iid_percentile_pointwise"

    @model_validator(mode="after")
    def computed(self) -> Self:
        points = latency_points(self.samples_ms)
        alpha = (1 - self.confidence_level) / 2
        for name, point, row in zip(("mean", "p50", "p95"), points, self.estimates, strict=True):
            expected_count = self.requested_resamples if len(self.samples_ms) >= 2 else 0
            if (
                row.metric != name
                or row.estimate != point
                or len(row.resampled_estimates) != expected_count
                or row.lower != percentile(list(row.resampled_estimates), alpha)
                or row.upper != percentile(list(row.resampled_estimates), 1 - alpha)
            ):
                raise ValueError("DVI-CONFIDENCE-BOOTSTRAP: estimates differ from retained samples")
        return self


class SeedRate(ValueModel):
    seed: Annotated[StrictInt, Field(ge=0)]
    detected: Count
    missed: Count
    unknown: Count
    invalid: Count
    detection_rate: Finite | None


class SeedStability(ValueModel):
    key: NonEmpty
    side: Side
    rates: Annotated[tuple[SeedRate, ...], Field(max_length=8)]
    possible_pairs: Count
    resolved_pairs: Count
    agreeing_pairs: Count
    unavailable_pairs: Count
    score: Annotated[float, Field(ge=0, le=1)] | None
    state: Literal["measured", "partial", "unknown"]
    reasons: tuple[Identifier, ...]

    @model_validator(mode="after")
    def computed(self) -> Self:
        value = self.agreeing_pairs / self.resolved_pairs if self.resolved_pairs else None
        if (
            self.resolved_pairs + self.unavailable_pairs != self.possible_pairs
            or self.agreeing_pairs > self.resolved_pairs
            or self.score != (None if self.state == "unknown" else value)
        ):
            raise ValueError("DVI-CONFIDENCE-STABILITY: pair accounting differs")
        for row in self.rates:
            total = row.detected + row.missed
            if row.detection_rate != (row.detected / total if total else None):
                raise ValueError("DVI-CONFIDENCE-STABILITY: seed denominator differs")
        return self


class StatisticalWarning(ValueModel):
    group: NonEmpty
    code: Identifier
    explanation: NonEmpty


class GroupConfidence(ValueModel):
    key: NonEmpty
    side: Side
    seed: Annotated[StrictInt, Field(ge=0)]
    scope: Scope
    scope_id: NonEmpty
    case_ids: tuple[Identifier, ...]
    metrics: VariantMetrics
    detection_interval: RateInterval
    miss_interval: RateInterval
    detection_identification_bounds: tuple[Finite | None, Finite | None]
    latency: LatencyBootstrap
    stability_key: NonEmpty
    confidence_class: ConfidenceClass
    warnings: tuple[Identifier, ...]

    @model_validator(mode="after")
    def computed(self) -> Self:
        m = self.metrics
        known = m.detected + m.missed
        eligible = known + m.unknown
        identification = (
            (m.detected / eligible, (m.detected + m.unknown) / eligible)
            if eligible
            else (None, None)
        )
        if (
            len(set(self.case_ids)) != len(self.case_ids)
            or len(self.case_ids) != m.total
            or self.detection_interval.numerator != m.detected
            or self.miss_interval.numerator != m.missed
            or self.detection_interval.denominator != known
            or self.miss_interval.denominator != known
            or self.detection_identification_bounds != identification
            or len(self.latency.samples_ms) != m.latency_samples
            or (not known and self.confidence_class != "unknown")
        ):
            raise ValueError("DVI-CONFIDENCE-DENOMINATOR: group evidence/counts differ")
        return self


class PairedEffect(ValueModel):
    scope: Scope
    scope_id: NonEmpty
    paired_cases: Count
    recovered: Count
    lost: Count
    unchanged: Count
    unavailable: Count
    delta: Finite | None
    lower: Finite | None
    upper: Finite | None
    confidence_level: Level
    direction: Literal["negative_interval", "positive_interval", "includes_zero", "unknown"]
    method: Literal["approximate_bonferroni_wilson_paired_difference"] = (
        "approximate_bonferroni_wilson_paired_difference"
    )

    @model_validator(mode="after")
    def computed(self) -> Self:
        n = self.recovered + self.lost + self.unchanged
        bounds = paired_difference_bounds(self.recovered, self.lost, n, self.confidence_level)
        direction = (
            "unknown"
            if not n
            else "negative_interval"
            if bounds[1] is not None and bounds[1] < 0
            else "positive_interval"
            if bounds[0] is not None and bounds[0] > 0
            else "includes_zero"
        )
        if (
            n + self.unavailable != self.paired_cases
            or (self.lower, self.upper) != bounds
            or self.delta != ((self.recovered - self.lost) / n if n else None)
            or self.direction != direction
        ):
            raise ValueError("DVI-CONFIDENCE-EFFECT: paired transition counts differ")
        return self


class SeedComparison(ValueModel):
    seed: Annotated[StrictInt, Field(ge=0)]
    legacy: ComparisonResult
    effects: tuple[PairedEffect, ...]
    effect_reasons: tuple[NonEmpty, ...] = ()


class ConfidenceReport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    input: ConfidenceInput | None
    state: Literal["measured", "unknown", "unsafe_rejected"]
    gates: tuple[OracleResult, ...] = ()
    groups: tuple[GroupConfidence, ...] = ()
    seed_stability: tuple[SeedStability, ...] = ()
    comparisons: tuple[SeedComparison, ...] = ()
    comparison_reasons: tuple[NonEmpty, ...] = ()
    warnings: tuple[StatisticalWarning, ...] = ()
    calibration_note: NonEmpty

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.input is None:
            if self.state == "measured" or self.groups or self.seed_stability or self.comparisons:
                raise ValueError("DVI-CONFIDENCE-GATE: blocked input cannot contain estimates")
            return self
        if self.input_digest != self.input.stable_digest() or any(g.blocking for g in self.gates):
            raise ValueError("DVI-CONFIDENCE-GATE: input changed or an authoritative gate failed")
        stability = {row.key: row for row in self.seed_stability}
        if len(stability) != len(self.seed_stability) or len(
            {row.key for row in self.groups}
        ) != len(self.groups):
            raise ValueError("DVI-CONFIDENCE-IDENTITY: duplicate group/stability identity")
        for group in self.groups:
            if group.stability_key not in stability:
                raise ValueError("DVI-CONFIDENCE-STABILITY: group lacks a stability record")
        # Reproduce bounded numerical evidence, never detector execution. Import locally
        # to keep the input models independent of the analyzer during module loading.
        from dvi_sentinel.confidence import CALIBRATION, _derive, _gates

        if self.state != "measured" or self.gates != _gates(self.input):
            raise ValueError("DVI-CONFIDENCE-GATE: require complete matching authoritative gates")
        actual = (
            self.groups,
            self.seed_stability,
            self.comparisons,
            self.comparison_reasons,
            self.warnings,
        )
        if actual != _derive(self.input) or self.calibration_note != CALIBRATION:
            raise ValueError("DVI-CONFIDENCE-DERIVATION: report differs from retained input")
        return self


class StabilityExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    records: tuple[SeedStability, ...]


class DistributionExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    groups: tuple[GroupConfidence, ...]


class WarningExport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    warnings: tuple[StatisticalWarning, ...]
    calibration_note: NonEmpty
