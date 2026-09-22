"""Immutable, bounded local counterfactual inputs and evidence records (D)."""

from itertools import combinations
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from dvi_sentinel.constraint_models import (
    ConstraintDecision,
    CoveringArray,
    ExplorationStep,
    Option,
)
from dvi_sentinel.harness_models import HarnessResult, RuleHarnessConfig
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json, digest

Count = Annotated[StrictInt, Field(ge=0, le=4096)]
Active = Annotated[tuple[Identifier, ...], Field(max_length=6)]
Outcome = Literal["detected", "missed", "unknown", "invalid", "not_evaluated"]
Stage = Literal["baseline", "single", "covering", "minimization", "not_selected"]


def subsets(names: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Canonical full power set for at most six binary dimensions."""
    if len(names) > 6 or len(set(names)) != len(names):
        raise ValueError("DVI-COUNTERFACTUAL-BOUNDS: require unique dimensions, at most six")
    return tuple(
        group for size in range(len(names) + 1) for group in combinations(sorted(names), size)
    )


class CounterfactualDimension(ValueModel):
    name: Identifier
    operation: Option

    @model_validator(mode="after")
    def active_operation(self) -> Self:
        if self.operation == "none":
            raise ValueError(
                "DVI-COUNTERFACTUAL-DIMENSION: dimension needs a non-identity operation"
            )
        return self


class CounterfactualBudget(ValueModel):
    max_cases: Annotated[StrictInt, Field(ge=1, le=64)] = 64
    max_events: Annotated[StrictInt, Field(ge=0, le=4096)] = 4096


class CounterfactualInput(ValueModel):
    events: Annotated[tuple[TelemetryEvent, ...], Field(min_length=1, max_length=8)]
    dimensions: Annotated[tuple[CounterfactualDimension, ...], Field(min_length=1, max_length=6)]
    policy: VariationPolicy
    expected: DetectionExpectation
    harness: RuleHarnessConfig
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)] = 0
    strength: Annotated[StrictInt, Field(ge=1, le=4)] = 2
    budget: CounterfactualBudget = CounterfactualBudget()

    @field_validator("dimensions")
    @classmethod
    def ordered_dimensions(
        cls, values: tuple[CounterfactualDimension, ...]
    ) -> tuple[CounterfactualDimension, ...]:
        if len({v.name for v in values}) != len(values) or len(
            {v.operation for v in values}
        ) != len(values):
            raise ValueError("DVI-COUNTERFACTUAL-DIMENSION: names and operations must be unique")
        return tuple(sorted(values, key=lambda v: v.name))

    @field_validator("harness")
    @classmethod
    def ordered_rules(cls, value: RuleHarnessConfig) -> RuleHarnessConfig:
        if len(value.rules) > 8:
            raise ValueError("DVI-COUNTERFACTUAL-BOUNDS: at most eight local rules")
        return value.model_copy(update={"rules": tuple(sorted(value.rules, key=lambda r: r.id))})

    @field_validator("policy")
    @classmethod
    def ordered_policy(cls, value: VariationPolicy) -> VariationPolicy:
        return value.model_copy(
            update={
                "families": tuple(sorted(value.families)),
                "optional_fields": tuple(sorted(value.optional_fields)),
            }
        )

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len({e.event_id for e in self.events}) != len(self.events):
            raise ValueError("DVI-COUNTERFACTUAL-IDENTITY: duplicate event IDs")
        if len(canonical_json(self).encode("utf-8")) > 262_144:
            raise ValueError("DVI-COUNTERFACTUAL-BOUNDS: complete input exceeds 256 KiB")
        return self


class CounterfactualCase(ValueModel):
    case_id: Identifier
    input_digest: Sha256
    active: Active
    stage: Stage
    outcome: Outcome
    reason: NonEmpty
    candidate_digest: Sha256 | None = None
    events: Annotated[tuple[TelemetryEvent, ...], Field(max_length=128)] = ()
    steps: Annotated[tuple[ExplorationStep, ...], Field(max_length=6)] = ()
    rejections: tuple[ConstraintDecision, ...] = ()
    observation: HarnessResult | None = None
    match: MatchResult | None = None
    evaluation: Annotated[StrictInt, Field(ge=1, le=64)] | None = None

    @model_validator(mode="after")
    def linked(self) -> Self:
        measured = self.outcome in {"detected", "missed", "unknown"}
        if self.active != tuple(sorted(set(self.active))):
            raise ValueError(
                "DVI-COUNTERFACTUAL-IDENTITY: active dimensions must be sorted and unique"
            )
        if measured != (
            self.observation is not None and self.match is not None and self.evaluation is not None
        ):
            raise ValueError("DVI-COUNTERFACTUAL-EVIDENCE: measured outcome needs an observation")
        if not measured and (
            self.observation is not None
            or self.match is not None
            or self.evaluation is not None
            or self.events
        ):
            raise ValueError(
                "DVI-COUNTERFACTUAL-EVIDENCE: unobserved row contains execution evidence"
            )
        if (
            self.match is not None
            and self.observation is not None
            and (
                self.match.case_id != self.case_id
                or self.observation.case_id != self.case_id
                or self.match.status != self.outcome
                or not self.events
                or self.rejections
            )
        ):
            raise ValueError("DVI-COUNTERFACTUAL-EVIDENCE: observation identity or outcome differs")
        if self.events and self.candidate_digest != digest(
            [e.model_dump(mode="json") for e in self.events]
        ):
            raise ValueError("DVI-COUNTERFACTUAL-DIGEST: candidate content changed")
        if (self.outcome == "invalid") != bool(self.rejections):
            raise ValueError("DVI-COUNTERFACTUAL-GATE: invalid rows need rejection evidence")
        if any(not step.preservation.valid for step in self.steps) or (
            self.steps
            and (
                self.steps[-1].output_digest != self.candidate_digest
                or any(
                    a.output_digest != b.input_digest
                    for a, b in zip(self.steps, self.steps[1:], strict=False)
                )
            )
        ):
            raise ValueError("DVI-COUNTERFACTUAL-TRACE: disconnected or rejected transformation")
        return self


class FailureSet(ValueModel):
    case_id: Identifier
    dimensions: Active
    status: Literal["minimal", "nonminimal", "unresolved"]
    proper_subset_cases: Annotated[tuple[Identifier, ...], Field(max_length=63)]
    smaller_missed_cases: Annotated[tuple[Identifier, ...], Field(max_length=63)]
    unresolved_cases: Annotated[tuple[Identifier, ...], Field(max_length=63)]
    explanation: NonEmpty


class EffectPair(ValueModel):
    without_case: Identifier
    with_case: Identifier
    input_changed: StrictBool
    miss_delta: Annotated[StrictInt, Field(ge=-1, le=1)]


class EffectEstimate(ValueModel):
    dimension: Identifier
    pairs: Annotated[tuple[EffectPair, ...], Field(max_length=32)]
    possible_pairs: Count
    unavailable_pairs: Count
    unchanged_input_pairs: Count
    loss_pairs: Count
    recovery_pairs: Count
    mean_miss_delta: Annotated[float, Field(ge=-1, le=1)] | None
    scope: Literal["descriptive_local_pairs"] = "descriptive_local_pairs"

    @model_validator(mode="after")
    def arithmetic(self) -> Self:
        changed = tuple(p for p in self.pairs if p.input_changed)
        lost = sum(p.miss_delta == 1 for p in changed)
        recovered = sum(p.miss_delta == -1 for p in changed)
        mean = (lost - recovered) / len(changed) if changed else None
        if (
            len(self.pairs) + self.unavailable_pairs != self.possible_pairs
            or self.unchanged_input_pairs != len(self.pairs) - len(changed)
            or self.loss_pairs != lost
            or self.recovery_pairs != recovered
            or self.mean_miss_delta != mean
        ):
            raise ValueError("DVI-COUNTERFACTUAL-EFFECT: denominators or paired arithmetic differ")
        return self


class CausalRanking(ValueModel):
    rank: Annotated[StrictInt, Field(ge=1, le=6)]
    dimension: CounterfactualDimension
    effect: EffectEstimate
    minimal_failure_cases: tuple[Identifier, ...]
    confidence: Literal[
        "verified_local_subset_controls", "partial_local_pairs", "insufficient_evidence"
    ]
    statement: NonEmpty


class CounterfactualFinding(ValueModel):
    case_id: Identifier
    necessary_dimensions: Active
    control_cases: tuple[Identifier, ...]
    confidence: Literal["verified_local_subset_controls"] = "verified_local_subset_controls"
    statement: NonEmpty


class CounterfactualSummary(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    input: CounterfactualInput | None
    state: Literal[
        "findings",
        "no_failure_observed",
        "incomplete",
        "baseline_not_detected",
        "unknown",
        "unsafe_rejected",
    ]
    cases: Annotated[tuple[CounterfactualCase, ...], Field(max_length=64)]
    covering_plan: CoveringArray | None
    executed_interactions: Count = 0
    unexecuted_cover_cases: tuple[Identifier, ...] = ()
    failure_sets: Annotated[tuple[FailureSet, ...], Field(max_length=63)]
    rankings: Annotated[tuple[CausalRanking, ...], Field(max_length=6)]
    findings: Annotated[tuple[CounterfactualFinding, ...], Field(max_length=63)]
    evaluations: Count
    evaluated_events: Count
    limitations: NonEmpty

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.input is None:
            if (
                self.cases
                or self.failure_sets
                or self.rankings
                or self.findings
                or self.covering_plan
                or self.evaluations
                or self.evaluated_events
                or self.state not in {"unknown", "unsafe_rejected"}
            ):
                raise ValueError("DVI-COUNTERFACTUAL-GATE: blocked input cannot export evidence")
            return self
        if self.input_digest != self.input.stable_digest() or any(
            c.input_digest != self.input_digest for c in self.cases
        ):
            raise ValueError("DVI-COUNTERFACTUAL-DIGEST: input reference differs")
        if (
            not self.cases
            or self.cases[0].active
            or len({c.case_id for c in self.cases}) != len(self.cases)
        ):
            raise ValueError("DVI-COUNTERFACTUAL-IDENTITY: baseline and unique cases required")
        measured = tuple(c for c in self.cases if c.observation is not None)
        if (
            self.evaluations != len(measured)
            or self.evaluated_events != sum(len(c.events) for c in measured)
            or sorted(c.evaluation for c in measured if c.evaluation is not None)
            != list(range(1, len(measured) + 1))
            or self.evaluations > self.input.budget.max_cases
            or self.evaluated_events > self.input.budget.max_events
        ):
            raise ValueError("DVI-COUNTERFACTUAL-BUDGET: evaluation accounting differs")
        if self.cases[0].outcome != "detected":
            if (
                len(self.cases) != 1
                or self.failure_sets
                or self.rankings
                or self.findings
                or self.covering_plan
                or self.state not in {"baseline_not_detected", "unknown"}
            ):
                raise ValueError(
                    "DVI-COUNTERFACTUAL-BASELINE: detected baseline required for mining"
                )
            return self
        names = tuple(d.name for d in self.input.dimensions)
        by_active = {c.active: c for c in self.cases}
        if tuple(c.active for c in self.cases) != subsets(names):
            raise ValueError("DVI-COUNTERFACTUAL-ACCOUNTING: every subset must appear once")
        if tuple(f.case_id for f in self.failure_sets) != tuple(
            c.case_id for c in self.cases if c.outcome == "missed"
        ):
            raise ValueError("DVI-COUNTERFACTUAL-FAILURE: every observed miss must be accounted")
        for failure in self.failure_sets:
            case = by_active.get(failure.dimensions)
            if case is None:
                raise ValueError("DVI-COUNTERFACTUAL-MINIMALITY: undeclared subset")
            controls = tuple(by_active[a] for a in subsets(failure.dimensions)[:-1])
            smaller = tuple(c.case_id for c in controls if c.outcome == "missed")
            unresolved = tuple(
                c.case_id for c in controls if c.outcome not in {"detected", "missed"}
            )
            expected = "nonminimal" if smaller else "unresolved" if unresolved else "minimal"
            if (
                case is None
                or case.case_id != failure.case_id
                or case.outcome != "missed"
                or failure.status != expected
                or failure.proper_subset_cases != tuple(c.case_id for c in controls)
                or failure.smaller_missed_cases != smaller
                or failure.unresolved_cases != unresolved
            ):
                raise ValueError("DVI-COUNTERFACTUAL-MINIMALITY: proper subset evidence differs")
        minimal = tuple(f for f in self.failure_sets if f.status == "minimal")
        if tuple(f.case_id for f in self.findings) != tuple(f.case_id for f in minimal):
            raise ValueError(
                "DVI-COUNTERFACTUAL-FINDING: only verified minimal sets support findings"
            )
        for finding, failure in zip(self.findings, minimal, strict=True):
            if (
                finding.necessary_dimensions != failure.dimensions
                or finding.control_cases != failure.proper_subset_cases
            ):
                raise ValueError("DVI-COUNTERFACTUAL-FINDING: necessity differs from controls")
        if tuple(r.rank for r in self.rankings) != tuple(range(1, len(names) + 1)) or {
            r.dimension.name for r in self.rankings
        } != set(names):
            raise ValueError("DVI-COUNTERFACTUAL-RANKING: every dimension must be ranked once")
        for ranking in self.rankings:
            dimension = ranking.dimension
            if dimension not in self.input.dimensions or ranking.effect.dimension != dimension.name:
                raise ValueError("DVI-COUNTERFACTUAL-RANKING: dimension reference differs")
            contrasts = []
            alternatives = subsets(tuple(n for n in names if n != dimension.name))
            for active in alternatives:
                a = by_active[active]
                b = by_active[tuple(sorted((*active, dimension.name)))]
                if a.outcome in {"detected", "missed"} and b.outcome in {"detected", "missed"}:
                    contrasts.append(
                        EffectPair(
                            without_case=a.case_id,
                            with_case=b.case_id,
                            input_changed=a.candidate_digest != b.candidate_digest,
                            miss_delta=int(b.outcome == "missed") - int(a.outcome == "missed"),
                        )
                    )
            necessary = tuple(f.case_id for f in minimal if dimension.name in f.dimensions)
            confidence = (
                "verified_local_subset_controls"
                if necessary
                else "partial_local_pairs"
                if any(p.input_changed for p in contrasts)
                else "insufficient_evidence"
            )
            if (
                ranking.effect.possible_pairs != len(alternatives)
                or ranking.effect.pairs != tuple(contrasts)
                or ranking.minimal_failure_cases != necessary
                or ranking.confidence != confidence
            ):
                raise ValueError(
                    "DVI-COUNTERFACTUAL-EFFECT: ranking differs from measured controls"
                )
        original_digest = digest([e.model_dump(mode="json") for e in self.input.events])
        for case in measured:
            start = case.steps[0].input_digest if case.steps else case.candidate_digest
            if start != original_digest:
                raise ValueError("DVI-COUNTERFACTUAL-TRACE: candidate belongs to another baseline")
        if self.covering_plan is not None:
            options = {d.name: d.operation for d in self.input.dimensions}
            unexecuted = []
            for assignment in self.covering_plan.rows:
                if tuple(t.parameter for t in assignment) != names or any(
                    t.option not in {"none", options[t.parameter]} for t in assignment
                ):
                    raise ValueError("DVI-COUNTERFACTUAL-COVERAGE: invalid planned assignment")
                case = by_active[tuple(t.parameter for t in assignment if t.option != "none")]
                if case.observation is None:
                    unexecuted.append(case.case_id)
            interactions = set().union(
                *(
                    set(
                        combinations(
                            tuple((n, options[n] if n in c.active else "none") for n in names),
                            self.covering_plan.strength,
                        )
                    )
                    for c in measured
                )
            )
            if self.executed_interactions != len(
                interactions
            ) or self.unexecuted_cover_cases != tuple(unexecuted):
                raise ValueError("DVI-COUNTERFACTUAL-COVERAGE: executed coverage differs")
        elif len(names) != 1 or self.executed_interactions or self.unexecuted_cover_cases:
            raise ValueError("DVI-COUNTERFACTUAL-COVERAGE: combination plan required")
        incomplete = (
            bool(self.unexecuted_cover_cases)
            or any(
                c.outcome in {"unknown", "invalid"}
                or (c.outcome == "not_evaluated" and c.stage != "not_selected")
                for c in self.cases
            )
            or any(f.status == "unresolved" for f in self.failure_sets)
            or (self.covering_plan is not None and self.covering_plan.state != "complete")
        )
        state = (
            "incomplete" if incomplete else "findings" if self.findings else "no_failure_observed"
        )
        if self.state != state:
            raise ValueError("DVI-COUNTERFACTUAL-STATE: report state differs from evidence")
        return self


class FailureAnalysis(ValueModel):
    input_digest: Sha256
    sets: tuple[FailureSet, ...]
    findings: tuple[CounterfactualFinding, ...]


class CausalRankings(ValueModel):
    input_digest: Sha256
    rankings: tuple[CausalRanking, ...]
    limitations: NonEmpty
