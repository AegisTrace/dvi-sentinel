"""Bounded inputs and linked evidence for opt-in oracle-aware V1 reduction (D)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from dvi_sentinel.harness_models import RuleHarnessConfig
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.oracle_consensus import build_consensus
from dvi_sentinel.oracle_models import OracleConsensus
from dvi_sentinel.probe_models import ProbeSpec
from dvi_sentinel.reductions import (
    changed_classes,
    reduction_cost,
    surviving_originals,
    validate_reduction,
)
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.score_models import FragilityClass
from dvi_sentinel.serialization import canonical_json, digest
from dvi_sentinel.taxonomy import PROBE_CLASSES, VARIATION_CLASSES
from dvi_sentinel.variation_models import EventLineage, SemanticPreservationResult, VariationCase

Cost = tuple[
    Annotated[StrictInt, Field(ge=0)],
    Annotated[StrictInt, Field(ge=0)],
    Annotated[StrictInt, Field(ge=0)],
]
Decision = Literal["accepted", "rejected", "invalid", "unknown", "budget_exhausted"]


def event_digest(events: tuple[TelemetryEvent, ...]) -> str:
    return digest([event.model_dump(mode="json") for event in events])


def consensus_signature(consensus: OracleConsensus) -> str:
    """Ignore content-specific links, never the measured decision/confidence/reasons."""
    return digest(
        {
            "state": consensus.state,
            "confidence": consensus.confidence,
            "decisions": [
                [row.oracle_id, row.decision, row.confidence, list(row.reason_codes)]
                for row in consensus.decisions
            ],
        }
    )


class OracleShrinkBudget(ValueModel):
    max_attempts: Annotated[StrictInt, Field(ge=0, le=128)] = 128
    max_evaluations: Annotated[StrictInt, Field(ge=0, le=258)] = 258
    max_events: Annotated[StrictInt, Field(ge=0, le=4096)] = 4096


class OracleShrinkInput(ValueModel):
    original: Annotated[tuple[TelemetryEvent, ...], Field(min_length=1, max_length=16)]
    case: VariationCase
    policy: VariationPolicy
    expected: DetectionExpectation
    harness: RuleHarnessConfig
    protected_event_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=16)]
    probe: ProbeSpec | None = None
    precision_digits: Annotated[StrictInt, Field(ge=0, le=6)] = 0
    budget: OracleShrinkBudget = OracleShrinkBudget()

    @field_validator("protected_event_ids")
    @classmethod
    def ordered_ids(cls, ids: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(ids)) != len(ids):
            raise ValueError("DVI-SHRINK-IDENTITY: duplicate protected ID")
        return tuple(sorted(ids))

    @field_validator("policy")
    @classmethod
    def ordered_policy(cls, policy: VariationPolicy) -> VariationPolicy:
        return policy.model_copy(
            update={
                "families": tuple(sorted(policy.families)),
                "optional_fields": tuple(sorted(policy.optional_fields)),
            }
        )

    @field_validator("harness")
    @classmethod
    def ordered_rules(cls, harness: RuleHarnessConfig) -> RuleHarnessConfig:
        if len(harness.rules) > 8:
            raise ValueError("DVI-SHRINK-BOUNDS: at most eight local rules")
        return harness.model_copy(
            update={"rules": tuple(sorted(harness.rules, key=lambda r: r.id))}
        )

    @model_validator(mode="after")
    def bounded(self) -> Self:
        ids = {event.event_id for event in self.original}
        if len(ids) != len(self.original) or not set(self.protected_event_ids) <= ids:
            raise ValueError(
                "DVI-SHRINK-IDENTITY: require unique originals and known protected IDs"
            )
        if not set(self.expected.event_ids) <= set(self.protected_event_ids):
            raise ValueError("DVI-SHRINK-IDENTITY: expectation event IDs must be protected")
        if not 1 <= len(self.case.events) <= 64 or len(self.case.lineage) > 64:
            raise ValueError(
                "DVI-SHRINK-BOUNDS: require 1..64 candidate events and at most 64 refs"
            )
        if self.case.family not in VARIATION_CLASSES or (
            self.probe and self.probe.finding_class not in PROBE_CLASSES
        ):
            raise ValueError("DVI-SHRINK-CLASS: require a supported variation/probe class")
        if len(canonical_json(self).encode("utf-8")) > 262_144:
            raise ValueError("DVI-SHRINK-BOUNDS: complete input exceeds 256 KiB")
        return self

    @property
    def finding_class(self) -> FragilityClass:
        return (
            PROBE_CLASSES[self.probe.finding_class]
            if self.probe
            else VARIATION_CLASSES[self.case.family]
        )


class ShrinkMeasurement(ValueModel):
    evaluation: Annotated[StrictInt, Field(ge=1, le=258)]
    events_digest: Sha256
    match: MatchResult
    consensus: OracleConsensus

    @model_validator(mode="after")
    def linked(self) -> Self:
        evidence = self.consensus.evidence
        if (
            evidence is None
            or evidence.observation is None
            or self.match.case_id != self.consensus.subject_id
            or self.events_digest != event_digest(evidence.events)
        ):
            raise ValueError("DVI-SHRINK-EVIDENCE: measurement needs linked actual observations")
        if evidence.expected is None or self.match != match_detection(
            evidence.expected, evidence.observation, evidence.events
        ):
            raise ValueError("DVI-SHRINK-MATCH: matcher evidence differs from observation")
        rebuilt = build_consensus(self.consensus.decisions)
        if rebuilt.model_dump(exclude={"evidence"}) != self.consensus.model_dump(
            exclude={"evidence"}
        ):
            raise ValueError("DVI-SHRINK-CONSENSUS: consensus differs from oracle decisions")
        return self

    @property
    def events(self) -> tuple[TelemetryEvent, ...]:
        assert self.consensus.evidence is not None
        return self.consensus.evidence.events


class OracleShrinkAttempt(ValueModel):
    attempt: Annotated[StrictInt, Field(ge=1, le=128)]
    reduction: NonEmpty
    parent_digest: Sha256
    candidate_digest: Sha256
    cost: Cost
    lineage: Annotated[tuple[EventLineage, ...], Field(max_length=64)]
    preservation: SemanticPreservationResult
    changed_classes: tuple[FragilityClass, ...]
    decision: Decision
    reason: NonEmpty
    baseline: ShrinkMeasurement | None = None
    candidate: ShrinkMeasurement | None = None

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.candidate and self.candidate.events_digest != self.candidate_digest:
            raise ValueError("DVI-SHRINK-TRACE: candidate measurement differs from proposal")
        if not self.preservation.valid and (self.baseline or self.candidate):
            raise ValueError("DVI-SHRINK-TRACE: invalid proposal reached measurement")
        if self.decision == "accepted" and (
            not self.preservation.valid
            or self.baseline is None
            or self.baseline.match.status != "detected"
            or self.candidate is None
            or self.candidate.match.status != "missed"
            or self.candidate.consensus.state != "confirmed"
        ):
            raise ValueError("DVI-SHRINK-TRACE: accepted proposal needs resolved controls")
        return self


class OracleShrinkReport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    input: OracleShrinkInput | None
    state: Literal[
        "minimized", "budget_exhausted", "not_a_failure", "unknown", "invalid", "unsafe_rejected"
    ]
    baseline: ShrinkMeasurement | None = None
    initial: ShrinkMeasurement | None = None
    final: ShrinkMeasurement | None = None
    final_lineage: tuple[EventLineage, ...] = ()
    trace: Annotated[tuple[OracleShrinkAttempt, ...], Field(max_length=128)] = ()
    evaluations: Annotated[StrictInt, Field(ge=0, le=258)] = 0
    evaluated_events: Annotated[StrictInt, Field(ge=0, le=4096)] = 0
    pending_reduction: NonEmpty | None = None
    explanation: NonEmpty
    minimality: Literal[
        "Local minimum under supported reductions only; no global minimum or universal cause claim"
    ] = "Local minimum under supported reductions only; no global minimum or universal cause claim"

    @model_validator(mode="after")
    def linked(self) -> Self:
        if self.input is None:
            if (
                self.state not in {"unknown", "unsafe_rejected"}
                or self.baseline
                or self.initial
                or self.final
                or self.trace
                or self.evaluations
                or self.evaluated_events
                or self.final_lineage
            ):
                raise ValueError("DVI-SHRINK-BLOCKED: blocked input cannot contain evidence")
            return self
        request = self.input
        if self.input_digest != request.stable_digest():
            raise ValueError("DVI-SHRINK-DIGEST: input differs from retained pin")
        if (
            len(self.trace) > request.budget.max_attempts
            or self.evaluations > request.budget.max_evaluations
            or self.evaluated_events > request.budget.max_events
        ):
            raise ValueError("DVI-SHRINK-BUDGET: reported work exceeds configured budget")
        measured: dict[int, ShrinkMeasurement] = {}
        observations = [self.baseline, self.initial, self.final]
        observations.extend(
            value for step in self.trace for value in (step.baseline, step.candidate)
        )
        for row in observations:
            if row is not None:
                if row.evaluation in measured and measured[row.evaluation] != row:
                    raise ValueError("DVI-SHRINK-CACHE: conflicting cached observation")
                measured[row.evaluation] = row
                assert row.consensus.evidence is not None
                if row.consensus.evidence.expected != request.expected:
                    raise ValueError("DVI-SHRINK-EXPECTATION: observation uses another expectation")
        if (
            sorted(measured) != list(range(1, self.evaluations + 1))
            or sum(len(row.events) for row in measured.values()) != self.evaluated_events
        ):
            raise ValueError("DVI-SHRINK-ACCOUNTING: actual evaluation counts differ")
        if len({row.events_digest for row in measured.values()}) != len(measured):
            raise ValueError("DVI-SHRINK-CACHE: repeated content was evaluated twice")
        if self.baseline and self.baseline.events_digest != event_digest(request.original):
            raise ValueError("DVI-SHRINK-BASELINE: original baseline content differs")
        if self.initial and self.initial.events_digest != event_digest(request.case.events):
            raise ValueError("DVI-SHRINK-INITIAL: initial observation content differs")
        current = self.initial
        lineage = request.case.lineage if current else ()
        for index, step in enumerate(self.trace, 1):
            if (
                current is None
                or step.attempt != index
                or step.parent_digest != current.events_digest
            ):
                raise ValueError("DVI-SHRINK-TRACE: reduction chain is disconnected")
            if step.decision in {"unknown", "budget_exhausted"} and index != len(self.trace):
                raise ValueError("DVI-SHRINK-TRACE: work continued after uncertainty or exhaustion")
            scope = surviving_originals(request.original, step.lineage)
            if step.baseline and step.baseline.events != scope:
                raise ValueError(
                    "DVI-SHRINK-CONTROL: measured baseline differs from retained scope"
                )
            if step.candidate and (
                not validate_reduction(
                    scope,
                    step.candidate.events,
                    step.lineage,
                    request.policy,
                    request.case.family,
                    request.probe,
                ).valid
                or step.cost
                != reduction_cost(request.original, step.candidate.events, step.lineage)
                or step.changed_classes
                != changed_classes(
                    request.original,
                    step.candidate.events,
                    step.lineage,
                    request.case.family,
                    request.probe,
                )
            ):
                raise ValueError("DVI-SHRINK-COST: cost/classes differ from actual candidate")
            if step.decision == "accepted":
                assert step.candidate is not None and self.initial is not None
                if (
                    request.finding_class not in step.changed_classes
                    or step.candidate.match.reason != self.initial.match.reason
                    or consensus_signature(step.candidate.consensus)
                    != consensus_signature(self.initial.consensus)
                    or step.cost >= reduction_cost(request.original, current.events, lineage)
                    or not set(request.protected_event_ids) <= {e.event_id for e in scope}
                    or not validate_reduction(
                        scope,
                        step.candidate.events,
                        step.lineage,
                        request.policy,
                        request.case.family,
                        request.probe,
                    ).valid
                ):
                    raise ValueError(
                        "DVI-SHRINK-PRESERVATION: accepted reduction changed the finding"
                    )
                current, lineage = step.candidate, step.lineage
        if self.final != current or self.final_lineage != lineage:
            raise ValueError("DVI-SHRINK-FINAL: retained result differs from accepted trace")
        if self.state == "minimized" and (
            self.baseline is None
            or self.baseline.match.status != "detected"
            or self.initial is None
            or self.initial.match.status != "missed"
            or self.initial.consensus.state != "confirmed"
            or self.pending_reduction is not None
            or any(step.decision in {"unknown", "budget_exhausted"} for step in self.trace)
        ):
            raise ValueError("DVI-SHRINK-MINIMUM: minimum claim lacks resolved evidence")
        if self.state == "budget_exhausted" and self.pending_reduction is None:
            raise ValueError("DVI-SHRINK-BUDGET: exhausted result needs a pending reduction")
        return self


class OraclePreservationRow(ValueModel):
    attempt: Annotated[StrictInt, Field(ge=1, le=128)]
    candidate_digest: Sha256
    decision: Decision
    measured_signature: Sha256 | None
    preserved: StrictBool | None


class OraclePreservation(ValueModel):
    input_digest: Sha256
    initial: OracleConsensus | None
    final: OracleConsensus | None
    attempts: tuple[OraclePreservationRow, ...]
