"""Bounded reduction traces, minimum claims, and fixture-local ablation evidence."""

from typing import Literal

from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, TelemetryEvent, ValueModel
from dvi_sentinel.probe_models import ProbeSpec
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.score_models import FragilityClass
from dvi_sentinel.variation_models import EventLineage, SemanticPreservationResult


class ShrinkTrace(ValueModel):
    attempt: int
    reduction: NonEmpty
    input_digest: Sha256
    decision: Literal["accepted", "rejected", "invalid", "unknown"]
    preservation: SemanticPreservationResult
    match: MatchResult | None


class AblationResult(ValueModel):
    reduction: NonEmpty
    association: Literal[
        "necessary_in_fixture", "failure_persists", "different_failure", "unknown", "invalid"
    ]
    match: MatchResult | None
    input_digest: Sha256


class RootCauseReport(ValueModel):
    status: Literal["measured", "not_applicable", "unknown"]
    ranked: tuple[AblationResult, ...] = ()
    budget_exhausted: bool = False
    rationale: NonEmpty = (
        "Necessity is conditional on this fixture and tested ablations; no universal causality"
    )


class MinimalCounterexample(ValueModel):
    schema_version: Literal["1"] = "1"
    original_case_id: Identifier
    original_events: tuple[TelemetryEvent, ...]
    policy: VariationPolicy
    expected: DetectionExpectation
    probe: ProbeSpec | None = None
    finding_class: FragilityClass
    status: Literal["minimized", "budget_exhausted", "not_a_failure", "unknown", "invalid"]
    baseline: MatchResult
    initial: MatchResult | None
    final: MatchResult | None
    events: tuple[TelemetryEvent, ...]
    lineage: tuple[EventLineage, ...]
    preservation: SemanticPreservationResult
    trace: tuple[ShrinkTrace, ...] = ()
    root_cause: RootCauseReport
    minimality: NonEmpty = "Local minimum under supported reductions only; no global minimum claim"
