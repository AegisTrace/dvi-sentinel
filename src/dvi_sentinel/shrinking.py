"""Conservative failure reduction and bounded fixture-local causal ablation."""

from dvi_sentinel.harness import DetectorHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.probe_models import ProbeSpec
from dvi_sentinel.reductions import SOURCE_PROBES, reductions, validate_reduction
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json, digest
from dvi_sentinel.shrinking_models import (
    AblationResult,
    MinimalCounterexample,
    RootCauseReport,
    ShrinkTrace,
)
from dvi_sentinel.taxonomy import PROBE_CLASSES, VARIATION_CLASSES
from dvi_sentinel.variation_models import (
    MetamorphicInvariant,
    SemanticPreservationResult,
    VariationCase,
)


class RootCauseRanker:
    """Rank observed necessity first, retaining unknown and invalid ablations."""

    @staticmethod
    def rank(results: tuple[AblationResult, ...], *, budget_exhausted: bool) -> RootCauseReport:
        order = {
            "necessary_in_fixture": 0,
            "different_failure": 1,
            "failure_persists": 2,
            "unknown": 3,
            "invalid": 4,
        }
        return RootCauseReport(
            status="measured"
            if any(
                r.association in {"necessary_in_fixture", "failure_persists", "different_failure"}
                for r in results
            )
            else "unknown"
            if results or budget_exhausted
            else "not_applicable",
            ranked=tuple(
                sorted(results, key=lambda result: (order[result.association], result.reduction))
            ),
            budget_exhausted=budget_exhausted,
        )


class FailureShrinker:
    def __init__(self, harness: DetectorHarness) -> None:
        self.harness = harness

    def shrink(
        self,
        original: tuple[TelemetryEvent, ...],
        case: VariationCase,
        policy: VariationPolicy,
        expected: DetectionExpectation,
        *,
        probe: ProbeSpec | None = None,
        max_attempts: int = 128,
        max_ablations: int = 32,
    ) -> MinimalCounterexample:
        if any(
            type(value) is not int or not 0 <= value <= 512
            for value in (max_attempts, max_ablations)
        ):
            raise ValueError("DVI-SHRINK-BUDGET: budgets must be integers in 0..512")
        if (
            not original
            or len(original) > 10_000
            or len({e.event_id for e in original}) != len(original)
        ):
            raise ValueError("DVI-SHRINK-INPUT: require 1..10000 unique original events")
        if case.family not in VARIATION_CLASSES and probe is None:
            raise ValueError("DVI-SHRINK-FAMILY: baseline has no transformation to shrink")
        finding_class = (
            PROBE_CLASSES[probe.finding_class] if probe else VARIATION_CLASSES[case.family]
        )
        representation = probe is not None and probe.name in SOURCE_PROBES
        baseline = match_detection(
            expected,
            self.harness.evaluate(
                HarnessRequest(
                    case_id="baseline",
                    events=original,
                )
            ),
            original,
        )
        preservation = validate_reduction(
            original, case.events, case.lineage, policy, case.family, probe
        )
        preservation = SemanticPreservationResult(
            checks=(
                *preservation.checks,
                MetamorphicInvariant(
                    id="DVI-INV-CHANGE",
                    passed=case.events != original,
                    explanation="An assumption failure requires a nontrivial counterfactual",
                ),
            )
        )
        initial = (
            match_detection(
                expected,
                self.harness.evaluate(
                    HarnessRequest(
                        case_id=case.id,
                        events=case.events,
                    )
                ),
                case.events,
                preservation=preservation,
            )
            if preservation.valid
            else None
        )
        result = MinimalCounterexample(
            original_case_id=case.id,
            original_events=original,
            policy=policy,
            expected=expected,
            probe=probe,
            finding_class=finding_class,
            status="invalid"
            if not preservation.valid
            else "unknown"
            if baseline.status != "detected" or initial is None or initial.status == "unknown"
            else "not_a_failure"
            if initial.status != "missed"
            else "minimized",
            baseline=baseline,
            initial=initial,
            final=initial,
            events=case.events,
            lineage=case.lineage,
            preservation=preservation,
            root_cause=RootCauseReport(status="not_applicable"),
        )
        if result.status != "minimized" or initial is None:
            return result

        def observe(
            candidate: tuple[TelemetryEvent, ...], valid: SemanticPreservationResult, key: str
        ) -> MatchResult | None:
            if not valid.valid:
                return None
            if candidate == original:
                return baseline
            return match_detection(
                expected,
                self.harness.evaluate(
                    HarnessRequest(
                        case_id=f"shrink:{key[:24]}",
                        events=candidate,
                    )
                ),
                candidate,
                preservation=valid,
            )

        events, lineage = case.events, case.lineage
        trace: list[ShrinkTrace] = []
        seen = {digest([event.model_dump(mode="json") for event in events]): "accepted"}
        exhausted = False
        final = initial
        while True:
            accepted = False
            unresolved = False
            for label, candidate, refs in reductions(
                original, events, lineage, case.family, policy, representation=representation
            ):
                key = digest([event.model_dump(mode="json") for event in candidate])
                if key in seen:
                    unresolved |= seen[key] == "unknown"
                    continue
                if len(trace) >= max_attempts:
                    exhausted = True
                    break
                valid = validate_reduction(original, candidate, refs, policy, case.family, probe)
                matched = observe(candidate, valid, key)
                keeps_failure = (
                    matched is not None
                    and matched.status == "missed"
                    and matched.reason == initial.reason
                )
                trace.append(
                    ShrinkTrace(
                        attempt=len(trace) + 1,
                        reduction=label,
                        input_digest=key,
                        preservation=valid,
                        match=matched,
                        decision="invalid"
                        if not valid.valid
                        else "unknown"
                        if matched is None or matched.status == "unknown"
                        else "accepted"
                        if keeps_failure
                        else "rejected",
                    )
                )
                seen[key] = trace[-1].decision
                unresolved |= trace[-1].decision == "unknown"
                if keeps_failure and matched:
                    events, lineage, preservation, final = candidate, refs, valid, matched
                    accepted = True
                    break
            if exhausted or not accepted:
                break
        ablations: list[AblationResult] = []
        ablation_exhausted = False
        for label, candidate, refs in reductions(
            original,
            events,
            lineage,
            case.family,
            policy,
            representation=representation,
            ablation=True,
        ):
            if len(ablations) >= max_ablations:
                ablation_exhausted = True
                break
            key = digest([event.model_dump(mode="json") for event in candidate])
            valid = validate_reduction(original, candidate, refs, policy, case.family, probe)
            matched = observe(candidate, valid, key)
            ablations.append(
                AblationResult(
                    reduction=label,
                    input_digest=key,
                    match=matched,
                    association="invalid"
                    if not valid.valid
                    else "unknown"
                    if matched is None or matched.status == "unknown"
                    else "necessary_in_fixture"
                    if matched.status == "detected"
                    else "failure_persists"
                    if matched.reason == initial.reason
                    else "different_failure",
                )
            )
        return MinimalCounterexample.model_validate(
            result.model_dump()
            | {
                "status": "budget_exhausted"
                if exhausted
                else "unknown"
                if unresolved
                else "minimized",
                "events": events,
                "lineage": lineage,
                "preservation": preservation,
                "final": final,
                "trace": tuple(trace),
                "root_cause": RootCauseRanker.rank(
                    tuple(ablations), budget_exhausted=ablation_exhausted
                ),
            }
        )


def shrink_artifacts(result: MinimalCounterexample) -> dict[str, str]:
    return {
        "minimal_case.json": canonical_json(result) + "\n",
        "minimal_case.md": f"# Minimal counterexample\n\nStatus: {result.status}\n\n"
        f"Class: {result.finding_class}\n\nEvents retained: {len(result.events)}\n\n"
        f"{result.minimality}\n\n{result.root_cause.rationale}\n",
        "shrinking_trace.jsonl": "".join(canonical_json(step) + "\n" for step in result.trace),
        "root_cause.json": canonical_json(result.root_cause) + "\n",
    }
