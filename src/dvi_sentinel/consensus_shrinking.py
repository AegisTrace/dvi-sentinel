"""Oracle-aware extension of V1 local reduction proposals and independent checks (A)."""

from dvi_sentinel.artifact_models import MAX_ARTIFACT_BYTES
from dvi_sentinel.consensus_shrinking_models import (
    OraclePreservation,
    OraclePreservationRow,
    OracleShrinkAttempt,
    OracleShrinkInput,
    OracleShrinkReport,
    ShrinkMeasurement,
    consensus_signature,
    event_digest,
)
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.ontology import extract_signal
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_consensus import build_consensus
from dvi_sentinel.oracle_models import OracleConsensus, OracleEvidence
from dvi_sentinel.policy import PolicyError, evaluate_events, inspect_content
from dvi_sentinel.reductions import (
    SOURCE_PROBES,
    changed_classes,
    reduction_cost,
    scoped_reductions,
    surviving_originals,
    validate_reduction,
)
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes
from dvi_sentinel.serialization import digest
from dvi_sentinel.variation_models import (
    EventLineage,
    MetamorphicInvariant,
    SemanticPreservationResult,
)


def _validate(
    request: OracleShrinkInput,
    events: tuple[TelemetryEvent, ...],
    lineage: tuple[EventLineage, ...],
    *,
    initial: bool = False,
) -> SemanticPreservationResult:
    scope = request.original if initial else surviving_originals(request.original, lineage)
    checked = validate_reduction(
        scope, events, lineage, request.policy, request.case.family, request.probe
    )
    protected = set(request.protected_event_ids)
    return SemanticPreservationResult(
        checks=(
            *checked.checks,
            MetamorphicInvariant(
                id="DVI-SHRINK-PROTECTED",
                passed=bool(scope)
                and protected <= {e.event_id for e in scope}
                and protected <= {e.event_id for e in events},
                explanation="All protected and expected original event identities survive",
            ),
        )
    )


def _known(events: tuple[TelemetryEvent, ...]) -> bool:
    return all(not extract_signal(event).findings for event in events)


def shrink_with_oracles(
    request: OracleShrinkInput, *, expected_digest: str | None = None
) -> OracleShrinkReport:
    """Remeasure bounded declarative rules; never accept supplied oracle votes as proof."""
    request = OracleShrinkInput.model_validate(request.model_dump(mode="python"))
    fingerprint = request.stable_digest()
    if expected_digest != fingerprint:
        return OracleShrinkReport(
            input_digest=fingerprint,
            input=None,
            state="unknown" if expected_digest is None else "unsafe_rejected",
            explanation="A matching pinned complete input digest is required before consumption.",
        )
    try:
        unsafe = evaluate_events((*request.original, *request.case.events)) or inspect_content(
            {
                "harness": request.harness.model_dump(mode="json"),
                "expected": request.expected.model_dump(mode="json"),
            }
        )
    except PolicyError as exc:
        unsafe = exc.decisions
    if unsafe:
        return OracleShrinkReport(
            input_digest=fingerprint,
            input=None,
            state="unsafe_rejected",
            explanation="Structural fixture policy rejected input before any detector evaluation.",
        )

    harness = RuleLogicHarness(request.harness)
    cache: dict[str, ShrinkMeasurement] = {}
    evaluated_events = 0
    trace: list[OracleShrinkAttempt] = []
    baseline: ShrinkMeasurement | None = None
    initial: ShrinkMeasurement | None = None
    current: ShrinkMeasurement | None = None
    lineage: tuple[EventLineage, ...] = ()

    def finish(state: str, explanation: str, pending: str | None = None) -> OracleShrinkReport:
        return OracleShrinkReport.model_validate(
            {
                "input_digest": fingerprint,
                "input": request,
                "state": state,
                "baseline": baseline,
                "initial": initial,
                "final": current,
                "final_lineage": lineage,
                "trace": tuple(trace),
                "evaluations": len(cache),
                "evaluated_events": evaluated_events,
                "pending_reduction": pending,
                "explanation": explanation,
            }
        )

    def measure(events: tuple[TelemetryEvent, ...]) -> ShrinkMeasurement | None:
        nonlocal evaluated_events
        key = event_digest(events)
        if key in cache:
            return cache[key]
        if (
            len(cache) >= request.budget.max_evaluations
            or evaluated_events + len(events) > request.budget.max_events
        ):
            return None
        subject = "shrink:" + digest({"input": fingerprint, "events": key})[:24]
        observed = harness.evaluate(HarnessRequest(case_id=subject, events=events))
        matched = match_detection(request.expected, observed, events)
        evidence = OracleEvidence(
            subject_id=subject,
            events=events,
            expected=request.expected,
            observation=observed,
            precision_digits=request.precision_digits,
        )
        consensus = build_consensus(
            evaluate_oracles(evidence, expected_digest=evidence.stable_digest())
        )
        if consensus.blocking_oracles:
            # The fixed local harness should never produce unsafe evidence. Fail closed
            # rather than retaining rejected detector content in an exported report.
            raise ValueError("DVI-SHRINK-OBSERVATION: oracle integrity rejected detector output")
        row = ShrinkMeasurement(
            evaluation=len(cache) + 1,
            events_digest=key,
            match=matched,
            consensus=OracleConsensus.model_validate(
                consensus.model_dump(mode="python") | {"evidence": evidence}
            ),
        )
        cache[key] = row
        evaluated_events += len(events)
        return row

    valid = _validate(request, request.case.events, request.case.lineage, initial=True)
    if not valid.valid:
        return finish(
            "invalid", "Initial candidate fails independent V1/protected-event invariants."
        )
    if request.finding_class not in changed_classes(
        request.original,
        request.case.events,
        request.case.lineage,
        request.case.family,
        request.probe,
    ):
        return finish("invalid", "No actual change supports the declared finding class.")
    if not _known((*request.original, *request.case.events)):
        return finish("unknown", "Initial semantic evidence is unresolved; consumption stopped.")
    baseline = measure(request.original)
    if baseline is None:
        return finish(
            "budget_exhausted", "Baseline evaluation exceeds the shared budget.", "baseline"
        )
    if baseline.match.status != "detected":
        return finish(
            "unknown" if baseline.match.status == "unknown" else "not_a_failure",
            "The original baseline must be a measured detection.",
        )
    if baseline.consensus.state != "suppressed_false_positive":
        return finish("unknown", "Baseline oracle evidence is unresolved or disagrees; stopped.")
    initial = current = measure(request.case.events)
    if initial is None:
        return finish(
            "budget_exhausted", "Initial evaluation exceeds the shared budget.", "initial"
        )
    lineage = request.case.lineage
    if initial.match.status == "detected":
        return finish("not_a_failure", "The initial candidate retains the expected detection.")
    if initial.match.status != "missed" or initial.consensus.state != "confirmed":
        return finish("unknown", "Initial failure lacks confirmed oracle consensus; stopped.")

    representation = request.probe is not None and request.probe.name in SOURCE_PROBES
    while True:
        assert current is not None
        accepted = False
        cost = reduction_cost(request.original, current.events, lineage)
        proposed: set[str] = set()
        for label, events, refs in scoped_reductions(
            request.original,
            current.events,
            lineage,
            request.case.family,
            request.policy,
            request.protected_event_ids,
            representation=representation,
        ):
            key = event_digest(events)
            if key in proposed:
                continue
            proposed.add(key)
            if len(trace) >= request.budget.max_attempts:
                return finish(
                    "budget_exhausted", "Attempt budget exhausted before next proposal.", label
                )
            valid = _validate(request, events, refs)
            classes = (
                changed_classes(request.original, events, refs, request.case.family, request.probe)
                if valid.valid
                else ()
            )
            after_cost = reduction_cost(request.original, events, refs)
            control = candidate = None
            decision = "invalid"
            reason = "Independent semantic, safety or protected-event invariant rejected proposal."
            if valid.valid:
                if after_cost >= cost:
                    decision, reason = "rejected", "Proposal does not strictly simplify the case."
                elif request.finding_class not in classes:
                    decision, reason = "rejected", "The declared finding class would disappear."
                elif not _known(events):
                    decision, reason = "unknown", "Semantic evidence is unresolved; stopped."
                else:
                    control = measure(surviving_originals(request.original, refs))
                    if control is None:
                        decision, reason = "budget_exhausted", "Baseline control exceeds budget."
                    elif control.consensus.state not in {"confirmed", "suppressed_false_positive"}:
                        decision, reason = (
                            "unknown",
                            "Baseline oracle evidence is unresolved; stopped.",
                        )
                    elif control.match.status != "detected":
                        decision, reason = "rejected", "Surviving baseline no longer detects."
                    else:
                        candidate = measure(events)
                        if candidate is None:
                            decision, reason = (
                                "budget_exhausted",
                                "Candidate evaluation exceeds budget.",
                            )
                        elif candidate.consensus.state not in {
                            "confirmed",
                            "suppressed_false_positive",
                        }:
                            decision, reason = (
                                "unknown",
                                "Candidate oracle evidence is unresolved; stopped.",
                            )
                        elif candidate.match.status != "missed":
                            decision, reason = "rejected", "Expected detection was restored."
                        elif candidate.match.reason != initial.match.reason:
                            decision, reason = "rejected", "Matcher failure class/reason changed."
                        elif consensus_signature(candidate.consensus) != consensus_signature(
                            initial.consensus
                        ):
                            decision, reason = (
                                "rejected",
                                "Oracle decisions, confidence or reasons changed.",
                            )
                        else:
                            decision, reason = (
                                "accepted",
                                "Semantics, finding and oracle consensus preserved.",
                            )
            step = OracleShrinkAttempt.model_validate(
                {
                    "attempt": len(trace) + 1,
                    "reduction": label,
                    "parent_digest": current.events_digest,
                    "candidate_digest": key,
                    "cost": after_cost,
                    "lineage": refs,
                    "preservation": valid,
                    "changed_classes": classes,
                    "decision": decision,
                    "reason": reason,
                    "baseline": control,
                    "candidate": candidate,
                }
            )
            trace.append(step)
            if decision == "unknown":
                return finish("unknown", reason)
            if decision == "budget_exhausted":
                return finish("budget_exhausted", reason, label)
            if decision == "accepted":
                assert candidate is not None
                current, lineage, accepted = candidate, refs, True
                break
        if not accepted:
            return finish(
                "minimized", "No supported simplifying proposal preserves the confirmed finding."
            )


def oracle_shrink_artifacts(
    request: OracleShrinkInput, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    report = shrink_with_oracles(request, expected_digest=expected_digest)
    initial = report.initial.consensus if report.initial else None
    final = report.final.consensus if report.final else None
    preservation = OraclePreservation(
        input_digest=report.input_digest,
        initial=initial,
        final=final,
        attempts=tuple(
            OraclePreservationRow(
                attempt=step.attempt,
                candidate_digest=step.candidate_digest,
                decision=step.decision,
                measured_signature=consensus_signature(step.candidate.consensus)
                if step.candidate
                else None,
                preserved=consensus_signature(step.candidate.consensus)
                == consensus_signature(initial)
                if step.candidate and initial
                else None,
            )
            for step in report.trace
        ),
    )
    markdown = (
        f"# Oracle-aware local reduction\n\nState: {report.state}\n\n"
        f"Finding class: {request.finding_class}\n\n"
        f"Events retained: {len(report.final.events) if report.final else 0}\n\n"
        f"Actual evaluations: {report.evaluations}; attempted reductions: {len(report.trace)}.\n\n"
        f"{report.explanation}\n\n{report.minimality}.\n\n"
        "A minimum is claimed only in the minimized state. Findings are conditional on this "
        "local fixture and the explicitly protected event scope. Confidence describes check "
        "resolution, not statistical certainty. JSON and trace retain actual evidence.\n"
    )
    artifacts = {
        "shrunk_case.json": json_bytes(report),
        "shrunk_case.md": markdown.encode("utf-8"),
        "shrinking_trace.jsonl": jsonl_bytes(report.trace),
        "oracle_preservation.json": json_bytes(preservation),
    }
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-SHRINK-OUTPUT: combined artifacts exceed 32 MiB")
    return artifacts
