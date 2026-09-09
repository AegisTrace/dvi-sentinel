"""Bounded non-adaptive probes comparing local detector identity observations."""

from collections import Counter

from pydantic import ValidationError

from dvi_sentinel import __version__
from dvi_sentinel.harness import DetectorHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.probe_transforms import permission, specifications, transform
from dvi_sentinel.scenario import DetectionExpectation, VariationPolicy
from dvi_sentinel.serialization import canonical_json, digest


def run_probes(
    events: tuple[TelemetryEvent, ...],
    policy: VariationPolicy,
    harness: DetectorHarness,
    *,
    event_budget: int = 50_000,
    expected: DetectionExpectation | None = None,
) -> tuple[AssumptionProbe, ...]:
    if not events or len(events) > 10_000 or len({e.event_id for e in events}) != len(events):
        raise ValueError("DVI-PROBE-INPUT: require 1..10000 uniquely identified events")
    if type(event_budget) is not int or not len(events) <= event_budget <= 50_000:
        raise ValueError("DVI-PROBE-BUDGET: budget must cover baseline and be <=50000")
    decisions = evaluate_events(events)
    if decisions:
        raise PolicyError(decisions)
    baseline = harness.evaluate(HarnessRequest(case_id="baseline", events=events))
    baseline_match = match_detection(expected, baseline, events) if expected else None
    identities = [(d.detector, d.signature) for d in baseline.detections]
    ambiguous = any(count > 1 for count in Counter(identities).values())
    input_digest = digest([e.model_dump(mode="json") for e in events])
    config_digest = digest(
        {
            "policy": policy.model_dump(mode="json"),
            "budget": event_budget,
            "version": __version__,
            "expected": expected.model_dump(mode="json") if expected else None,
        }
    )
    rows: list[AssumptionProbe] = []
    spent = len(events)
    seen: set[str] = set()
    for spec in specifications():
        if expected:
            spec = type(spec).model_validate(
                spec.model_dump()
                | {"hypothesis": f"Expected detection survives: {spec.transformation}"}
            )
        probe_id = (
            "probe:"
            + digest(
                {
                    "spec": spec.model_dump(mode="json"),
                    "input": input_digest,
                    "config": config_digest,
                }
            )[:24]
        )
        row = AssumptionProbe(
            id=probe_id,
            spec=spec,
            input_digest=input_digest,
            config_digest=config_digest,
            observed_result="not_applicable",
            reason="Transformation is not declared by policy",
            confidence_rationale="One local counterfactual; no statistical or universal claim",
            evidence_paths=("#/baseline", "#/baseline_match") if expected else ("#/baseline",),
            baseline=baseline,
            baseline_match=baseline_match,
        )
        changes: dict[str, object] = {}
        if permission(spec, policy):
            try:
                candidate, lineage, preservation = transform(spec, events, policy)
                candidate_digest = digest([e.model_dump(mode="json") for e in candidate])
                if candidate == events:
                    changes = {"reason": "No supported nontrivial transformation for these records"}
                elif spent + len(candidate) > event_budget:
                    changes = {
                        "observed_result": "unknown",
                        "reason": "DVI-PROBE-BUDGET: event budget exhausted",
                    }
                elif candidate_digest in seen:
                    changes = {
                        "reason": "Equivalent candidate already tested; duplicate suppressed"
                    }
                else:
                    spent += len(candidate)
                    seen.add(candidate_digest)
                    changes = {
                        "events": candidate,
                        "lineage": lineage,
                        "preservation": preservation,
                        "evidence_paths": ("#/baseline", "#/events", "#/lineage", "#/preservation"),
                    }
                    if not preservation.valid:
                        changes.update(
                            observed_result="invalid",
                            reason="Invariant failed; candidate was not evaluated",
                        )
                    elif (baseline_match is not None and baseline_match.status != "detected") or (
                        baseline_match is None
                        and (baseline.status != "complete" or not identities or ambiguous)
                    ):
                        changes.update(
                            observed_result="unknown",
                            reason="Baseline does not establish the expected detection"
                            if baseline_match
                            else "Baseline is unavailable, empty, or identity-ambiguous",
                        )
                    else:
                        result = harness.evaluate(
                            HarnessRequest(case_id=probe_id, events=candidate)
                        )
                        changes["candidate"] = result
                        changes["evidence_paths"] = (
                            *row.evidence_paths,
                            "#/candidate",
                            "#/events",
                            "#/lineage",
                            "#/preservation",
                        )
                        observed = [(d.detector, d.signature) for d in result.detections]
                        if expected:
                            matched = match_detection(
                                expected, result, candidate, preservation=preservation
                            )
                            changes["candidate_match"] = matched
                            changes["evidence_paths"] = (
                                "#/baseline",
                                "#/candidate",
                                "#/events",
                                "#/lineage",
                                "#/preservation",
                                "#/baseline_match",
                                "#/candidate_match",
                            )
                            changes.update(
                                observed_result="fragile"
                                if matched.status == "missed"
                                else "robust"
                                if matched.status == "detected"
                                else "unknown",
                                reason=f"Expected-detection comparison: {matched.reason}",
                            )
                        elif result.status != "complete" or len(set(observed)) != len(observed):
                            changes.update(
                                observed_result="unknown",
                                reason="Candidate observation is unavailable or identity-ambiguous",
                            )
                        else:
                            missing = tuple(sorted(set(identities) - set(observed)))
                            changes.update(
                                observed_result="fragile" if missing else "robust",
                                reason="Baseline detection identities disappeared"
                                if missing
                                else "Baseline detection identities survived this counterfactual",
                                missing_identities=missing,
                            )
            except (ValueError, ValidationError, OverflowError, PolicyError) as exc:
                changes = {
                    "observed_result": "invalid",
                    "reason": f"Transformation rejected: {type(exc).__name__}",
                }
        rows.append(AssumptionProbe.model_validate(row.model_dump() | changes))
    return tuple(rows)


def probes_jsonl(probes: tuple[AssumptionProbe, ...]) -> str:
    return "".join(canonical_json(probe) + "\n" for probe in probes)


def probes_markdown(probes: tuple[AssumptionProbe, ...]) -> str:
    counts = Counter(probe.observed_result for probe in probes)
    lines = [
        "## Assumption probes",
        "",
        "; ".join(f"{key}: {counts[key]}" for key in sorted(counts)),
        "",
        "Findings compare configured expected-detection semantics in local observations."
        if any(probe.baseline_match for probe in probes)
        else "Findings compare detector/signature identity survival in local observations.",
        "A robust result covers only its tested counterfactual; unknown is not a measured miss.",
        "",
    ]
    for probe in probes:
        # Names/classes are fixed engine identifiers, not source-controlled Markdown.
        lines.append(f"- `{probe.spec.name}`: **{probe.observed_result}** (`{probe.id}`).")
    return "\n".join(lines) + "\n"
