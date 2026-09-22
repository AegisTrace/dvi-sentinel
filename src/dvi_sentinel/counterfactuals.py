"""Bounded local rule observations, subset controls and descriptive effects (A)."""

from dvi_sentinel.artifact_models import MAX_ARTIFACT_BYTES
from dvi_sentinel.constraint_models import (
    Binding,
    BudgetPolicy,
    EligibleCombination,
    Parameter,
    ParameterSpace,
)
from dvi_sentinel.counterfactual_models import (
    CausalRanking,
    CausalRankings,
    CounterfactualCase,
    CounterfactualFinding,
    CounterfactualInput,
    CounterfactualSummary,
    EffectEstimate,
    EffectPair,
    FailureAnalysis,
    FailureSet,
    Stage,
    subsets,
)
from dvi_sentinel.covering_array import _interactions, _select_cover
from dvi_sentinel.exploration import _event_digest, _materialize
from dvi_sentinel.harness import RuleLogicHarness
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.matching import match_detection
from dvi_sentinel.policy import PolicyError, evaluate_events, inspect_content
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes
from dvi_sentinel.serialization import digest

LIMITATIONS = (
    "Findings are associated with this local fixture. Necessity applies only within each "
    "verified failure set under this tested scenario, not across all possible contexts. "
    "The search does not establish a globally smallest undiscovered set or universal cause. "
    "Effects are descriptive paired outcomes from a deterministic local rule harness, not "
    "independent samples, causal probabilities or statistical confidence intervals. "
    "Unknown, invalid and untested controls remain explicit. Covering-array coverage does "
    "not imply exhaustive subset testing or security completeness."
)


def _assignment(request: CounterfactualInput, active: tuple[str, ...]) -> tuple[Binding, ...]:
    return tuple(
        Binding(parameter=d.name, option=d.operation if d.name in active else "none")
        for d in request.dimensions
    )


def _active(assignment: tuple[Binding, ...]) -> tuple[str, ...]:
    return tuple(t.parameter for t in assignment if t.option != "none")


def _failure_sets(cases: tuple[CounterfactualCase, ...]) -> tuple[FailureSet, ...]:
    by_active = {c.active: c for c in cases}
    findings = []
    for case in cases:
        if case.outcome != "missed":
            continue
        controls = tuple(by_active[a] for a in subsets(case.active)[:-1])
        smaller = tuple(c.case_id for c in controls if c.outcome == "missed")
        unresolved = tuple(c.case_id for c in controls if c.outcome not in {"detected", "missed"})
        findings.append(
            FailureSet(
                case_id=case.case_id,
                dimensions=case.active,
                status="nonminimal" if smaller else "unresolved" if unresolved else "minimal",
                proper_subset_cases=tuple(c.case_id for c in controls),
                smaller_missed_cases=smaller,
                unresolved_cases=unresolved,
                explanation="A measured smaller subset also misses the expectation."
                if smaller
                else "Some subset controls are unresolved; minimality is unknown."
                if unresolved
                else "All proper subsets detected; minimal under this tested scenario.",
            )
        )
    return tuple(findings)


def _rankings(
    request: CounterfactualInput,
    cases: tuple[CounterfactualCase, ...],
    failures: tuple[FailureSet, ...],
) -> tuple[CausalRanking, ...]:
    by_active = {c.active: c for c in cases}
    estimates = []
    for dimension in request.dimensions:
        pairs = []
        alternatives = subsets(tuple(d.name for d in request.dimensions if d != dimension))
        for active in alternatives:
            left, right = by_active[active], by_active[tuple(sorted((*active, dimension.name)))]
            if left.outcome not in {"detected", "missed"} or right.outcome not in {
                "detected",
                "missed",
            }:
                continue
            pairs.append(
                EffectPair(
                    without_case=left.case_id,
                    with_case=right.case_id,
                    input_changed=left.candidate_digest != right.candidate_digest,
                    miss_delta=int(right.outcome == "missed") - int(left.outcome == "missed"),
                )
            )
        changed = tuple(p for p in pairs if p.input_changed)
        lost, recovered = (
            sum(p.miss_delta == 1 for p in changed),
            sum(p.miss_delta == -1 for p in changed),
        )
        effect = EffectEstimate(
            dimension=dimension.name,
            pairs=tuple(pairs),
            possible_pairs=len(alternatives),
            unavailable_pairs=len(alternatives) - len(pairs),
            unchanged_input_pairs=len(pairs) - len(changed),
            loss_pairs=lost,
            recovery_pairs=recovered,
            mean_miss_delta=(lost - recovered) / len(changed) if changed else None,
        )
        necessary = tuple(
            f.case_id for f in failures if f.status == "minimal" and dimension.name in f.dimensions
        )
        estimates.append((dimension, effect, necessary))
    # Verified subset necessity precedes descriptive direction; ties use stable dimension names.
    estimates.sort(
        key=lambda row: (
            -bool(row[2]),
            row[1].mean_miss_delta is None,
            -(row[1].mean_miss_delta or 0),
            -row[1].loss_pairs,
            row[0].name,
        )
    )
    return tuple(
        CausalRanking(
            rank=i + 1,
            dimension=dimension,
            effect=effect,
            minimal_failure_cases=necessary,
            confidence="verified_local_subset_controls"
            if necessary
            else "partial_local_pairs"
            if effect.mean_miss_delta is not None
            else "insufficient_evidence",
            statement=(
                "A likely contributor associated with this local fixture; necessary under "
                "this tested scenario within the linked minimal sets."
            )
            if necessary
            else "Positive paired local miss association; necessity has not been established."
            if effect.mean_miss_delta is not None and effect.mean_miss_delta > 0
            else "No positive local effect established; missing pairs do not prove irrelevance.",
        )
        for i, (dimension, effect, necessary) in enumerate(estimates)
    )


def mine_counterfactuals(
    request: CounterfactualInput, *, expected_digest: str | None = None
) -> CounterfactualSummary:
    """Measure a local declarative harness; no caller-supplied outcomes or callbacks."""
    request = CounterfactualInput.model_validate(request.model_dump(mode="python"))
    fingerprint = request.stable_digest()

    def blocked(unsafe: bool, reason: str) -> CounterfactualSummary:
        return CounterfactualSummary(
            input_digest=fingerprint,
            input=None,
            state="unsafe_rejected" if unsafe else "unknown",
            cases=(),
            covering_plan=None,
            failure_sets=(),
            rankings=(),
            findings=(),
            evaluations=0,
            evaluated_events=0,
            limitations=reason + " " + LIMITATIONS,
        )

    if expected_digest is None:
        return blocked(False, "A pinned complete input digest is required before consumption.")
    if expected_digest != fingerprint:
        return blocked(True, "The pinned input digest differs from supplied content.")
    try:
        rejected = evaluate_events(request.events) or inspect_content(
            {
                "harness": request.harness.model_dump(mode="json"),
                "expected": request.expected.model_dump(mode="json"),
            }
        )
    except PolicyError as exc:
        rejected = exc.decisions
    if rejected:
        return blocked(True, "Structural fixture policy rejected consumption.")

    harness = RuleLogicHarness(request.harness)
    names = tuple(d.name for d in request.dimensions)
    all_subsets = subsets(names)
    rows: dict[tuple[str, ...], CounterfactualCase] = {}
    eligible: list[EligibleCombination] = []
    evaluations = 0
    evaluated_events = 0

    def prepare(active: tuple[str, ...]) -> None:
        assignment = _assignment(request, active)
        events, _, failures = _materialize(request.events, assignment, request.policy)
        row = CounterfactualCase(
            case_id="counterfactual:" + digest({"input": fingerprint, "active": list(active)})[:24],
            input_digest=fingerprint,
            active=active,
            stage="not_selected" if active else "baseline",
            outcome="invalid" if failures else "not_evaluated",
            reason="Eligibility rejected this subset."
            if failures
            else "Eligible subset not selected for observation.",
            rejections=failures,
            candidate_digest=None if failures else _event_digest(events),
        )
        rows[active] = row
        if not failures:
            eligible.append(
                EligibleCombination(
                    assignment=assignment,
                    event_count=len(events),
                    events_digest=_event_digest(events),
                )
            )

    def observe(active: tuple[str, ...], stage: Stage) -> None:
        nonlocal evaluations, evaluated_events
        row = rows[active]
        if row.observation is not None or row.outcome == "invalid":
            return
        item = next(e for e in eligible if _active(e.assignment) == active)
        reason = (
            "Case budget exhausted."
            if evaluations >= request.budget.max_cases
            else "Event budget would be exceeded."
            if evaluated_events + item.event_count > request.budget.max_events
            else None
        )
        if reason is not None:
            rows[active] = row.model_copy(update={"stage": stage, "reason": reason})
            return
        events, steps, failures = _materialize(request.events, item.assignment, request.policy)
        if failures or _event_digest(events) != item.events_digest:
            raise ValueError(
                "DVI-COUNTERFACTUAL-REPLAY: candidate differs from eligibility evidence"
            )
        observation = harness.evaluate(HarnessRequest(case_id=row.case_id, events=events))
        matched = match_detection(request.expected, observation, events)
        evaluations += 1
        evaluated_events += len(events)
        rows[active] = CounterfactualCase.model_validate(
            row.model_dump(mode="python")
            | {
                "stage": stage,
                "outcome": matched.status,
                "events": events,
                "steps": steps,
                "observation": observation,
                "match": matched,
                "evaluation": evaluations,
                "reason": matched.explanation,
            }
        )

    prepare(())
    observe((), "baseline")
    baseline = rows[()]
    if baseline.outcome != "detected":
        return CounterfactualSummary(
            input_digest=fingerprint,
            input=request,
            state="baseline_not_detected" if baseline.outcome == "missed" else "unknown",
            cases=(baseline,),
            covering_plan=None,
            failure_sets=(),
            rankings=(),
            findings=(),
            evaluations=evaluations,
            evaluated_events=evaluated_events,
            limitations="Mining requires a measured detected baseline. " + LIMITATIONS,
        )
    for active in all_subsets[1:]:
        prepare(active)
    for name in names:
        observe((name,), "single")

    covering = None
    if len(names) > 1:
        space = ParameterSpace(
            parameters=tuple(
                Parameter(name=d.name, options=("none", d.operation)) for d in request.dimensions
            ),
            strength=min(request.strength, len(names)),
        )
        covering, _ = _select_cover(
            space, tuple(eligible), BudgetPolicy(max_cases=64), request.seed
        )
        for assignment in covering.rows:
            observe(_active(assignment), "covering")

    # Single-deletion checks are insufficient for non-monotonic rules.
    initial_misses = tuple(a for a in all_subsets if rows[a].outcome == "missed")
    for active in initial_misses:
        for smaller in subsets(active)[:-1]:
            observe(smaller, "minimization")
    cases = tuple(rows[a] for a in all_subsets)
    failures = _failure_sets(cases)
    findings = tuple(
        CounterfactualFinding(
            case_id=f.case_id,
            necessary_dimensions=f.dimensions,
            control_cases=f.proper_subset_cases,
            statement="These changes are associated with this local fixture. Each is necessary "
            "under this tested scenario within this minimal set, making each a likely contributor "
            "to the observed local miss.",
        )
        for f in failures
        if f.status == "minimal"
    )
    unexecuted_cover = (
        tuple(
            rows[_active(a)].case_id for a in covering.rows if rows[_active(a)].observation is None
        )
        if covering
        else ()
    )
    interactions = (
        set().union(
            *(
                _interactions(_assignment(request, c.active), covering.strength)
                for c in cases
                if c.observation is not None
            )
        )
        if covering
        else set()
    )
    incomplete = (
        bool(unexecuted_cover)
        or any(
            c.outcome in {"unknown", "invalid"}
            or (c.outcome == "not_evaluated" and c.stage != "not_selected")
            for c in cases
        )
        or any(f.status == "unresolved" for f in failures)
        or (covering is not None and covering.state != "complete")
    )
    return CounterfactualSummary(
        input_digest=fingerprint,
        input=request,
        state="incomplete" if incomplete else "findings" if findings else "no_failure_observed",
        cases=cases,
        covering_plan=covering,
        executed_interactions=len(interactions),
        unexecuted_cover_cases=unexecuted_cover,
        failure_sets=failures,
        rankings=_rankings(request, cases, failures),
        findings=findings,
        evaluations=evaluations,
        evaluated_events=evaluated_events,
        limitations=LIMITATIONS,
    )


def counterfactual_artifacts(
    request: CounterfactualInput, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    summary = mine_counterfactuals(request, expected_digest=expected_digest)
    artifacts = {
        "counterfactuals.jsonl": jsonl_bytes(summary.cases),
        "minimal_failure_set.json": json_bytes(
            FailureAnalysis(
                input_digest=summary.input_digest,
                sets=summary.failure_sets,
                findings=summary.findings,
            )
        ),
        "causal_rankings.json": json_bytes(
            CausalRankings(
                input_digest=summary.input_digest,
                rankings=summary.rankings,
                limitations=summary.limitations,
            )
        ),
        "counterfactual_summary.json": json_bytes(summary),
    }
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-COUNTERFACTUAL-OUTPUT: combined artifacts exceed 32 MiB")
    return artifacts
