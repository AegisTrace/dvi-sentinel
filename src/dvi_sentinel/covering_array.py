"""Greedy finite t-way covering with deterministic ties and explicit budgets (A)."""

from itertools import combinations

from dvi_sentinel.constraint_models import (
    Binding,
    BudgetPolicy,
    CoveringArray,
    EligibleCombination,
    Option,
    ParameterSpace,
    SkippedCombination,
    SkipReason,
)
from dvi_sentinel.serialization import digest

Interaction = tuple[tuple[str, Option], ...]


def _interactions(assignment: tuple[Binding, ...], strength: int) -> set[Interaction]:
    return set(combinations(tuple((term.parameter, term.option) for term in assignment), strength))


def _select_cover(
    space: ParameterSpace,
    eligible: tuple[EligibleCombination, ...],
    budget: BudgetPolicy,
    seed: int,
) -> tuple[CoveringArray, tuple[SkippedCombination, ...]]:
    """Cover interactions observed in feasible rows; excluded rows never inflate coverage."""
    # The exploration engine supplies eligibility measured from actual transformed events.
    universe = set().union(*(_interactions(row, space.strength) for row in space.assignments()))
    by_row = {row.assignment: _interactions(row.assignment, space.strength) for row in eligible}
    feasible: set[Interaction] = set().union(*by_row.values())
    remaining = set(feasible)
    selected: list[tuple[Binding, ...]] = []
    event_count = 0
    while remaining and len(selected) < budget.max_cases:
        available = [
            row
            for row in eligible
            if row.assignment not in selected
            and row.event_count + event_count <= budget.max_events
            and remaining.intersection(by_row[row.assignment])
        ]
        if not available:
            break
        best = min(
            available,
            key=lambda row: (
                -len(remaining.intersection(by_row[row.assignment])),
                digest(
                    {
                        "seed": seed,
                        "assignment": [t.model_dump(mode="json") for t in row.assignment],
                    }
                ),
            ),
        )
        selected.append(best.assignment)
        event_count += best.event_count
        remaining.difference_update(by_row[best.assignment])
    omissions = []
    for row in eligible:
        if row.assignment in selected:
            continue
        reason: SkipReason = (
            "coverage_redundant"
            if not remaining.intersection(by_row[row.assignment])
            else "case_budget"
            if len(selected) >= budget.max_cases
            else "event_budget"
        )
        omissions.append(
            SkippedCombination(
                assignment=row.assignment,
                reason=reason,
                explanation={
                    "coverage_redundant": "All interactions in this row are already covered.",
                    "case_budget": "Uncovered interactions remain; the case budget is full.",
                    "event_budget": "This row exceeds the remaining event budget.",
                }[reason],
            )
        )

    def bindings(values: set[Interaction]) -> tuple[tuple[Binding, ...], ...]:
        return tuple(
            tuple(Binding(parameter=name, option=option) for name, option in row)
            for row in sorted(values)
        )

    return CoveringArray(
        strength=space.strength,
        rows=tuple(selected),
        theoretical_interactions=len(universe),
        feasible_interactions=len(feasible),
        covered_interactions=len(feasible) - len(remaining),
        infeasible_interactions=bindings(universe - feasible),
        uncovered_interactions=bindings(remaining),
        state="infeasible" if not eligible else "partial" if remaining else "complete",
        events_selected=event_count,
    ), tuple(omissions)
