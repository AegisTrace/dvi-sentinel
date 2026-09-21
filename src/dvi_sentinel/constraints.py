"""Exact conjunction checks over bounded parameter choices (pure analyzer)."""

from dvi_sentinel.constraint_models import Binding, ConstraintDecision, ParameterSpace


def check_constraints(
    space: ParameterSpace, assignment: tuple[Binding, ...]
) -> tuple[ConstraintDecision, ...]:
    space = ParameterSpace.model_validate(space.model_dump(mode="python"))
    assignment = tuple(
        Binding.model_validate(term.model_dump(mode="python")) for term in assignment
    )
    actual = {term.parameter: term.option for term in assignment}
    declared = {p.name: p.options for p in space.parameters}
    if (
        len(actual) != len(assignment)
        or actual.keys() != declared.keys()
        or any(option not in declared[name] for name, option in actual.items())
    ):
        raise ValueError("DVI-CONSTRAINT-ASSIGNMENT: require one declared option per parameter")
    return tuple(
        ConstraintDecision(
            constraint_id=constraint.id,
            passed=not all(actual[term.parameter] == term.option for term in constraint.forbidden),
            category="constraint",
            reason_code="forbidden_conjunction",
            explanation=constraint.explanation,
        )
        for constraint in sorted(space.constraints, key=lambda item: item.id)
    )
