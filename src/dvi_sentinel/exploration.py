"""Bounded composition of V1 probes with measured constraint coverage (pure analyzer)."""

import hashlib

from pydantic import ValidationError

from dvi_sentinel.artifact_models import MAX_ARTIFACT_BYTES
from dvi_sentinel.constraint_models import (
    Binding,
    BudgetPolicy,
    Category,
    ConstraintDecision,
    EligibleCombination,
    ExplorationCase,
    ExplorationManifest,
    ExplorationPlan,
    ExplorationStep,
    InvalidCombination,
    InvalidCombinations,
    ParameterSpace,
)
from dvi_sentinel.constraints import check_constraints
from dvi_sentinel.covering_array import _select_cover
from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.ontology import extract_signal, semantic_equivalence
from dvi_sentinel.policy import PolicyError, evaluate_events
from dvi_sentinel.probe_transforms import permission, specifications, transform
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import canonical_json, digest


def _failure(category: Category, reason: str, explanation: str) -> tuple[ConstraintDecision, ...]:
    return (
        ConstraintDecision(
            constraint_id="dvi:explore:" + reason,
            passed=False,
            category=category,
            reason_code=reason,
            explanation=explanation,
        ),
    )


def _event_digest(events: tuple[TelemetryEvent, ...]) -> str:
    return digest([event.model_dump(mode="json") for event in events])


def _materialize(
    events: tuple[TelemetryEvent, ...],
    assignment: tuple[Binding, ...],
    policy: VariationPolicy,
) -> tuple[tuple[TelemetryEvent, ...], tuple[ExplorationStep, ...], tuple[ConstraintDecision, ...]]:
    indexed = {spec.name: spec for spec in specifications()}
    current = events
    steps = []
    for term in assignment:
        if term.option == "none":
            continue
        spec = indexed[term.option]
        if not permission(spec, policy):
            return (
                (),
                (),
                _failure(
                    "permission",
                    "operation_not_permitted",
                    term.option + " is not permitted by the variation policy.",
                ),
            )
        try:
            candidate, _, preservation = transform(spec, current, policy)
            candidate = tuple(
                TelemetryEvent.model_validate(e.model_dump(mode="python")) for e in candidate
            )
        except (ValidationError, OverflowError) as exc:
            return (
                (),
                (),
                _failure(
                    "schema",
                    "transform_unrepresentable",
                    "Transformation exceeds a schema or timestamp limit: " + type(exc).__name__,
                ),
            )
        except ValueError as exc:
            if not str(exc).startswith("DVI-PROBE-PARSE:"):
                raise
            return (
                (),
                (),
                _failure(
                    "schema",
                    "transform_parse_failed",
                    "Transformed representation could not normalize to one event.",
                ),
            )
        if (
            len(candidate) > 128
            or len(canonical_json([e.model_dump(mode="json") for e in candidate]).encode("utf-8"))
            > MAX_FIXTURE_BYTES
        ):
            return (
                (),
                (),
                _failure("bounds", "candidate_limit", "Candidate exceeds 128 events or 2 MiB."),
            )
        try:
            decisions = evaluate_events(candidate)
        except PolicyError as exc:
            decisions = exc.decisions
        if decisions:
            return (
                (),
                (),
                _failure(
                    "safety",
                    "unsafe_candidate",
                    "Post-transformation policy rejected candidate content.",
                ),
            )
        if not preservation.valid:
            failed = ", ".join(check.id for check in preservation.checks if not check.passed)
            return (
                (),
                (),
                _failure(
                    "invariant", "invariant_rejected", "Independent V1 checks failed: " + failed
                ),
            )
        steps.append(
            ExplorationStep(
                operation=term.option,
                input_digest=_event_digest(current),
                output_digest=_event_digest(candidate),
                preservation=preservation,
            )
        )
        current = candidate
    # Required original meaning is checked independently of the composed probe trace.
    by_id = {event.event_id: event for event in current}
    if len(by_id) != len(current) or any(event.event_id not in by_id for event in events):
        return (
            (),
            (),
            _failure(
                "invariant",
                "identity_lost",
                "Original IDs must survive and all candidate IDs must be unique.",
            ),
        )
    for original in events:
        relation = semantic_equivalence(
            extract_signal(original), extract_signal(by_id[original.event_id])
        )
        if relation.decision != "equivalent":
            return (
                (),
                (),
                _failure("invariant", "semantic_" + relation.decision, relation.explanation),
            )
    return current, tuple(steps), ()


def plan_exploration(
    events: tuple[TelemetryEvent, ...],
    space: ParameterSpace,
    policy: VariationPolicy,
    *,
    seed: int = 0,
    budget: BudgetPolicy | None = None,
) -> ExplorationPlan:
    """Exhaustively validate <=512 rows, then select a feasible bounded covering array."""
    if not 1 <= len(events) <= 32:
        raise ValueError("DVI-EXPLORE-INPUT: require 1..32 unique telemetry events")
    events = tuple(TelemetryEvent.model_validate(e.model_dump(mode="python")) for e in events)
    space = ParameterSpace.model_validate(space.model_dump(mode="python"))
    # Canonicalize declarations as well as execution order.
    space = ParameterSpace(
        parameters=tuple(
            p.model_copy(update={"options": tuple(sorted(p.options))})
            for p in sorted(space.parameters, key=lambda p: p.name)
        ),
        constraints=tuple(
            c.model_copy(
                update={"forbidden": tuple(sorted(c.forbidden, key=lambda t: t.parameter))}
            )
            for c in sorted(space.constraints, key=lambda c: c.id)
        ),
        strength=space.strength,
    )
    policy = VariationPolicy.model_validate(policy.model_dump(mode="python"))
    policy = policy.model_copy(
        update={
            "families": tuple(sorted(policy.families)),
            "optional_fields": tuple(sorted(policy.optional_fields)),
        }
    )
    budget = BudgetPolicy.model_validate((budget or BudgetPolicy()).model_dump(mode="python"))
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("DVI-EXPLORE-SEED: require an integer in 0..2**63-1")
    if len({e.event_id for e in events}) != len(events):
        raise ValueError("DVI-EXPLORE-INPUT: require 1..32 unique telemetry events")
    if (
        len(canonical_json([e.model_dump(mode="json") for e in events]).encode("utf-8"))
        > MAX_FIXTURE_BYTES
    ):
        raise ValueError("DVI-EXPLORE-INPUT: input exceeds 2 MiB")
    rejected = evaluate_events(events)
    if rejected:
        raise PolicyError(rejected)
    input_digest = _event_digest(events)
    config_digest = digest(
        {
            "space": space.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
            "budget": budget.model_dump(mode="json"),
            "seed": seed,
        }
    )
    invalid = []
    eligible = []
    for assignment in space.assignments():
        failures = tuple(row for row in check_constraints(space, assignment) if not row.passed)
        if not failures:
            candidate, _, failures = _materialize(events, assignment, policy)
        if failures:
            invalid.append(InvalidCombination(assignment=assignment, decisions=failures))
        else:
            eligible.append(
                EligibleCombination(
                    assignment=assignment,
                    event_count=len(candidate),
                    events_digest=_event_digest(candidate),
                )
            )
    covering, skipped = _select_cover(space, tuple(eligible), budget, seed)
    expected = {item.assignment: item.events_digest for item in eligible}
    cases = []
    for assignment in covering.rows:
        candidate, steps, failures = _materialize(events, assignment, policy)
        if failures or _event_digest(candidate) != expected[assignment]:
            raise ValueError(
                "DVI-EXPLORE-REPLAY: selected candidate differs from eligibility evidence"
            )
        cases.append(
            ExplorationCase(
                id="explore:"
                + digest(
                    {
                        "input": input_digest,
                        "config": config_digest,
                        "assignment": [t.model_dump(mode="json") for t in assignment],
                    }
                )[:24],
                assignment=assignment,
                events=candidate,
                steps=steps,
                events_digest=expected[assignment],
            )
        )
    return ExplorationPlan(
        input_digest=input_digest,
        input_events=events,
        config_digest=config_digest,
        seed=seed,
        space=space,
        policy=policy,
        budget=budget,
        cases=tuple(cases),
        invalid=tuple(invalid),
        skipped=skipped,
        covering=covering,
    )


def exploration_artifacts(
    events: tuple[TelemetryEvent, ...],
    space: ParameterSpace,
    policy: VariationPolicy,
    *,
    seed: int = 0,
    budget: BudgetPolicy | None = None,
) -> dict[str, bytes]:
    """Generate artifacts from actual evaluated input, never caller-supplied eligibility flags."""
    plan = plan_exploration(events, space, policy, seed=seed, budget=budget)
    artifacts = {
        "constraint_plan.json": json_bytes(plan),
        "covering_array.json": json_bytes(plan.covering),
        "invalid_combinations.json": json_bytes(
            InvalidCombinations(
                input_digest=plan.input_digest, invalid=plan.invalid, skipped=plan.skipped
            )
        ),
    }
    manifest = ExplorationManifest(
        input_digest=plan.input_digest,
        config_digest=plan.config_digest,
        seed=seed,
        attempted=len(space.assignments()),
        selected=len(plan.cases),
        rejected=len(plan.invalid),
        skipped=len(plan.skipped),
        state=plan.covering.state,
        artifact_digests={
            name: hashlib.sha256(content).hexdigest() for name, content in sorted(artifacts.items())
        },
    )
    artifacts["exploration_manifest.json"] = json_bytes(manifest)
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-EXPLORE-OUTPUT: combined artifacts exceed 32 MiB")
    return artifacts
