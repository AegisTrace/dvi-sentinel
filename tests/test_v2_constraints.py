"""Measured covering, pruning, control detection, safety and budget regression proof."""

import hashlib
import importlib.util
import itertools
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

import dvi_sentinel.exploration as engine
from dvi_sentinel.constraint_models import (
    Binding,
    BudgetPolicy,
    Constraint,
    ExplorationPlan,
    Parameter,
    ParameterSpace,
)
from dvi_sentinel.constraints import check_constraints
from dvi_sentinel.exploration import exploration_artifacts, plan_exploration
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import digest, parse_json

EXAMPLE = Path(__file__).parents[1] / "examples" / "constraint_exploration.py"
spec = importlib.util.spec_from_file_location("constraint_example", EXAMPLE)
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


def space(strength=2):
    return ParameterSpace(
        parameters=(
            Parameter(name="a", options=("none", "ordering")),
            Parameter(name="b", options=("none", "duplicates")),
            Parameter(name="c", options=("none", "benign_noise")),
        ),
        strength=strength,
    )


def fixture():
    events, _, policy = example.fixture()
    return events, space(), policy


def key(assignment):
    return tuple((term.parameter, term.option) for term in assignment)


def interactions(rows, strength):
    return {part for row in rows for part in itertools.combinations(key(row), strength)}


@pytest.mark.parametrize("strength,expected", [(1, 6), (2, 12), (3, 8)])
def test_small_space_covers_every_feasible_t_way_interaction(strength, expected):
    events, _, policy = fixture()
    selected_space = space(strength)
    plan = plan_exploration(events, selected_space, policy, seed=8)
    selected = tuple(case.assignment for case in plan.cases)
    expected_rows = tuple(
        itertools.product(("none", "ordering"), ("none", "duplicates"), ("none", "benign_noise"))
    )
    truth = {tuple(zip(("a", "b", "c"), row, strict=True)) for row in expected_rows}
    truth_interactions = {part for row in truth for part in itertools.combinations(row, strength)}
    assert interactions(selected, strength) == truth_interactions
    assert plan.covering.covered_interactions == expected
    assert plan.covering.state == "complete" and not plan.invalid
    assert len(plan.cases) + len(plan.skipped) == 8
    assert len(plan.cases) == 8 if strength == 3 else len(plan.cases) < 8
    assert all(row.reason == "coverage_redundant" for row in plan.skipped)


def test_forbidden_combinations_change_feasibility_not_the_coverage_denominator():
    events, selected_space, policy = example.fixture()
    plan = plan_exploration(events, selected_space, policy, seed=42)
    assert len(plan.invalid) == 4
    assert all(row.decisions[0].reason_code == "forbidden_conjunction" for row in plan.invalid)
    assert plan.covering.theoretical_interactions == 24
    assert plan.covering.feasible_interactions == plan.covering.covered_interactions == 23
    assert len(plan.covering.infeasible_interactions) == 1
    assert {term.option for term in plan.covering.infeasible_interactions[0]} == {
        "duplicates",
        "benign_noise",
    }
    controls = example.check_controls(plan)
    assert controls == {"robust": 5, "sensor-dependent": 3}


@pytest.mark.parametrize(
    "budget,reason",
    [
        (BudgetPolicy(max_cases=1), "case_budget"),
        (BudgetPolicy(max_events=1), "event_budget"),
        (BudgetPolicy(max_cases=0), "case_budget"),
    ],
)
def test_budget_truncation_preserves_feasible_uncovered_interactions(budget, reason):
    plan = plan_exploration(*fixture(), budget=budget)
    assert plan.covering.state == "partial"
    assert plan.covering.feasible_interactions == 12
    assert len(plan.covering.uncovered_interactions) + plan.covering.covered_interactions == 12
    assert any(row.reason == reason and row.explanation for row in plan.skipped)
    assert len(plan.cases) <= budget.max_cases
    assert sum(len(case.events) for case in plan.cases) <= budget.max_events
    assert not plan.invalid


def test_case_selection_uses_an_affordable_alternative_when_large_rows_do_not_fit():
    events, selected_space, policy = fixture()
    plan = plan_exploration(events, selected_space, policy, budget=BudgetPolicy(max_events=2))
    assert len(plan.cases) == 1
    assert len(plan.cases[0].events) == 2
    assert plan.covering.state == "partial"
    assert any(row.reason == "event_budget" for row in plan.skipped)


@given(st.integers(min_value=0, max_value=2**63 - 1))
@settings(max_examples=12, deadline=None)
def test_seed_determinism_and_declaration_order_invariance(seed):
    events, selected_space, policy = example.fixture()
    shuffled = ParameterSpace(
        parameters=tuple(
            p.model_copy(update={"options": tuple(reversed(p.options))})
            for p in reversed(selected_space.parameters)
        ),
        constraints=tuple(
            c.model_copy(update={"forbidden": tuple(reversed(c.forbidden))})
            for c in selected_space.constraints
        ),
    )
    a = plan_exploration(events, selected_space, policy, seed=seed)
    b = plan_exploration(events, shuffled, policy, seed=seed)
    assert a == b
    assert a.covering.state == "complete"


def test_seed_changes_tie_order_without_changing_the_required_interactions():
    a = plan_exploration(*fixture(), seed=1)
    b = plan_exploration(*fixture(), seed=2)
    assert a.covering.rows != b.covering.rows
    assert a.covering.covered_interactions == b.covering.covered_interactions == 12


def test_permission_filter_runs_before_unapproved_transform(monkeypatch):
    events, selected_space, _ = fixture()

    def forbidden(*args):
        pytest.fail("unapproved transform ran")

    monkeypatch.setattr(engine, "transform", forbidden)
    plan = plan_exploration(events, selected_space, VariationPolicy())
    assert len(plan.cases) == 1 and len(plan.invalid) == 7
    assert all(row.decisions[0].category == "permission" for row in plan.invalid)
    assert plan.covering.feasible_interactions == 3


def test_unsafe_input_blocks_exploration_before_transforms(monkeypatch):
    events, selected_space, policy = fixture()
    unsafe = TelemetryEvent.model_validate(
        events[0].model_dump()
        | {"raw": RawSource.from_payload({"target": "production.invalid"}, adapter="jsonl")}
    )
    monkeypatch.setattr(engine, "transform", lambda *args: pytest.fail("unsafe input consumed"))
    with pytest.raises(PolicyError):
        plan_exploration((unsafe,), selected_space, policy)


def test_unsafe_transformation_is_pruned_even_when_it_claims_invariant_success(monkeypatch):
    real = engine.transform

    def tainted(*args):
        candidate, lineage, preservation = real(*args)
        bad = TelemetryEvent.model_validate(
            candidate[0].model_dump()
            | {"raw": RawSource.from_payload({"target": "production.invalid"}, adapter="jsonl")}
        )
        return (bad, *candidate[1:]), lineage, preservation

    monkeypatch.setattr(engine, "transform", tainted)
    plan = plan_exploration(*fixture())
    assert len(plan.cases) == 1 and len(plan.invalid) == 7
    assert {d.category for row in plan.invalid for d in row.decisions} == {"safety"}
    assert all("production.invalid" not in str(case) for case in plan.cases)


def test_unknown_original_semantics_never_yield_vacuous_complete_coverage():
    events, selected_space, policy = fixture()
    broken = TelemetryEvent.model_validate(
        events[0].model_dump() | {"semantics": {"category": "dns", "action": "observed"}}
    )
    plan = plan_exploration((broken,), selected_space, policy)
    assert plan.covering.state == "infeasible" and not plan.cases
    assert plan.covering.feasible_interactions == 0
    assert len(plan.invalid) == 8
    assert all(row.decisions[0].reason_code == "semantic_unknown" for row in plan.invalid)


def test_composition_detects_real_identity_collision_and_preserves_other_cases():
    events, _, policy = fixture()
    selected_space = ParameterSpace(
        parameters=(
            Parameter(name="a", options=("none", "duplicates")),
            Parameter(name="b", options=("none", "bounded_volume")),
        )
    )
    plan = plan_exploration(events, selected_space, policy)
    assert len(plan.invalid) == 1
    assert plan.invalid[0].decisions[0].reason_code == "invariant_rejected"
    assert plan.covering.covered_interactions == 3
    assert plan.covering.state == "complete"


def test_final_semantic_check_rejects_dropped_correlation_even_if_optional_to_v1():
    events, _, policy = fixture()
    events = tuple(
        TelemetryEvent.model_validate(e.model_dump() | {"correlation_id": "flow:1"}) for e in events
    )
    selected_space = ParameterSpace(
        parameters=(
            Parameter(name="a", options=("none", "drop:correlation_id")),
            Parameter(name="b", options=("none", "ordering")),
        )
    )
    policy = VariationPolicy.model_validate(
        policy.model_dump()
        | {"families": ["dropout", "ordering"], "optional_fields": ["correlation_id"]}
    )
    plan = plan_exploration(events, selected_space, policy)
    assert len(plan.invalid) == 2
    assert all(row.decisions[0].reason_code == "semantic_different" for row in plan.invalid)


@pytest.mark.parametrize(
    "changes",
    [
        {"strength": True},
        {"strength": 4},
        {"parameters": (Parameter(name="a", options=("none",)),) * 2},
        {
            "parameters": (
                Parameter(name="a", options=("ordering",)),
                Parameter(name="b", options=("ordering",)),
            )
        },
        {
            "constraints": (
                Constraint(
                    id="bad",
                    forbidden=(Binding(parameter="missing", option="none"),),
                    explanation="invalid binding",
                ),
            )
        },
    ],
)
def test_invalid_or_copied_parameter_spaces_are_revalidated(changes):
    events, selected_space, policy = fixture()
    with pytest.raises(ValidationError):
        plan_exploration(events, selected_space.model_copy(update=changes), policy)


@pytest.mark.parametrize("seed", [True, -1, 2**63, 0.5])
def test_seed_bounds_are_strict(seed):
    with pytest.raises(ValueError, match="DVI-EXPLORE-SEED"):
        plan_exploration(*fixture(), seed=seed)


def test_input_and_budget_bounds_and_duplicate_bindings():
    events, selected_space, policy = fixture()
    for invalid in (
        (),
        (events[0], events[0]),
        tuple(events[0].model_copy(update={"event_id": f"e:{i}"}) for i in range(33)),
    ):
        with pytest.raises(ValueError, match="DVI-EXPLORE-INPUT"):
            plan_exploration(invalid, selected_space, policy)
    with pytest.raises(ValidationError):
        plan_exploration(
            events,
            selected_space,
            policy,
            budget=BudgetPolicy().model_copy(update={"max_cases": True}),
        )
    with pytest.raises(ValueError, match="ASSIGNMENT"):
        check_constraints(selected_space, (Binding(parameter="a", option="none"),) * 3)
    with pytest.raises(ValidationError, match="duplicate"):
        Parameter(name="bad", options=("none", "none"))
    with pytest.raises(ValidationError, match="duplicate"):
        Constraint(
            id="bad", forbidden=(Binding(parameter="a", option="none"),) * 2, explanation="bad"
        )


def test_constraints_are_data_and_unknown_operations_never_execute(tmp_path):
    marker = tmp_path / "must-not-exist"
    with pytest.raises(ValidationError):
        Parameter.model_validate(
            {"name": "x", "options": [f"__import__('pathlib').Path('{marker}').touch()"]}
        )
    assert not marker.exists()


def test_no_optional_solver_is_needed(monkeypatch):
    monkeypatch.setitem(sys.modules, "z3", None)
    assert plan_exploration(*fixture()).covering.state == "complete"


def test_four_way_coverage_and_full_assignment_rejections():
    events, selected_space, policy = example.fixture()
    selected_space = ParameterSpace.model_validate(selected_space.model_dump() | {"strength": 4})
    plan = plan_exploration(events, selected_space, policy)
    assert len(plan.cases) == plan.covering.covered_interactions == 12
    assert len(plan.covering.infeasible_interactions) == 4
    assert plan.covering.state == "complete"


def test_enumeration_limit_prevents_large_cartesian_search(monkeypatch):
    events, selected_space, policy = fixture()
    operations = [
        "ordering",
        "duplicates",
        "benign_noise",
        "bounded_volume",
        "timezone",
        "timestamp_precision",
        "schema_alias",
        "severity_normalization",
        "name:sensor",
        "name:vendor",
        "drop:sensor",
        "drop:vendor",
    ]
    parameters = tuple(
        Parameter(name=f"p:{i}", options=("none", *operations[2 * i : 2 * i + 2])) for i in range(6)
    )
    monkeypatch.setattr(engine, "transform", lambda *args: pytest.fail("oversized space consumed"))
    with pytest.raises(ValidationError, match="512"):
        plan_exploration(
            events, selected_space.model_copy(update={"parameters": parameters}), policy
        )


def test_real_candidate_growth_obeys_event_limit():
    events, _, policy = fixture()
    original = tuple(
        TelemetryEvent.model_validate(events[0].model_dump() | {"event_id": f"e:{i}"})
        for i in range(32)
    )
    selected_space = ParameterSpace(
        parameters=(
            Parameter(name="a", options=("none", "bounded_volume")),
            Parameter(name="b", options=("none",)),
        )
    )
    policy = VariationPolicy.model_validate(policy.model_dump() | {"max_duplicates": 100})
    plan = plan_exploration(original, selected_space, policy)
    assert len(plan.cases) == len(plan.invalid) == 1
    assert plan.invalid[0].decisions[0].reason_code == "candidate_limit"
    assert plan.covering.state == "complete"


@pytest.mark.parametrize(
    "error,code",
    [
        (OverflowError("date range"), "transform_unrepresentable"),
        (ValueError("DVI-PROBE-PARSE: unsupported record"), "transform_parse_failed"),
    ],
)
def test_unrepresentable_transformations_have_structured_rejections(monkeypatch, error, code):
    def broken(*args):
        raise error

    monkeypatch.setattr(engine, "transform", broken)
    plan = plan_exploration(*fixture())
    assert len(plan.invalid) == 7
    assert all(row.decisions[0].reason_code == code for row in plan.invalid)


def test_unexpected_transform_errors_are_not_swallowed(monkeypatch):
    def broken(*args):
        raise ValueError("unexpected implementation failure")

    monkeypatch.setattr(engine, "transform", broken)
    with pytest.raises(ValueError, match="unexpected implementation failure"):
        plan_exploration(*fixture())


def test_selected_case_must_replay_the_measured_candidate(monkeypatch):
    events, _, policy = fixture()
    selected_space = ParameterSpace(
        parameters=(
            Parameter(name="a", options=("ordering",)),
            Parameter(name="b", options=("none",)),
        )
    )
    real = engine.transform
    calls = 0

    def drifting(*args):
        nonlocal calls
        calls += 1
        candidate, lineage, preservation = real(*args)
        if calls > 1:
            changed = TelemetryEvent.model_validate(
                candidate[0].model_dump()
                | {"raw": candidate[0].raw.model_dump() | {"sensor": "fixture-sensor-alias"}}
            )
            candidate = (changed, *candidate[1:])
        return candidate, lineage, preservation

    monkeypatch.setattr(engine, "transform", drifting)
    with pytest.raises(ValueError, match="DVI-EXPLORE-REPLAY"):
        plan_exploration(events, selected_space, policy)


def test_artifact_hashes_replay_accounting_and_tampering():
    inputs = fixture()
    artifacts = exploration_artifacts(*inputs, seed=9)
    assert artifacts == exploration_artifacts(*inputs, seed=9)
    assert set(artifacts) == {
        "constraint_plan.json",
        "covering_array.json",
        "invalid_combinations.json",
        "exploration_manifest.json",
    }
    manifest = parse_json(artifacts["exploration_manifest.json"])
    for name, expected in manifest["artifact_digests"].items():
        assert hashlib.sha256(artifacts[name]).hexdigest() == expected
    data = parse_json(artifacts["constraint_plan.json"])
    plan = ExplorationPlan.model_validate(data)
    assert digest(data["input_events"]) == plan.input_digest
    assert (
        manifest["selected"] + manifest["rejected"] + manifest["skipped"]
        == manifest["attempted"]
        == 8
    )
    data["cases"][0]["events"][0]["timestamp"] = "2026-01-01T01:00:00Z"
    with pytest.raises(ValidationError, match="content changed"):
        ExplorationPlan.model_validate(data)
    clean = parse_json(artifacts["constraint_plan.json"])
    clean["skipped"] = []
    with pytest.raises(ValidationError, match="accounted once"):
        ExplorationPlan.model_validate(clean)


def test_example_executes_controls_emits_four_files_and_refuses_existing_path(
    tmp_path, monkeypatch
):
    out = tmp_path / "proof"
    monkeypatch.setattr(sys, "argv", [str(EXAMPLE), "--out", str(out)])
    example.main()
    assert len(list(out.iterdir())) == 4
    assert parse_json((out / "exploration_manifest.json").read_bytes())["state"] == "complete"
    with pytest.raises(SystemExit):
        example.main()
