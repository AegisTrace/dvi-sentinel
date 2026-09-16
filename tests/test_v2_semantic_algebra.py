"""Semantic relation proofs use actual ontology evidence, including unknown controls."""

import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.models import RawSource, TelemetryEvent, ValidationWarning
from dvi_sentinel.ontology import default_profile, extract_signal
from dvi_sentinel.ontology_models import (
    FieldBinding,
    OntologyProfile,
    SemanticSignal,
    SignalMeaning,
)
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.semantic_algebra import (
    algebra_artifacts,
    bind_invariant,
    bind_transform,
    contradicts,
    equivalent,
    evaluate_plan,
    explains,
    implies,
    preserves,
    requires,
    weakens,
)
from dvi_sentinel.semantic_algebra_models import (
    AlgebraDecision,
    RelationCheck,
    SemanticPlan,
)
from dvi_sentinel.serialization import canonical_json, parse_json


def event(**changes):
    return TelemetryEvent.model_validate(
        {
            "event_id": "fixture:dns",
            "timestamp": "2026-01-01T00:00:00.123456Z",
            "semantics": {
                "category": "dns",
                "action": "query",
                "dns_name": "demo.example",
                "protocol": "udp",
            },
            "confidence": 0.9,
            "raw": RawSource.from_payload(
                {"label": "alpha"},
                adapter="jsonl",
                original_timestamp="2026-01-01T00:00:00.123456Z",
            ),
        }
        | changes
    )


def context(**changes):
    return extract_signal(event(**changes))


def missing():
    return context(semantics=event().semantics.model_dump() | {"dns_name": None})


def profile(**changes):
    return OntologyProfile.model_validate(default_profile().model_dump() | changes)


def test_preserves_actual_declared_invariant_and_exposes_values():
    source = context()
    changed = context(
        event_id="fixture:other",
        tags=("lab",),
        raw=RawSource.from_payload({"label": "beta"}, adapter="csv"),
    )
    transform = bind_transform(source, changed)
    invariant = bind_invariant(source, ("action", "category", "evidence.dns_name"))
    result = preserves(transform, invariant)
    assert result.truth == "true" and result.effect == "supported"
    assert all(check.expected_json == check.actual_json for check in result.checks)
    assert result.oracle.confidence.value == 1.0
    assert result.oracle.confidence.numerator == result.oracle.confidence.denominator == 4
    assert transform.changed_fields == ()


def test_known_contradiction_suppresses_a_false_positive_assertion():
    source = context()
    changed = context(semantics=event().semantics.model_dump() | {"action": "response"})
    invariant = bind_invariant(source, ("action",))
    assert preserves(bind_transform(source, changed), invariant).truth == "false"
    result = contradicts(changed, invariant)
    assert result.truth == "true" and result.effect == "suppressed_false_positive"
    assert result.oracle.blocking
    assert result.checks[0].expected_json == '"query"'
    assert result.checks[0].actual_json == '"response"'
    assert requires(source, changed).truth == "false"
    assert contradicts(source, invariant).truth == "false"


@pytest.mark.parametrize("field", ["evidence.dns_name", "resource", "evidence"])
def test_missing_evidence_is_unknown_not_a_known_contradiction(field):
    source, absent = context(), missing()
    invariant = bind_invariant(source, (field,))
    assert requires(source, absent).truth == "unknown"
    assert preserves(bind_transform(source, absent), invariant).truth == "unknown"
    assert contradicts(absent, invariant).truth == "unknown"
    assert equivalent(source, absent).truth == "unknown"
    assert implies(source, absent).truth == "unknown"


def test_weaker_evidence_lowers_explicit_support_confidence():
    source, absent = context(), missing()
    result = weakens(bind_transform(source, absent), source)
    assert result.truth == "true"
    assert result.confidence_before.value == 1.0
    assert result.confidence_after.value == 0.75
    assert result.confidence_after.numerator == 3 and result.confidence_after.denominator == 4
    assert result.oracle.confidence_basis == "satisfied_required_evidence_fraction"
    assert result.oracle.confidence == requires(source, absent).oracle.confidence
    assert weakens(bind_transform(source, source), source).truth == "false"
    assert weakens(bind_transform(absent, absent), absent).truth == "unknown"


def test_confidence_threshold_is_a_requirement_not_exact_sample_equality():
    selected = profile(confidence_requirement=0.8)
    source = extract_signal(event(confidence=0.95), selected)
    adequate = extract_signal(event(confidence=0.85), selected)
    below = extract_signal(event(confidence=0.7), selected)
    assert requires(source, adequate).truth == "true"
    assert requires(source, below).truth == "false"
    assert weakens(bind_transform(source, below), source).confidence_after.value == 0.8


def test_implication_is_directional_for_stronger_requirements():
    sample = event(correlation_id="flow:1")
    strong = extract_signal(
        sample, profile(correlation_requirement="required", confidence_requirement=0.8)
    )
    weak = extract_signal(sample)
    assert implies(strong, weak).truth == "true"
    assert implies(weak, strong).truth == "false"
    assert equivalent(strong, weak).truth == "false"
    assert implies(strong, strong).truth == "true"
    precise = extract_signal(sample, profile(timestamp_precision_digits=6))
    assert implies(precise, weak).truth == "true"
    assert implies(weak, precise).truth == "false"


def test_implication_preserves_actual_core_and_bound_evidence_constraints():
    base = default_profile()
    selected = profile(
        bindings=(*base.bindings, FieldBinding(field="label", paths=("raw.payload.label",)))
    )
    strict = extract_signal(event(), selected)
    generic = context()
    assert implies(strict, generic).truth == "true"
    assert implies(generic, strict).truth == "false"
    other = context(semantics=event().semantics.model_dump() | {"action": "response"})
    assert implies(other, generic).truth == "false"


def test_explains_real_findings_and_refuses_unrelated_or_unavailable_support():
    absent = missing()
    finding = absent.findings[0]
    assert explains(finding, absent).truth == "true"
    assert explains(finding, context()).truth == "false"
    warning = ValidationWarning(code="UNINTERPRETED", path="timestamp", explanation="Needs mapping")
    unknown = context(warnings=(warning,))
    assert explains(unknown.findings[0], unknown).truth == "unknown"
    assert requires(context(), unknown).truth == "unknown"
    assert requires(context(), unknown).oracle.confidence.value == 1.0
    assert weakens(bind_transform(context(), unknown), context()).truth == "unknown"


@pytest.mark.parametrize(
    "field,changes",
    [
        ("protocol", {"protocol": None}),
        ("outcome", {"outcome": "success"}),
        ("source_destination_relation", {"source": {"address": "192.0.2.1"}}),
    ],
)
def test_unavailable_semantic_components_do_not_become_contradictions(field, changes):
    source = context()
    other = context(semantics=event().semantics.model_dump() | changes)
    assert contradicts(other, bind_invariant(source, (field,))).truth == "unknown"


def test_unknown_fields_and_empty_requirement_contract_are_explicit():
    source = context()
    invariant = bind_invariant(source, ("unknown.field",))
    assert preserves(bind_transform(source, source), invariant).truth == "unknown"
    assert contradicts(source, invariant).truth == "unknown"
    empty = extract_signal(
        event(),
        profile(bindings=(FieldBinding(field="optional", paths=("raw.vendor",), required=False),)),
    )
    assert requires(empty, empty).truth == "unknown"
    assert requires(empty, empty).oracle.confidence.value is None
    assert weakens(bind_transform(empty, empty), empty).truth == "unknown"


def test_unknown_reference_cannot_assert_a_known_contradiction():
    reference = missing()
    candidate = context(semantics=event().semantics.model_dump() | {"action": "response"})
    invariant = bind_invariant(reference, ("action",))
    assert contradicts(candidate, invariant).truth == "unknown"
    assert preserves(bind_transform(reference, candidate), invariant).truth == "unknown"
    assert requires(reference, candidate).truth == "unknown"


def test_known_contradiction_survives_unrelated_missing_evidence():
    source = context()
    changed = context(
        semantics=event().semantics.model_dump() | {"action": "response", "dns_name": None}
    )
    result = contradicts(changed, bind_invariant(source, ("action", "evidence.dns_name")))
    assert changed.state == "unknown"
    assert result.truth == "true" and result.effect == "suppressed_false_positive"
    assert [check.truth for check in result.checks] == ["true", "unknown"]


def test_omitted_binding_and_lossy_required_value_remain_unknown():
    source = context()
    sparse = extract_signal(
        event(),
        profile(bindings=tuple(b for b in default_profile().bindings if b.field != "dns_name")),
    )
    result = requires(source, sparse)
    assert result.truth == "unknown"
    assert result.oracle.confidence.value == 0.75
    selected = profile(
        bindings=(
            *default_profile().bindings,
            FieldBinding(field="label", paths=("raw.payload.label",), normalization="casefold"),
        )
    )
    lossy = extract_signal(
        event(raw=RawSource.from_payload({"label": "ALPHA"}, adapter="jsonl")), selected
    )
    assert requires(extract_signal(event(), selected), lossy).truth == "unknown"


@pytest.mark.parametrize("field,count", [("bindings", 65), ("findings", 257)])
def test_oversized_context_is_rejected_before_evaluation(field, count):
    source = missing()
    oversized = source.model_copy(update={field: (getattr(source, field)[0],) * count})
    with pytest.raises(ValueError, match="BOUNDS"):
        requires(source, oversized)


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=25))
def test_equivalent_source_metadata_changes_retain_signal(label):
    source = context()
    changed = context(raw=RawSource.from_payload({"label": label}, adapter="csv"))
    result = equivalent(source, changed)
    assert result.truth == "true"
    assert source.signal.semantic_digest == changed.signal.semantic_digest


def test_plan_and_artifacts_are_real_deterministic_and_replayable():
    source, absent = context(), missing()
    transform = bind_transform(source, absent)
    invariant = bind_invariant(source, ("action", "evidence.dns_name"))
    plan = evaluate_plan(transform, invariant)
    assert {d.relation.operation for d in plan.decisions} == {
        "preserves",
        "requires",
        "contradicts",
        "implies",
        "equivalent",
        "weakens",
        "explains",
    }
    assert SemanticPlan.model_validate_json(canonical_json(plan)) == plan
    files = algebra_artifacts(plan)
    assert files == algebra_artifacts(evaluate_plan(transform, invariant))
    assert set(files) == {"semantic_plan.json", "algebra_decisions.jsonl"}
    rows = tuple(
        AlgebraDecision.model_validate(parse_json(line))
        for line in files["algebra_decisions.jsonl"].splitlines()
    )
    assert rows == plan.decisions
    robust = evaluate_plan(bind_transform(source, source), invariant)
    assert len(robust.decisions) == 6  # No fabricated finding to populate an explanation row.


def test_unrelated_references_forged_transforms_and_decisions_are_rejected():
    source, absent = context(), missing()
    transform = bind_transform(source, absent)
    invariant = bind_invariant(source, ("action",))
    unrelated = context(event_id="unrelated")
    with pytest.raises(ValueError, match="REFERENCE"):
        preserves(transform, bind_invariant(unrelated, ("action",)))
    with pytest.raises(ValueError, match="REFERENCE"):
        weakens(transform, unrelated)
    for change in ({"changed_fields": ()}, {"source_digest": "0" * 64}, {"transform_id": "forged"}):
        with pytest.raises(ValidationError, match="TRANSFORM"):
            preserves(transform.model_copy(update=change), invariant)
    for change in ({"invariant_id": "forged"}, {"protected_fields": ("category",)}):
        with pytest.raises(ValidationError, match="INVARIANT"):
            preserves(transform, invariant.model_copy(update=change))
    plan = evaluate_plan(transform, invariant)
    with pytest.raises(ValidationError, match="PLAN"):
        SemanticPlan.model_validate(
            plan.model_dump() | {"invariant": bind_invariant(unrelated, ("action",))}
        )
    first = plan.decisions[0]
    forged = first.model_copy(
        update={"oracle": first.oracle.model_copy(update={"explanation": "Unsupported claim"})}
    )
    with pytest.raises(ValueError, match="INTEGRITY"):
        algebra_artifacts(plan.model_copy(update={"decisions": (forged, *plan.decisions[1:])}))


def test_strict_relation_values_and_invariant_selectors():
    source = context()
    with pytest.raises(ValidationError, match="INVARIANT"):
        bind_invariant(source, ("action", "action"))
    with pytest.raises(ValidationError):
        bind_invariant(source, ("__import__('os')",))
    with pytest.raises(ValidationError, match="VALUE"):
        RelationCheck(
            field="action",
            truth="true",
            expected_json='{"a": 1}',
            actual_json="{}",
            reason_code="fixture",
            explanation="Noncanonical evidence",
        )
    decision = requires(source, source)
    for change in (
        {"truth": "unknown"},
        {"effect": "unknown"},
        {"confidence_before": decision.oracle.confidence},
    ):
        with pytest.raises(ValidationError):
            AlgebraDecision.model_validate(decision.model_dump() | change)
    weakening = weakens(bind_transform(source, missing()), source)
    with pytest.raises(ValidationError, match="CONFIDENCE"):
        AlgebraDecision.model_validate(weakening.model_dump() | {"confidence_before": None})


def test_direct_algebra_rejects_unsafe_values_in_forged_context():
    source = context()
    meaning = SignalMeaning.model_validate(
        source.signal.meaning().model_dump()
        | {
            "source_destination_relation": {
                "direction": "source_to_destination",
                "source": {"address": "8.8.8.8"},
                "destination": {"address": "192.0.2.1"},
            },
        }
    )
    forged = source.model_copy(update={"signal": SemanticSignal.from_meaning(meaning)})
    with pytest.raises(PolicyError):
        requires(source, forged)


def test_executable_example_uses_actual_weakening_and_writes_no_fake_findings(tmp_path):
    script = Path(__file__).parents[1] / "examples/semantic_algebra.py"
    output = tmp_path / "algebra"
    result = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert "support=1.0 -> 0.75" in result.stdout
    plan = SemanticPlan.model_validate_json((output / "semantic_plan.json").read_bytes())
    for name, expected in algebra_artifacts(plan).items():
        assert (output / name).read_bytes() == expected
    rejected = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert rejected.returncode == 2 and "new local directory" in rejected.stderr
    for name, expected in algebra_artifacts(plan).items():
        assert (output / name).read_bytes() == expected
