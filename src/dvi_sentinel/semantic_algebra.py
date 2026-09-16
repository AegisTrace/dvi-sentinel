"""Executable, bounded semantic relations over trusted local ontology evidence."""

from pydantic import JsonValue

from dvi_sentinel.ontology import semantic_equivalence
from dvi_sentinel.ontology_models import OntologyExtraction, SemanticFinding, SignalMeaning
from dvi_sentinel.policy import PolicyError, inspect_content
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes
from dvi_sentinel.score_models import Ratio
from dvi_sentinel.semantic_algebra_models import (
    AlgebraDecision,
    Effect,
    Evidence,
    Invariant,
    Operation,
    OracleDecision,
    OracleResult,
    Relation,
    RelationCheck,
    SemanticPlan,
    Signal,
    Transform,
    Truth,
)
from dvi_sentinel.serialization import canonical_json, digest, parse_json


def _checked(value: Evidence) -> Evidence:
    if len(value.bindings) > 64 or len(value.findings) > 256:
        raise ValueError("DVI-ALGEBRA-BOUNDS: at most 64 bindings and 256 findings per context")
    json_bytes(value)
    value = OntologyExtraction.model_validate(value.model_dump())
    decisions = list(inspect_content(value.signal.model_dump(mode="json"), "signal"))
    for observable in (
        *value.signal.resource,
        *value.signal.evidence,
        *(item for binding in value.bindings for item in binding.candidates),
    ):
        if observable.value_json is not None:
            decisions.extend(
                inspect_content(
                    {observable.field.split(".")[-1]: parse_json(observable.value_json)},
                    "evidence",
                )
            )
    if decisions:
        raise PolicyError(tuple(decisions))
    return value


def _row(
    field: str,
    truth: Truth,
    expected: str | None,
    actual: str | None,
    reason: str,
) -> RelationCheck:
    return RelationCheck(
        field=field,
        truth=truth,
        expected_json=expected,
        actual_json=actual,
        reason_code=reason,
        explanation=reason.replace("_", " ").lower(),
    )


def _all(checks: tuple[RelationCheck, ...]) -> Truth:
    if any(check.truth == "false" for check in checks):
        return "false"
    return "unknown" if not checks or any(check.truth == "unknown" for check in checks) else "true"


def _ratio(checks: tuple[RelationCheck, ...]) -> Ratio:
    count = sum(check.truth == "true" for check in checks)
    total = len(checks)
    return Ratio(numerator=count, denominator=total, value=count / total if total else None)


def _requirements(signal: Signal, evidence: Evidence) -> tuple[RelationCheck, ...]:
    expected = {item.field: item for item in signal.signal.evidence}
    actual = {item.specification.field: item.observable for item in evidence.bindings}
    checks = []
    for field in signal.signal.evidence_requirements:
        wanted, observed = expected.get(field), actual.get(field)
        desired = wanted.value_json if wanted else None
        if observed is None or observed.state != "known":
            checks.append(_row(field, "unknown", desired, None, "REQUIRED_EVIDENCE_UNRESOLVED"))
            continue
        if field == "confidence" and signal.signal.confidence_requirement is not None:
            value = parse_json(observed.value_json or "null")
            supported = isinstance(value, int | float) and not isinstance(value, bool)
            threshold = signal.signal.confidence_requirement
            passed = supported and isinstance(value, int | float) and value >= threshold
            checks.append(
                _row(
                    field,
                    "true" if passed else "false" if supported else "unknown",
                    canonical_json(threshold),
                    observed.value_json,
                    "CONFIDENCE_REQUIREMENT_SATISFIED"
                    if passed
                    else "CONFIDENCE_REQUIREMENT_UNMET",
                )
            )
        elif any(finding.field == field for finding in evidence.findings):
            checks.append(
                _row(field, "unknown", desired, observed.value_json, "REQUIRED_EVIDENCE_HAS_LOSS")
            )
        elif wanted is not None and wanted.state != "known":
            checks.append(
                _row(
                    field, "unknown", desired, observed.value_json, "REFERENCE_EVIDENCE_UNRESOLVED"
                )
            )
        else:
            equal = wanted is None or desired == observed.value_json
            checks.append(
                _row(
                    field,
                    "true" if equal else "false",
                    desired,
                    observed.value_json,
                    "REQUIRED_EVIDENCE_SATISFIED" if equal else "REQUIRED_EVIDENCE_CONTRADICTED",
                )
            )
    return tuple(checks)


def _compare(
    reference: Signal, candidate: Signal, fields: tuple[str, ...]
) -> tuple[RelationCheck, ...]:
    before, after = (
        reference.signal.meaning().model_dump(mode="json"),
        candidate.signal.meaning().model_dump(mode="json"),
    )
    left = {item.specification.field: item.observable for item in reference.bindings}
    right = {item.specification.field: item.observable for item in candidate.bindings}
    checks = []
    for field in fields:
        if field.startswith("evidence."):
            name = field.removeprefix("evidence.")
            expected, actual = left.get(name), right.get(name)
            known = (
                expected is not None
                and actual is not None
                and expected.state == actual.state == "known"
            )
            known = known and not any(
                f.field == name for context in (reference, candidate) for f in context.findings
            )
            wanted = expected.value_json if expected else None
            observed = actual.value_json if actual else None
        elif field in before:
            known, wanted, observed = (
                True,
                canonical_json(before[field]),
                canonical_json(after[field]),
            )
            if wanted != observed:
                if field in {"resource", "evidence"}:
                    left_values = {item["field"]: item for item in before[field]}
                    right_values = {item["field"]: item for item in after[field]}
                    for name in left_values.keys() | right_values.keys():
                        a, b = left_values.get(name), right_values.get(name)
                        if a != b and (
                            a is None or b is None or a["state"] != "known" or b["state"] != "known"
                        ):
                            known = False
                elif field == "source_destination_relation":
                    known = all(
                        before[field][role] is not None and after[field][role] is not None
                        for role in ("source", "destination")
                    )
                elif field == "protocol":
                    known = before[field] is not None and after[field] is not None
                elif field == "outcome":
                    known = before[field] != "unknown" and after[field] != "unknown"
        else:
            checks.append(_row(field, "unknown", None, None, "UNSUPPORTED_INVARIANT_FIELD"))
            continue
        checks.append(
            _row(
                field,
                "unknown" if not known else "true" if wanted == observed else "false",
                wanted,
                observed,
                "PROTECTED_FIELD_UNRESOLVED"
                if not known
                else "PROTECTED_FIELD_PRESERVED"
                if wanted == observed
                else "PROTECTED_FIELD_CHANGED",
            )
        )
    return tuple(checks)


def _decision(
    operation: Operation,
    subjects: tuple[str, ...],
    truth: Truth,
    checks: tuple[RelationCheck, ...],
    reference: Signal,
    evidence: Evidence,
    explanation: str,
    *,
    before: Ratio | None = None,
) -> AlgebraDecision:
    support = _ratio(_requirements(reference, evidence))
    relation = Relation(operation=operation, subjects=subjects)
    effect: Effect = (
        "unknown"
        if truth == "unknown"
        else "not_supported"
        if truth == "false"
        else ("suppressed_false_positive" if operation == "contradicts" else "supported")
    )
    oracle_decision: OracleDecision = (
        "pass" if truth == "true" else ("fail" if truth == "false" else "unknown")
    )
    return AlgebraDecision(
        relation=relation,
        truth=truth,
        effect=effect,
        checks=checks,
        oracle=OracleResult(
            oracle_id=f"semantic-algebra:{operation}",
            subject_id="relation:" + relation.stable_digest(),
            decision=oracle_decision,
            confidence=support,
            reason_codes=tuple(sorted({check.reason_code for check in checks})),
            evidence_refs=tuple(sorted({reference.event_digest, evidence.event_digest})),
            explanation=explanation,
            blocking=effect != "supported",
        ),
        confidence_before=before,
        confidence_after=support if operation == "weakens" else None,
    )


def bind_invariant(reference: Signal, fields: tuple[str, ...]) -> Invariant:
    reference = _checked(reference)
    ordered = tuple(sorted(fields))
    return Invariant(
        invariant_id="invariant:"
        + digest({"reference": reference.stable_digest(), "fields": list(ordered)}),
        protected_fields=ordered,
        reference=reference,
        explanation="Preserve the declared fields against this evidence reference.",
    )


def bind_transform(source: Signal, destination: Signal) -> Transform:
    source, destination = _checked(source), _checked(destination)
    change = semantic_equivalence(source, destination).transform
    identity = digest(
        {"source": source.stable_digest(), "destination": destination.stable_digest()}
    )
    return Transform.model_validate(
        change.model_dump()
        | {
            "transform_id": f"transform:{identity}",
            "source": source,
            "destination": destination,
        }
    )


def requires(signal: Signal, evidence: Evidence) -> AlgebraDecision:
    signal, evidence = _checked(signal), _checked(evidence)
    checks = _requirements(signal, evidence)
    truth = _all(checks)
    if signal.state != "known" or (truth == "true" and evidence.state != "known"):
        truth = "unknown"
    return _decision(
        "requires",
        (signal.stable_digest(), evidence.stable_digest()),
        truth,
        checks,
        signal,
        evidence,
        "Check required evidence values and presence under the reference contract.",
    )


def preserves(transform: Transform, invariant: Invariant) -> AlgebraDecision:
    transform = Transform.model_validate(transform.model_dump())
    invariant = Invariant.model_validate(invariant.model_dump())
    source, destination = _checked(transform.source), _checked(transform.destination)
    if invariant.reference != source:
        raise ValueError("DVI-ALGEBRA-REFERENCE: invariant must reference the transform source")
    checks = _compare(source, destination, invariant.protected_fields)
    truth = _all(checks)
    if source.state != "known" or (truth == "true" and destination.state != "known"):
        truth = "unknown"
    return _decision(
        "preserves",
        (transform.transform_id, invariant.invariant_id),
        truth,
        checks,
        source,
        destination,
        "Compare actual protected values; unresolved contexts cannot prove preservation.",
    )


def contradicts(evidence: Evidence, invariant: Invariant) -> AlgebraDecision:
    invariant = Invariant.model_validate(invariant.model_dump())
    reference, evidence = _checked(invariant.reference), _checked(evidence)
    compared = _compare(reference, evidence, invariant.protected_fields)
    checks = tuple(
        check.model_copy(
            update={"truth": {"true": "false", "false": "true", "unknown": "unknown"}[check.truth]}
        )
        for check in compared
    )
    truth: Truth = (
        "true"
        if any(check.truth == "true" for check in checks)
        else (
            "unknown"
            if evidence.state != "known" or any(check.truth == "unknown" for check in checks)
            else "false"
        )
    )
    if reference.state != "known":
        truth = "unknown"
    return _decision(
        "contradicts",
        (evidence.stable_digest(), invariant.invariant_id),
        truth,
        checks,
        reference,
        evidence,
        "A known protected-value contradiction suppresses the reference signal assertion.",
    )


def implies(signal_a: Signal, signal_b: Signal) -> AlgebraDecision:
    source, target = _checked(signal_a), _checked(signal_b)
    excluded = {
        "evidence",
        "evidence_requirements",
        "confidence_requirement",
        "correlation_requirement",
        "timestamp_precision_digits",
    }
    fields = tuple(sorted(set(SignalMeaning.model_fields) - excluded))
    checks = list(_compare(source, target, fields))
    left, right = source.signal, target.signal

    def constraint(name: str, passed: bool, expected: JsonValue, actual: JsonValue) -> None:
        checks.append(
            _row(
                name,
                "true" if passed else "false",
                canonical_json(expected),
                canonical_json(actual),
                "IMPLICATION_CONSTRAINT_SATISFIED" if passed else "IMPLICATION_CONSTRAINT_UNMET",
            )
        )

    constraint(
        "evidence_requirements",
        set(right.evidence_requirements) <= set(left.evidence_requirements),
        list(right.evidence_requirements),
        list(left.evidence_requirements),
    )
    threshold = right.confidence_requirement
    constraint(
        "confidence_requirement",
        threshold is None
        or (left.confidence_requirement is not None and left.confidence_requirement >= threshold),
        threshold,
        left.confidence_requirement,
    )
    constraint(
        "timestamp_precision_digits",
        left.timestamp_precision_digits >= right.timestamp_precision_digits,
        right.timestamp_precision_digits,
        left.timestamp_precision_digits,
    )
    constraint(
        "correlation_requirement",
        right.correlation_requirement == "optional" or left.correlation_requirement == "required",
        right.correlation_requirement,
        left.correlation_requirement,
    )
    evidence_a = {item.field: item for item in left.evidence}
    for item in right.evidence:
        other = evidence_a.get(item.field)
        checks.append(
            _row(
                "evidence." + item.field,
                "true" if other == item else "false",
                canonical_json(item),
                canonical_json(other) if other else None,
                "TARGET_EVIDENCE_SUPPORTED" if other == item else "TARGET_EVIDENCE_UNSUPPORTED",
            )
        )
    rows = tuple(checks)
    truth = _all(rows) if source.state == target.state == "known" else "unknown"
    return _decision(
        "implies",
        (source.stable_digest(), target.stable_digest()),
        truth,
        rows,
        target,
        source,
        "Matching core meaning and stronger evidence constraints imply this target contract.",
    )


def equivalent(signal_a: Signal, signal_b: Signal) -> AlgebraDecision:
    source, destination = _checked(signal_a), _checked(signal_b)
    comparison = semantic_equivalence(source, destination)
    truth: Truth = (
        "true"
        if comparison.decision == "equivalent"
        else ("false" if comparison.decision == "different" else "unknown")
    )
    checks = _compare(source, destination, comparison.invariant.protected_fields)
    return _decision(
        "equivalent",
        (source.stable_digest(), destination.stable_digest()),
        truth,
        checks,
        source,
        destination,
        comparison.explanation,
    )


def weakens(transform: Transform, signal: Signal) -> AlgebraDecision:
    transform = Transform.model_validate(transform.model_dump())
    signal, candidate = _checked(signal), _checked(transform.destination)
    if signal != transform.source:
        raise ValueError("DVI-ALGEBRA-REFERENCE: weakening must use the actual source signal")
    before, after = _ratio(_requirements(signal, signal)), _ratio(_requirements(signal, candidate))
    truth: Truth = "unknown"
    if signal.state == "known" and before.value is not None and after.value is not None:
        if after.value < before.value:
            truth = "true"
        elif candidate.state == "known":
            truth = "false"
    checks = (
        _row(
            "evidence_support",
            truth,
            canonical_json(before),
            canonical_json(after),
            "EVIDENCE_SUPPORT_DECREASED" if truth == "true" else "NO_PROVEN_SUPPORT_DECREASE",
        ),
    )
    return _decision(
        "weakens",
        (transform.transform_id, signal.stable_digest()),
        truth,
        checks,
        signal,
        candidate,
        "Compare required-evidence support fractions, without estimating detector effectiveness.",
        before=before,
    )


def explains(finding: SemanticFinding, evidence: Evidence) -> AlgebraDecision:
    evidence = _checked(evidence)
    finding = SemanticFinding.model_validate(finding.model_dump())
    linked = finding.event_id == evidence.event_id and finding in evidence.findings
    available = {item.specification.field for item in evidence.bindings}
    available.update({"timestamp_precision"} if "source_time_text" in available else set())
    resolved = all(field in available for field in finding.evidence_refs)
    truth: Truth = "false" if not linked else "true" if resolved else "unknown"
    checks = (
        _row(
            finding.field,
            truth,
            canonical_json(list(finding.evidence_refs)),
            canonical_json([field for field in sorted(available)]),
            "FINDING_LINK_SUPPORTED"
            if truth == "true"
            else "FINDING_LINK_UNSUPPORTED"
            if truth == "false"
            else "FINDING_SUPPORT_UNAVAILABLE",
        ),
    )
    return _decision(
        "explains",
        (finding.finding_id, evidence.stable_digest()),
        truth,
        checks,
        evidence,
        evidence,
        "Verify a recorded finding's source association and available evidence references.",
    )


def evaluate_plan(transform: Transform, invariant: Invariant) -> SemanticPlan:
    """Six core relations plus one explanation per actual destination finding."""
    transform = Transform.model_validate(transform.model_dump())
    invariant = Invariant.model_validate(invariant.model_dump())
    source, destination = _checked(transform.source), _checked(transform.destination)
    decisions = (
        preserves(transform, invariant),
        requires(source, destination),
        contradicts(destination, invariant),
        implies(source, destination),
        equivalent(source, destination),
        weakens(transform, source),
        *(explains(finding, destination) for finding in destination.findings),
    )
    return SemanticPlan(transform=transform, invariant=invariant, decisions=decisions)


def algebra_artifacts(plan: SemanticPlan) -> dict[str, bytes]:
    plan = SemanticPlan.model_validate(plan.model_dump())
    replay = evaluate_plan(plan.transform, plan.invariant)
    if plan != replay:
        raise ValueError(
            "DVI-ALGEBRA-INTEGRITY: decisions differ from evaluation of their evidence"
        )
    return {
        "semantic_plan.json": json_bytes(plan),
        "algebra_decisions.jsonl": jsonl_bytes(plan.decisions),
    }
