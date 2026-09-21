"""Conservative combination and canonical artifacts for a local detection-gap claim."""

from collections.abc import Sequence

from dvi_sentinel.artifact_models import MAX_ARTIFACT_BYTES
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_models import (
    GATE_IDS,
    ORACLE_IDS,
    VOTER_IDS,
    ConsensusState,
    OracleConsensus,
    OracleEvidence,
    OracleMatrix,
    OracleMatrixCell,
    OracleResult,
    UncertaintyReport,
)
from dvi_sentinel.run_artifacts import json_bytes, jsonl_bytes


def build_consensus(decisions: Sequence[OracleResult]) -> OracleConsensus:
    """Guard passes are eligibility checks; they never vote down a measured detection gap."""
    if not 1 <= len(decisions) <= 9:
        raise ValueError("DVI-ORACLE-BOUNDS: require 1..9 distinct oracle decisions")
    ordered = tuple(
        sorted(
            (OracleResult.model_validate(row.model_dump(mode="python")) for row in decisions),
            key=lambda row: row.oracle_id,
        )
    )
    indexed = {row.oracle_id: row for row in ordered}
    if len(indexed) != len(ordered):
        raise ValueError("DVI-ORACLE-IDENTITY: duplicate oracle identity")
    if len({(row.subject_id, row.input_digest) for row in ordered}) != 1:
        raise ValueError("DVI-ORACLE-IDENTITY: decisions belong to different subjects or evidence")
    missing = tuple(name for name in ORACLE_IDS if name not in indexed)
    blocked = tuple(row.oracle_id for row in ordered if row.blocking)
    supporters = tuple(
        row.oracle_id for row in ordered if row.oracle_id in VOTER_IDS and row.decision == "fail"
    )
    opponents = tuple(
        row.oracle_id for row in ordered if row.oracle_id in VOTER_IDS and row.decision == "pass"
    )
    disagreements = tuple(sorted((*supporters, *opponents))) if supporters and opponents else ()
    benign = all(
        name in indexed and "contradictory_benign_context" in indexed[name].reason_codes
        for name in ("semantic", "temporal")
    )
    failed_gates = any(
        name not in indexed or indexed[name].decision != "pass" or indexed[name].confidence < 0.75
        for name in GATE_IDS
        if not (benign and name == "semantic")
    )
    required_missing = any(name in missing for name in ("detection", "temporal"))
    unresolved = any(
        row.decision == "unknown"
        or (row.oracle_id in {"detection", "temporal"} and row.decision == "not_applicable")
        for row in ordered
    )
    warnings = any(row.decision == "warn" for row in ordered)
    confidence = 0.0
    state: ConsensusState
    if blocked:
        state, confidence = "unsafe_rejected", 1.0
        explanation = (
            "Safety or provenance integrity blocked consumption; other votes cannot override it."
        )
    elif failed_gates or required_missing:
        state = "not_enough_evidence"
        explanation = "Required gate or diagnostic evidence is unresolved."
    elif benign:
        state, confidence = "suppressed_false_positive", 0.5
        explanation = (
            "Semantic and temporal checks record benign/control context; attribution is suppressed."
        )
    elif disagreements:
        state, confidence = "ambiguous", 0.5 if not unresolved else 0.0
        explanation = "Diagnostics disagree; all supporting and opposing decisions remain recorded."
    elif unresolved:
        state = "unknown" if not supporters and not opponents else "not_enough_evidence"
        explanation = (
            "Missing diagnostic evidence prevents confirmation despite other decisive checks."
        )
    elif len(supporters) >= 2:
        confidence = min(indexed[name].confidence for name in supporters)
        confidence = min(confidence, 0.5) if warnings else confidence
        state = "confirmed" if confidence >= 0.75 else "probable"
        explanation = (
            "Multiple diagnostics support a local gap; warnings cap confirmation strength."
        )
    elif len(opponents) >= 2 and not warnings:
        state = "suppressed_false_positive"
        confidence = min(indexed[name].confidence for name in opponents)
        explanation = (
            "Multiple diagnostic checks support the detection contract and oppose the proposed gap."
        )
    elif supporters:
        state, confidence = "probable", min(0.5, indexed[supporters[0]].confidence)
        explanation = (
            "One diagnostic check suggests a gap; another must corroborate it before confirmation."
        )
    else:
        state = "not_enough_evidence"
        explanation = (
            "Available diagnostics do not provide multiple resolved checks of the proposed gap."
        )
    return OracleConsensus(
        subject_id=ordered[0].subject_id,
        input_digest=ordered[0].input_digest,
        state=state,
        confidence=confidence,
        decisions=ordered,
        confidence_basis="Minimum supporting check resolution; any warning caps at 0.5 and missing "
        "required evidence at 0. No statistical independence or population probability is assumed.",
        supporting_oracles=supporters,
        opposing_oracles=opponents,
        blocking_oracles=blocked,
        missing_oracles=missing,
        disagreements=disagreements,
        explanation=explanation,
    )


def oracle_artifacts(
    evidence: OracleEvidence, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    """Recompute every result from actual evidence before producing four bounded artifacts."""
    decisions = evaluate_oracles(evidence, expected_digest=expected_digest)
    summary = build_consensus(decisions)
    if not summary.blocking_oracles:
        summary = OracleConsensus.model_validate(
            summary.model_dump(mode="json")
            | {
                "evidence": evidence.model_dump(mode="json"),
            }
        )
    unresolved = tuple(row.oracle_id for row in decisions if row.decision in {"unknown", "warn"})
    uncertainty = UncertaintyReport(
        subject_id=summary.subject_id,
        input_digest=summary.input_digest,
        state=summary.state,
        confidence=summary.confidence,
        unresolved_oracles=unresolved,
        reason_codes=tuple(sorted({reason for row in decisions for reason in row.uncertainty})),
        explanation=summary.explanation,
    )
    matrix = OracleMatrix(
        subject_id=summary.subject_id,
        input_digest=summary.input_digest,
        cells=tuple(
            OracleMatrixCell(
                oracle_id=row.oracle_id,
                role="gate"
                if row.oracle_id in GATE_IDS
                else "diagnostic"
                if row.oracle_id in VOTER_IDS
                else "corroborating",
                decision=row.decision,
                confidence=row.confidence,
                result_digest=row.digest,
            )
            for row in decisions
        ),
    )
    artifacts = {
        "oracle_decisions.jsonl": jsonl_bytes(decisions),
        "oracle_consensus.json": json_bytes(summary),
        "uncertainty_report.json": json_bytes(uncertainty),
        "oracle_matrix.json": json_bytes(matrix),
    }
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError("DVI-ORACLE-BOUNDS: combined artifacts exceed 32 MiB")
    return artifacts
