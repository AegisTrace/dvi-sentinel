"""Nine bounded local evidence checks; no I/O or detector execution (pure analyzer)."""

import re
from collections.abc import Sequence
from datetime import timedelta

from pydantic import JsonValue, TypeAdapter

from dvi_sentinel.adapters import normalize
from dvi_sentinel.differential import compare_semantics
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import Sha256, TelemetryEvent, utc_timestamp
from dvi_sentinel.ontology import extract_signal
from dvi_sentinel.oracle_models import (
    ORACLE_IDS,
    Decision,
    OracleDecision,
    OracleEvidence,
    OracleId,
    OracleResult,
)
from dvi_sentinel.policy import PolicyError, evaluate_events, inspect_content
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.temporal import (
    alert_within_window,
    no_contradictory_context,
    same_correlation_key,
)


def _checked(evidence: OracleEvidence) -> OracleEvidence:
    # Python values retain invalid copied booleans; JSON serialization can coerce them to integers.
    return OracleEvidence.model_validate(evidence.model_dump(mode="python"))


def _policy(evidence: OracleEvidence) -> tuple[str, ...]:
    observations = (
        *evidence.repetitions,
        *((evidence.observation,) if evidence.observation else ()),
    )
    events = (*evidence.events, *(d for row in observations for d in row.detections))
    try:
        decisions = evaluate_events(events)
        if evidence.expected:
            decisions += inspect_content(evidence.expected.model_dump(mode="json"), "expected")
    except PolicyError as exc:
        decisions = exc.decisions
    reasons = {row.rule_id for row in decisions if row.decision == "reject"}
    for representation in evidence.representations:
        adapter = (
            "jsonl"
            if representation.representation == "canonical_jsonl"
            else representation.representation
        )
        normalized = normalize(representation.content.encode("utf-8"), adapter)
        reasons.update(
            issue.code for issue in normalized.errors if issue.code == "DVI-ADAPTER-POLICY"
        )
    return tuple(sorted(reasons))


def _safe(evidence: OracleEvidence) -> OracleEvidence:
    evidence = _checked(evidence)
    if _policy(evidence):
        raise ValueError("DVI-ORACLE-SAFETY: unsafe evidence cannot reach an analyzer")
    return evidence


def _result(
    evidence: OracleEvidence,
    oracle_id: OracleId,
    decision: Decision,
    explanation: str,
    refs: Sequence[str] = (),
    reasons: Sequence[str] = (),
    *,
    confidence: float | None = None,
) -> OracleResult:
    score = (
        (
            1.0
            if decision in {"pass", "fail", "unsafe_rejected"}
            else 0.5
            if decision == "warn"
            else 0.0
        )
        if confidence is None
        else confidence
    )
    codes = tuple(sorted(set(reasons)))
    return OracleResult.from_decision(
        OracleDecision(
            oracle_id=oracle_id,
            subject_id=evidence.subject_id,
            input_digest=evidence.stable_digest(),
            decision=decision,
            confidence=score,
            confidence_basis="Resolution of the supplied finite check: decisive=1, warning<=0.5, "
            "unknown/not-applicable=0; this is not a probability or population estimate.",
            severity=5
            if decision == "unsafe_rejected"
            else 4
            if decision == "fail"
            else 2
            if decision == "warn"
            else 1
            if decision == "pass"
            else 0,
            evidence_refs=tuple(sorted(set(refs))),
            reason_codes=codes,
            explanation=explanation,
            uncertainty=codes if decision in {"unknown", "warn", "not_applicable"} else (),
            blocking=oracle_id in {"safety", "provenance"}
            and decision in {"fail", "unsafe_rejected"},
        )
    )


class SafetyOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _checked(evidence)
        reasons = _policy(evidence)
        return _result(
            evidence,
            "safety",
            "unsafe_rejected" if reasons else "pass",
            "Structural policy checked every input, primary/repeated detection and expectation.",
            ("/events", "/observation", "/repetitions", "/expected"),
            reasons,
        )


class ProvenanceOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence, expected_digest: str | None = None) -> OracleResult:
        evidence = _checked(evidence)
        if expected_digest is None:
            return _result(
                evidence,
                "provenance",
                "unknown",
                "No pinned input digest was supplied.",
                reasons=("provenance_digest_missing",),
            )
        pinned = TypeAdapter(Sha256).validate_python(expected_digest)
        equal = pinned == evidence.stable_digest()
        return _result(
            evidence,
            "provenance",
            "pass" if equal else "unsafe_rejected",
            "Recomputed canonical evidence SHA-256 matches the pinned digest. This verifies "
            "content integrity, not authenticity."
            if equal
            else "Canonical evidence SHA-256 differs from the pinned digest; consumption blocked.",
            reasons=() if equal else ("provenance_digest_mismatch",),
        )


class SchemaOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        return _result(
            evidence,
            "schema",
            "pass" if evidence.events else "unknown",
            "Canonical event and observation schemas, raw digests and unique IDs were revalidated.",
            ("/events", "/observation"),
            () if evidence.events else ("schema_events_missing",),
        )


class SemanticOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        if not evidence.events:
            return _result(
                evidence,
                "semantic",
                "unknown",
                "No semantic input evidence.",
                reasons=("semantic_events_missing",),
            )
        extractions = tuple(extract_signal(event) for event in evidence.events)
        losses = tuple(
            sorted({finding.loss_class for row in extractions for finding in row.findings})
        )
        if losses:
            return _result(
                evidence,
                "semantic",
                "unknown",
                "Ontology requirements remain unresolved.",
                ("/events",),
                losses,
            )
        context = no_contradictory_context(evidence.events)
        return _result(
            evidence,
            "semantic",
            "warn" if context.outcome == "contradicted" else "pass",
            "Complete ontology bindings; explicit benign/control labels are contradictory context.",
            ("/events",),
            context.reason_codes,
        )


def _select(data: JsonValue, pointer: str) -> JsonValue:
    for part in pointer.split("/")[1:]:
        if isinstance(data, dict):
            data = data.get(part)
        elif (
            isinstance(data, list) and part.isdecimal() and len(part) <= 3 and int(part) < len(data)
        ):
            data = data[int(part)]
        else:
            return None
    return data


class EvidenceOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        # Core requirements cannot be removed by empty caller configuration.
        paths = tuple(
            sorted(set(evidence.required_paths) | {"/events", "/expected", "/observation"})
        )
        data = parse_json(evidence.model_dump_json())
        missing = tuple(path for path in paths if _select(data, path) in (None, "", [], {}))
        return _result(
            evidence,
            "evidence",
            "unknown" if missing else "pass",
            "Missing required paths: " + ", ".join(missing)[:900]
            if missing
            else "All required paths resolve to values; this does not authenticate them.",
            paths,
            ("required_evidence_missing",) if missing else (),
        )


class DetectionOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        if evidence.expected is None or evidence.observation is None:
            return _result(
                evidence,
                "detection",
                "unknown",
                "Expected/observed detection evidence is missing.",
                reasons=("detection_evidence_missing",),
            )
        match = match_detection(evidence.expected, evidence.observation, evidence.events)
        return _result(
            evidence,
            "detection",
            "pass"
            if match.status == "detected"
            else "fail"
            if match.status == "missed"
            else "unknown",
            match.explanation,
            ("/events", "/expected", "/observation"),
            (match.reason,),
        )


def _precision_known(events: Sequence[TelemetryEvent], digits: int) -> bool:
    if not digits:
        return True
    for event in events:
        source = event.raw.original_timestamp
        match = re.fullmatch(r".{19}(?:\.(\d{1,6}))?(?:Z|[+-]\d{2}:\d{2})", source or "")
        if match is None or len(match.group(1) or "") < digits or source is None:
            return False
        try:
            if utc_timestamp(source) != event.timestamp:
                return False
        except ValueError:
            return False
    return True


class TemporalOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        expected, observation = evidence.expected, evidence.observation
        if (
            expected is None
            or observation is None
            or observation.status != "complete"
            or not evidence.events
        ):
            return _result(
                evidence,
                "temporal",
                "unknown",
                "Complete timing evidence is unavailable.",
                reasons=("temporal_evidence_missing",),
            )
        context = no_contradictory_context(evidence.events)
        if context.outcome == "contradicted":
            return _result(
                evidence,
                "temporal",
                "warn",
                "Explicit benign/control event context suppresses attribution.",
                ("/events",),
                context.reason_codes,
            )
        # Only declared detector candidates participate. No synthetic alert or event reference.
        candidates = tuple(d for d in observation.detections if d.detector == expected.detector)
        if not candidates:
            return _result(
                evidence,
                "temporal",
                "unknown",
                "No alert exists to measure its time; matcher miss is retained separately.",
                ("/observation",),
                ("alert_evidence_missing",),
            )
        indexed = {event.event_id: event for event in evidence.events}
        outcomes: list[str] = []
        reasons: set[str] = set()
        for candidate in candidates:
            ids = expected.event_ids or candidate.related_event_ids
            sources = (
                tuple(indexed[key] for key in ids if key in indexed)
                if ids
                else (evidence.events if len(evidence.events) == 1 else ())
            )
            source = (
                max(sources, key=lambda event: (event.timestamp, event.event_id))
                if sources
                else None
            )
            if expected.reference_time is None and (
                source is None or (ids and len(sources) != len(ids))
            ):
                outcomes.append("unknown")
                reasons.add("time_reference_missing")
                continue
            precise = _precision_known((*sources, candidate), evidence.precision_digits)
            if expected.reference_time is not None and evidence.precision_digits:
                precise = False  # The expectation has no retained source-resolution record.
            if not precise:
                outcomes.append("unknown")
                reasons.add("timestamp_precision_loss")
                continue
            if expected.reference_time is not None:
                delta = candidate.timestamp - expected.reference_time
                time_state = (
                    "supported"
                    if timedelta(0) <= delta <= timedelta(milliseconds=expected.max_delay_ms)
                    else "contradicted"
                )
            else:
                assert source is not None
                time_state = alert_within_window(source, candidate, expected.max_delay_ms).outcome
            if expected.correlation_id is not None:
                if (
                    source is None
                    or source.correlation_id is None
                    or candidate.correlation_id is None
                ):
                    time_state = "unknown"
                    reasons.add("correlation_key_missing")
                elif (
                    same_correlation_key(source, candidate).outcome != "supported"
                    or candidate.correlation_id != expected.correlation_id
                ):
                    time_state = "contradicted"
                    reasons.add("correlation_key_mismatch")
            outcomes.append(time_state)
        status: Decision = (
            "pass" if "supported" in outcomes else "unknown" if "unknown" in outcomes else "fail"
        )
        return _result(
            evidence,
            "temporal",
            status,
            "Evaluate finite alert windows and declared key equality; retain existential candidate "
            "support and missing time/precision evidence.",
            ("/events", "/expected", "/observation"),
            tuple(reasons) or (("alert_outside_window",) if status == "fail" else ()),
        )


class DifferentialOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        if not evidence.representations:
            return _result(
                evidence,
                "differential",
                "not_applicable",
                "No optional representation comparison was requested.",
            )
        reasons: set[str] = set()
        unknown = False
        for representation in evidence.representations:
            adapter = (
                "jsonl"
                if representation.representation == "canonical_jsonl"
                else representation.representation
            )
            normalized = normalize(representation.content.encode("utf-8"), adapter)
            if not normalized.parser_success:
                unknown = True
                reasons.add("representation_unresolved")
            else:
                differences = compare_semantics(evidence.events, normalized.events)
                reasons.update(item.finding_class for item in differences)
        return _result(
            evidence,
            "differential",
            "unknown" if unknown else "warn" if reasons else "pass",
            "Independently normalize supplied representations and compare actual fields with the "
            "canonical inputs. Differences limit confidence without adding a matcher vote.",
            ("/events", "/representations"),
            tuple(reasons),
        )


class StatisticalOracle:
    @staticmethod
    def evaluate(evidence: OracleEvidence) -> OracleResult:
        evidence = _safe(evidence)
        if not evidence.repetitions:
            return _result(
                evidence,
                "statistical",
                "not_applicable",
                "No optional repeated local observations were supplied.",
            )
        if evidence.expected is None:
            return _result(
                evidence,
                "statistical",
                "unknown",
                "Repetitions need a declared detection expectation.",
                reasons=("statistical_expectation_missing",),
            )
        statuses = tuple(
            match_detection(evidence.expected, row, evidence.events).status
            for row in evidence.repetitions
        )
        unknown = statuses.count("unknown")
        enough = len(statuses) >= evidence.minimum_repetitions
        uniform = len(set(statuses)) == 1 and not unknown
        state: Decision = (
            "fail"
            if uniform and enough and statuses[0] == "missed"
            else ("pass" if uniform and enough else "warn")
        )
        reasons = tuple(
            code
            for applies, code in (
                (not enough, "statistical_small_sample"),
                (bool(unknown), "statistical_unknown_samples"),
                (not uniform, "statistical_mixed_outcomes"),
            )
            if applies
        )
        return _result(
            evidence,
            "statistical",
            state,
            f"Finite repeats: n={len(statuses)}, detected={statuses.count('detected')}, "
            f"missed={statuses.count('missed')}, unknown={unknown}; "
            f"required n={evidence.minimum_repetitions}. "
            "Repeatability does not establish independent samples or population significance.",
            ("/repetitions", "/expected", "/events"),
            reasons,
            confidence=min(0.5, (len(statuses) - unknown) / len(statuses))
            if state == "warn"
            else 1.0,
        )


def evaluate_oracles(
    evidence: OracleEvidence, *, expected_digest: str | None = None
) -> tuple[OracleResult, ...]:
    """Revalidate inputs, apply authoritative gates, then run independent local checks."""
    evidence = _checked(evidence)
    safety = SafetyOracle.evaluate(evidence)
    provenance = ProvenanceOracle.evaluate(evidence, expected_digest)
    if safety.blocking or provenance.blocking:
        results = (
            safety,
            provenance,
            *(
                _result(
                    evidence,
                    name,
                    "not_applicable",
                    "Consumption blocked by safety/provenance.",
                    reasons=("consumption_blocked",),
                )
                for name in ORACLE_IDS
                if name not in {"safety", "provenance"}
            ),
        )
    else:
        results = (
            safety,
            provenance,
            SchemaOracle.evaluate(evidence),
            SemanticOracle.evaluate(evidence),
            EvidenceOracle.evaluate(evidence),
            DetectionOracle.evaluate(evidence),
            TemporalOracle.evaluate(evidence),
            DifferentialOracle.evaluate(evidence),
            StatisticalOracle.evaluate(evidence),
        )
    return tuple(sorted(results, key=lambda row: row.oracle_id))
