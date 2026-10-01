"""Read typed V2 evidence from captured, verified bytes and check run scope (A)."""

from collections.abc import Mapping

from pydantic import BaseModel

from dvi_sentinel.advanced_report_models import AdvancedEvidence
from dvi_sentinel.artifact_models import RunRecord, VariationArtifact
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.confidence_models import ConfidenceReport
from dvi_sentinel.consensus_shrinking_models import OracleShrinkInput, OracleShrinkReport
from dvi_sentinel.counterfactual_models import CounterfactualInput, CounterfactualSummary
from dvi_sentinel.detection_intent import analyze_intent
from dvi_sentinel.harness_models import HarnessResult
from dvi_sentinel.intent_models import IntentAnalysis
from dvi_sentinel.knowledge_graph_models import GraphReport
from dvi_sentinel.metamorphic import analyze_representations
from dvi_sentinel.metamorphic_models import MetamorphicReport
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.ontology import extract_signal
from dvi_sentinel.oracle_consensus import oracle_artifacts
from dvi_sentinel.oracle_models import OracleConsensus
from dvi_sentinel.serialization import digest, parse_json
from dvi_sentinel.temporal_models import TemporalSummary

ANALYSIS_PATHS = {
    "intent": "semantic_loss_report.json",
    "mapping": "metamorphic_report.json",
    "temporal": "temporal_summary.json",
    "oracle": "oracle_consensus.json",
    "counterfactual": "counterfactual_summary.json",
    "confidence": "confidence.json",
    "graph": "detection_graph.json",
    "minimum": "shrunk_case.json",
}


def read_rows[T: BaseModel](data: bytes, model: type[T]) -> tuple[T, ...]:
    return tuple(model.model_validate(parse_json(row)) for row in data.splitlines())


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("DVI-REPORT-EVIDENCE: " + message)


def advanced_evidence(contents: Mapping[str, bytes]) -> AdvancedEvidence:
    """Never infer analyses from file presence alone or accept an unrelated run's evidence."""
    run = RunRecord.model_validate(parse_json(contents["run.json"]))
    events = read_rows(contents["normalized_events.jsonl"], TelemetryEvent)
    _require(len(events) <= 128, "advanced reports support at most 128 baseline events")
    cases = {
        row.variation.id: row.variation
        for row in read_rows(contents["variations.jsonl"], VariationArtifact)
    }
    observations = {
        row.case_id: row for row in read_rows(contents["observations.jsonl"], HarnessResult)
    }

    def optional[T: BaseModel](name: str, model: type[T]) -> T | None:
        path = ANALYSIS_PATHS[name]
        return model.model_validate(parse_json(contents[path])) if path in contents else None

    intent = optional("intent", IntentAnalysis)
    mapping = optional("mapping", MetamorphicReport)
    temporal = optional("temporal", TemporalSummary)
    oracle = optional("oracle", OracleConsensus)
    counterfactual = optional("counterfactual", CounterfactualSummary)
    confidence = optional("confidence", ConfidenceReport)
    graph = optional("graph", GraphReport)
    minimum = optional("minimum", OracleShrinkReport)
    if intent:
        _require(intent == analyze_intent(intent.parsed, events), "intent event support differs")
    if mapping:
        _require(mapping.state != "unsafe_rejected", "mapping safety gate failed")
        if mapping.input:
            _require(mapping.input.source in events, "mapping source belongs to another run")
            _require(
                mapping
                == analyze_representations(mapping.input, expected_digest=mapping.input_digest),
                "mapping differs from retained inputs",
            )
    if temporal:
        by_id = {event.event_id: event for event in events}
        _require(set(temporal.ordered_event_ids) == set(by_id), "temporal event coverage differs")
        _require(
            temporal.input_digest
            == digest([by_id[event_id].stable_digest() for event_id in temporal.ordered_event_ids]),
            "temporal input digest differs",
        )
        states = {t.check.outcome for t in temporal.traces}
        _require(
            temporal.state
            == (
                "unknown"
                if "unknown" in states
                else "contradicted"
                if "contradicted" in states
                else "supported"
            ),
            "temporal aggregate differs from recorded checks",
        )
    if oracle:
        _require(oracle.state != "unsafe_rejected", "oracle safety gate failed")
        if oracle.evidence:
            source = oracle.evidence
            case = cases.get(source.subject_id)
            _require(
                case is not None
                and source.events == case.events
                and source.expected == run.configuration.expected
                and source.observation == observations.get(source.subject_id),
                "oracle case or observation belongs to another run",
            )
            reproduced = oracle_artifacts(source, expected_digest=source.stable_digest())
            _require(
                oracle == OracleConsensus.model_validate_json(reproduced["oracle_consensus.json"]),
                "oracle decisions differ from retained evidence",
            )
        else:
            _require(oracle.state in {"unknown", "not_enough_evidence"}, "oracle lacks case proof")
    if counterfactual:
        _require(counterfactual.state != "unsafe_rejected", "counterfactual safety gate failed")
        if counterfactual.input:
            source_cf = counterfactual.input
            expected_cf = CounterfactualInput.model_validate(
                source_cf.model_dump()
                | {
                    "events": events,
                    "policy": run.configuration.variations,
                    "expected": run.configuration.expected,
                    "harness": run.configuration.harness,
                    "seed": run.seed,
                }
            )
            _require(source_cf == expected_cf, "counterfactual context belongs to another run")
    if confidence:
        _require(confidence.state != "unsafe_rejected", "statistical safety gate failed")
        if confidence.input:
            snapshot = ComparisonSnapshot.model_validate(parse_json(contents["comparison.json"]))
            canonical = snapshot.model_copy(
                update={
                    "probes": (),
                    "differential": None,
                    "assessments": tuple(sorted(snapshot.assessments, key=lambda a: a.case_id)),
                }
            )
            cohort = next((r for r in confidence.input.current if r.snapshot == canonical), None)
            _require(cohort is not None, "confidence lacks the current canonical snapshot")
            assert cohort is not None
            for proof in cohort.evidence:
                source = proof.evidence
                _require(
                    source.events == cases[source.subject_id].events
                    and source.expected == run.configuration.expected
                    and source.observation == observations[source.subject_id],
                    "confidence proof differs from captured case",
                )
    if graph:
        _require(graph.state != "unsafe_rejected", "graph safety gate failed")
        if graph.source:
            _require(
                counterfactual is not None and graph.source == counterfactual,
                "graph lacks its matching counterfactual source",
            )
    if minimum:
        _require(minimum.state != "unsafe_rejected", "shrinking safety gate failed")
        if minimum.input:
            source_min = minimum.input
            expected_min = OracleShrinkInput.model_validate(
                source_min.model_dump()
                | {
                    "original": events,
                    "expected": run.configuration.expected,
                    "policy": run.configuration.variations,
                    "harness": run.configuration.harness,
                }
            )
            _require(
                source_min == expected_min and source_min.case == cases.get(source_min.case.id),
                "minimum belongs to another run",
            )
    return AdvancedEvidence(
        semantics=tuple(extract_signal(e) for e in events),
        intent=intent,
        mapping=mapping,
        temporal=temporal,
        oracle=oracle,
        counterfactual=counterfactual,
        confidence=confidence,
        graph=graph,
        minimum=minimum,
    )
