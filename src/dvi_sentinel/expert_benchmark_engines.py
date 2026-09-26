"""Finite engine adapters over prepared fixture bytes; no reads or expected benchmarks (A)."""

from datetime import UTC, datetime, timedelta

from dvi_sentinel import __version__
from dvi_sentinel.artifact_models import LINEAGE_FILES, ArtifactEntry
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.confidence import analyze_confidence
from dvi_sentinel.confidence_models import ConfidenceEvidence, ConfidenceInput, ConfidenceRun
from dvi_sentinel.detection_intent import analyze_intent
from dvi_sentinel.differential_models import FixtureRepresentation
from dvi_sentinel.expert_benchmark_models import (
    IntentEvidence,
    IntentOperation,
    MappingEvidence,
    MappingOperation,
    NativeEvidence,
    Operation,
    OracleBenchmarkEvidence,
    ProvenanceEvidence,
    SequenceEvidence,
    StatisticalEvidence,
    TimingChange,
)
from dvi_sentinel.fixture_encoding import encode_fixture
from dvi_sentinel.harness_models import HarnessRequest
from dvi_sentinel.intent_parsing import parse_intent
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.lineage import byte_digest, verify_lineage
from dvi_sentinel.lineage_models import ProvenanceDAG
from dvi_sentinel.matching import match_detection
from dvi_sentinel.metamorphic import analyze_representations
from dvi_sentinel.metamorphic_models import MetamorphicInput, RepresentationInput
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_consensus import build_consensus
from dvi_sentinel.oracle_models import OracleConsensus, OracleEvidence
from dvi_sentinel.provenance_bundle import verify_bundle_lineage, with_artifact_lineage
from dvi_sentinel.run_artifacts import RunEvidence, build_run_artifacts
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.serialization import digest, parse_json
from dvi_sentinel.shrinking import FailureShrinker
from dvi_sentinel.temporal import within
from dvi_sentinel.variation_models import EventLineage, Family, VariationCase
from dvi_sentinel.variations import plan_variations
from dvi_sentinel.workflow import PreparedScenario


def _lineage(events: tuple[TelemetryEvent, ...]) -> tuple[EventLineage, ...]:
    return tuple(
        EventLineage(event_id=e.event_id, original_event_id=e.event_id, role="original")
        for e in events
    )


def _shift(event: TelemetryEvent, delta_ms: int) -> TelemetryEvent:
    try:
        return TelemetryEvent.model_validate(
            event.model_dump()
            | {
                "timestamp": event.timestamp + timedelta(milliseconds=delta_ms),
                "observed_at": event.observed_at + timedelta(milliseconds=delta_ms)
                if event.observed_at
                else None,
            }
        )
    except OverflowError as exc:
        raise ValueError("DVI-EXPERT-SEQUENCE: timing shift exceeds datetime range") from exc


def _sequence(prepared: PreparedScenario, source: bytes) -> SequenceEvidence:
    change = TimingChange.model_validate(parse_json(source))
    scenario, original, harness = prepared.scenario, prepared.events, prepared.harness
    if len(original) != 2 or change.event_id not in {e.event_id for e in original}:
        raise ValueError("DVI-EXPERT-SEQUENCE: require two events and a known change target")
    if scenario.harness.kind != "rule_logic" or len(scenario.harness.rules) != 1:
        raise ValueError("DVI-EXPERT-SEQUENCE: require one local sequence rule")
    duration = scenario.harness.rules[0].window_ms
    if duration is None:
        raise ValueError("DVI-EXPERT-SEQUENCE: require a finite rule window")
    events = tuple(
        _shift(e, change.delta_ms) if e.event_id == change.event_id else e for e in original
    )
    lineage = _lineage(events)
    preservation = check_candidate(original, events, lineage, scenario.variations, "timing")
    candidate = VariationCase(
        id="sequence:shift",
        family="timing",
        parameters=(),
        events=events,
        lineage=lineage,
        preservation=preservation,
        distance=float(abs(change.delta_ms)),
    )
    baseline = match_detection(
        scenario.expected,
        harness.evaluate(HarnessRequest(case_id="baseline", events=original)),
        original,
    )
    match = match_detection(
        scenario.expected,
        harness.evaluate(HarnessRequest(case_id=candidate.id, events=events)),
        events,
        preservation=preservation,
    )
    minimum = (
        FailureShrinker(harness).shrink(original, candidate, scenario.variations, scenario.expected)
        if baseline.status == "detected" and match.status == "missed"
        else None
    )
    return SequenceEvidence(
        baseline=baseline,
        candidate=candidate,
        match=match,
        window=within(events[0], events[1], duration, precision_digits=3),
        minimum=minimum,
    )


def _mapping(
    prepared: PreparedScenario, operation: MappingOperation, fixtures: dict[str, bytes]
) -> MappingEvidence:
    if len(prepared.events) != 1:
        raise ValueError("DVI-EXPERT-MAPPING: require one source event")
    request = MetamorphicInput(
        source=prepared.events[0],
        representations=(operation.representation,),
        supplied=(
            RepresentationInput(
                representation=operation.representation,
                content=fixtures[operation.supplied_fixture].decode("utf-8"),
            ),
        )
        if operation.supplied_fixture
        else (),
    )
    return MappingEvidence(
        report=analyze_representations(request, expected_digest=request.stable_digest())
    )


def _intent(
    prepared: PreparedScenario, operation: IntentOperation, fixtures: dict[str, bytes]
) -> IntentEvidence:
    parsed = parse_intent(fixtures[operation.intent_fixture].decode("utf-8"))
    return IntentEvidence(report=analyze_intent(parsed, prepared.events))


def _oracle(prepared: PreparedScenario) -> OracleBenchmarkEvidence:
    events, harness, expected = prepared.events, prepared.harness, prepared.scenario.expected
    evidence = OracleEvidence(
        subject_id="oracle:primary",
        events=events,
        expected=expected,
        observation=harness.evaluate(HarnessRequest(case_id="oracle:primary", events=events)),
        repetitions=tuple(
            harness.evaluate(HarnessRequest(case_id=f"oracle:repeat:{i}", events=events))
            for i in range(3)
        ),
        representations=(
            FixtureRepresentation(
                representation="canonical_jsonl", content=encode_fixture(events, "canonical_jsonl")
            ),
        ),
    )
    consensus = build_consensus(
        evaluate_oracles(evidence, expected_digest=evidence.stable_digest())
    )
    return OracleBenchmarkEvidence(
        report=OracleConsensus.model_validate(consensus.model_dump() | {"evidence": evidence})
    )


def _statistical(prepared: PreparedScenario, seed: int) -> StatisticalEvidence:
    scenario, harness = prepared.scenario, prepared.harness
    if not 2 <= len(prepared.events) <= 64:
        raise ValueError("DVI-EXPERT-STATISTICS: require baseline plus 1..63 local trials")
    assessments, proofs, inputs = [], [], {}
    for i, event in enumerate(prepared.events):
        events = (event,)
        family: Family = "baseline" if i == 0 else "metadata"
        preservation = check_candidate(
            events, events, _lineage(events), scenario.variations, family
        )
        case_id = f"trial:{i:03d}"
        observation = harness.evaluate(HarnessRequest(case_id=case_id, events=events))
        proof = OracleEvidence(
            subject_id=case_id, events=events, expected=scenario.expected, observation=observation
        )
        proofs.append(ConfidenceEvidence(evidence=proof, expected_digest=proof.stable_digest()))
        inputs[case_id] = digest([event.model_dump(mode="json")])
        assessments.append(
            CaseAssessment(
                case_id=case_id,
                family=family,
                distance=0.0,
                preservation=preservation,
                parser_success=True,
                match=match_detection(
                    scenario.expected, observation, events, preservation=preservation
                ),
            )
        )
    run = ConfidenceRun(
        snapshot=ComparisonSnapshot(
            tool_version=__version__,
            scenario_id=scenario.metadata.id,
            scenario_digest=scenario.stable_digest(),
            input_digest=digest([e.model_dump(mode="json") for e in prepared.events]),
            config_digest=scenario.variations.stable_digest(),
            detector_digest=scenario.harness.stable_digest(),
            seed=seed,
            case_input_digests=inputs,
            assessments=tuple(assessments),
        ),
        evidence=tuple(proofs),
    )
    request = ConfidenceInput(current=(run,))
    return StatisticalEvidence(
        report=analyze_confidence(request, expected_digest=request.stable_digest())
    )


def _provenance(
    prepared: PreparedScenario, mutation: str, seed: int, event_budget: int
) -> ProvenanceEvidence:
    scenario, events, harness = prepared.scenario, prepared.events, prepared.harness
    plan = plan_variations(
        scenario.metadata.id, events, scenario.variations, seed, event_budget=event_budget
    )
    evidence = RunEvidence(
        scenario=scenario,
        fixtures=prepared.fixtures,
        plan=plan,
        observations=tuple(
            harness.evaluate(HarnessRequest(case_id=c.id, events=c.events)) for c in plan.cases
        ),
        harness_fixture=prepared.harness_fixture,
    )
    epoch = datetime(2026, 1, 1, tzinfo=UTC)
    files = with_artifact_lineage(
        build_run_artifacts(
            evidence, started_at=epoch, finished_at=epoch, command=("expert-benchmark",)
        )
    )
    dag = ProvenanceDAG.model_validate(parse_json(files["provenance_dag.json"]))
    if mutation == "append_newline":
        files["fixtures/telemetry-000.jsonl"] += b"\n"
    evidence_files = {p: b for p, b in files.items() if p not in LINEAGE_FILES}
    return ProvenanceEvidence(
        dag=dag,
        observed=tuple(
            ArtifactEntry(path=p, sha256=byte_digest(b), size_bytes=len(b))
            for p, b in sorted(evidence_files.items())
        ),
        integrity=verify_lineage(dag, evidence_files),
        bundle_issues=verify_bundle_lineage(files),
    )


def measure_native(
    prepared: PreparedScenario,
    operation: Operation,
    fixtures: dict[str, bytes],
    *,
    seed: int,
    event_budget: int,
) -> NativeEvidence:
    """Dispatch finite operations without expected outcomes or control labels."""
    if operation.kind == "sequence":
        return _sequence(prepared, fixtures[operation.change_fixture])
    if operation.kind == "mapping":
        return _mapping(prepared, operation, fixtures)
    if operation.kind == "intent":
        return _intent(prepared, operation, fixtures)
    if operation.kind == "oracle":
        return _oracle(prepared)
    if operation.kind == "statistical":
        return _statistical(prepared, seed)
    if operation.kind == "provenance":
        return _provenance(prepared, operation.mutation, seed, event_budget)
    raise ValueError("DVI-EXPERT-OPERATION: legacy cases use the existing benchmark evaluator")
