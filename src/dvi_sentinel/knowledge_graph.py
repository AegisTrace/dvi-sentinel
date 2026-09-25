"""Pure bounded graph consumption and deterministic export (A)."""

from collections import Counter

from dvi_sentinel.counterfactual_models import CounterfactualCase, CounterfactualSummary
from dvi_sentinel.knowledge_graph_models import (
    DetectionGraph,
    GraphCount,
    GraphReport,
    GraphSummary,
    GraphSummaryArtifact,
    RecommendationGraph,
    WeakEdges,
)
from dvi_sentinel.matching import match_detection
from dvi_sentinel.oracle import ProvenanceOracle, SafetyOracle
from dvi_sentinel.oracle_models import OracleEvidence
from dvi_sentinel.policy import PolicyError, inspect_content
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.serialization import canonical_json

LIMITATIONS = (
    "This graph projects one pinned local counterfactual study, not all V1/V2 bundle types. "
    "Source hashes prove consistency, not authorship or detector replay. Transform preservation "
    "is retained producer evidence. Canonical ontology and rule-intent projections are bounded "
    "local interpretations, not full schema compliance. Local effects and minimal causes remain "
    "conditional on the tested fixtures and controls. Recommendations are untested review and "
    "retest guidance, not verified mitigations. Weak edges describe unresolved or limited support, "
    "not calibrated probabilities. The graph is not a release gate or the artifact provenance DAG."
)


class GraphIntegrityError(ValueError):
    """Safety, provenance or retained matching evidence cannot support consumption."""


def case_evidence(source: CounterfactualSummary, case: CounterfactualCase) -> OracleEvidence:
    assert source.input is not None
    return OracleEvidence(
        subject_id=case.case_id,
        events=case.events,
        expected=source.input.expected,
        observation=case.observation,
    )


def _checked_source(source: CounterfactualSummary) -> CounterfactualSummary:
    source = CounterfactualSummary.model_validate(source.model_dump(mode="python"))
    if len(canonical_json(source).encode("utf-8")) > 4 * 1024 * 1024:
        raise ValueError("DVI-GRAPH-BOUNDS: source exceeds 4 MiB")
    if source.input is None:
        raise GraphIntegrityError("DVI-GRAPH-SOURCE: source evidence unavailable")
    if (
        sum(len(c.events) for c in source.cases) > 128
        or sum(len(c.observation.detections) for c in source.cases if c.observation) > 256
    ):
        raise ValueError("DVI-GRAPH-BOUNDS: at most 128 retained events and 256 detections")
    try:
        rejected = inspect_content(source.input.harness.model_dump(mode="json"))
    except PolicyError as exc:
        rejected = exc.decisions
    if rejected:
        raise GraphIntegrityError("DVI-GRAPH-SAFETY: unsafe harness declaration")
    original = OracleEvidence(
        subject_id="graph:input", events=source.input.events, expected=source.input.expected
    )
    evidence = (original, *(case_evidence(source, c) for c in source.cases))
    # Complete authoritative preflight precedes any matcher, ontology or intent consumer.
    for row in evidence:
        if (
            SafetyOracle.evaluate(row).blocking
            or ProvenanceOracle.evaluate(row, row.stable_digest()).blocking
        ):
            raise GraphIntegrityError("DVI-GRAPH-GATE: unsafe or inconsistent source evidence")
    for case in source.cases:
        if (
            case.observation is not None
            and match_detection(source.input.expected, case.observation, case.events) != case.match
        ):
            raise GraphIntegrityError("DVI-GRAPH-MATCH: retained outcome differs from observation")
    return source


def graph_summary(graph: DetectionGraph) -> GraphSummary:
    nodes = Counter(n.kind for n in graph.nodes)
    edges = Counter(e.kind for e in graph.edges)
    return GraphSummary(
        nodes=len(graph.nodes),
        edges=len(graph.edges),
        weak_edges=sum(bool(e.weaknesses) for e in graph.edges),
        findings=nodes["finding"],
        recommendations=nodes["recommendation"],
        node_types=tuple(GraphCount(kind=k, count=v) for k, v in sorted(nodes.items())),
        edge_types=tuple(GraphCount(kind=k, count=v) for k, v in sorted(edges.items())),
    )


def build_detection_graph(
    source: CounterfactualSummary, *, expected_digest: str | None = None
) -> GraphReport:
    """Project retained local evidence; never run a detector or read a caller-selected file."""
    from dvi_sentinel.knowledge_graph_projection import _project_graph

    source = CounterfactualSummary.model_validate(source.model_dump(mode="python"))
    fingerprint = source.stable_digest()

    def blocked(unsafe: bool, reason: str) -> GraphReport:
        graph = DetectionGraph()
        return GraphReport(
            input_digest=fingerprint,
            source=None,
            state="unsafe_rejected" if unsafe else "unknown",
            graph=graph,
            summary=graph_summary(graph),
            reasons=(reason,),
            limitations=LIMITATIONS,
        )

    if expected_digest is None:
        return blocked(False, "source_pin_missing")
    if expected_digest != fingerprint:
        return blocked(True, "source_pin_changed")
    if source.input is None:
        return blocked(source.state == "unsafe_rejected", "source_evidence_unavailable")
    try:
        source = _checked_source(source)
    except GraphIntegrityError:
        return blocked(True, "source_integrity_rejected")
    graph = _project_graph(source)
    return GraphReport(
        input_digest=fingerprint,
        source=source,
        state="built",
        graph=graph,
        summary=graph_summary(graph),
        reasons=(),
        limitations=LIMITATIONS,
    )


def recommendation_view(graph: DetectionGraph) -> DetectionGraph:
    """Outgoing evidence/cause closure, retaining incoming mitigation links among selected nodes."""
    outgoing: dict[str, set[str]] = {n.id: set() for n in graph.nodes}
    for edge in graph.edges:
        outgoing[edge.source].add(edge.target)
    selected: set[str] = set()
    pending = [n.id for n in graph.nodes if n.kind == "recommendation"]
    while pending:
        node = pending.pop()
        if node not in selected:
            selected.add(node)
            pending.extend(outgoing[node] - selected)
    return DetectionGraph(
        nodes=tuple(n for n in graph.nodes if n.id in selected),
        edges=tuple(e for e in graph.edges if e.source in selected and e.target in selected),
    )


def graph_artifacts(
    source: CounterfactualSummary, *, expected_digest: str | None = None
) -> dict[str, bytes]:
    report = build_detection_graph(source, expected_digest=expected_digest)
    report_digest = report.stable_digest()
    graph_digest = report.graph.stable_digest()
    artifacts = {
        "detection_graph.json": json_bytes(report),
        "weak_edges.json": json_bytes(
            WeakEdges(
                report_digest=report_digest,
                graph_digest=graph_digest,
                edges=tuple(e for e in report.graph.edges if e.weaknesses),
            )
        ),
        "recommendation_graph.json": json_bytes(
            RecommendationGraph(
                report_digest=report_digest,
                graph_digest=graph_digest,
                graph=recommendation_view(report.graph),
            )
        ),
        "graph_summary.json": json_bytes(
            GraphSummaryArtifact(
                report_digest=report_digest,
                graph_digest=graph_digest,
                input_digest=report.input_digest,
                state=report.state,
                summary=report.summary,
                reasons=report.reasons,
            )
        ),
    }
    if sum(map(len, artifacts.values())) > 32 * 1024 * 1024:
        raise ValueError("DVI-GRAPH-OUTPUT: combined graph artifacts exceed 32 MiB")
    return artifacts
