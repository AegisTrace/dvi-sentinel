"""Bounded typed graphs and source-linked projections (D)."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from dvi_sentinel.counterfactual_models import CounterfactualSummary
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.ontology_models import JsonSnapshot
from dvi_sentinel.serialization import canonical_json, digest, parse_json

NodeKind = Literal[
    "run",
    "detector",
    "semantic_signal",
    "entity",
    "observable",
    "evidence_field",
    "schema_profile",
    "adapter",
    "detection_intent",
    "data_source",
    "data_component",
    "invariant",
    "transform",
    "variation_case",
    "oracle_decision",
    "finding",
    "counterfactual",
    "recommendation",
    "artifact",
]
EdgeKind = Literal[
    "requires",
    "preserves",
    "violates",
    "normalizes_to",
    "maps_to",
    "depends_on",
    "explains",
    "weakens",
    "strengthens",
    "mitigated_by",
    "derived_from",
    "supported_by",
    "contradicted_by",
]
WeakReason = Literal[
    "unknown_evidence",
    "missing_evidence",
    "unavailable_check",
    "conflicting_evidence",
    "declared_source",
    "recorded_preservation",
    "local_association",
    "untested_remedy",
    "unresolved_case",
]
Count = Annotated[StrictInt, Field(ge=0, le=32768)]


class GraphReference(ValueModel):
    artifact: Literal["counterfactual_summary.json"] = "counterfactual_summary.json"
    sha256: Sha256
    pointer: Annotated[str, Field(max_length=1024)]
    value_digest: Sha256

    @model_validator(mode="after")
    def pointer_syntax(self) -> Self:
        if self.pointer and not self.pointer.startswith("/"):
            raise ValueError("DVI-GRAPH-REFERENCE: require a JSON pointer")
        for part in self.pointer.split("/")[1:]:
            if "~" in part.replace("~0", "").replace("~1", ""):
                raise ValueError("DVI-GRAPH-REFERENCE: invalid pointer escape")
        return self


References = Annotated[tuple[GraphReference, ...], Field(min_length=1, max_length=64)]


class GraphNode(ValueModel):
    id: Identifier
    kind: NodeKind
    key: NonEmpty
    label: NonEmpty
    fact_json: JsonSnapshot
    references: References
    executed: StrictBool = False

    @model_validator(mode="after")
    def content_identity(self) -> Self:
        if canonical_json(parse_json(self.fact_json)) != self.fact_json:
            raise ValueError("DVI-GRAPH-FACT: require canonical JSON")
        if self.executed and self.kind != "transform":
            raise ValueError("DVI-GRAPH-TRANSFORM: only transforms have execution checks")
        if self.id != "node:" + digest(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("DVI-GRAPH-ID: node content differs from identity")
        _references(self.references)
        return self


class GraphEdge(ValueModel):
    id: Identifier
    kind: EdgeKind
    source: Identifier
    target: Identifier
    explanation: NonEmpty
    references: References
    weaknesses: Annotated[tuple[WeakReason, ...], Field(max_length=9)] = ()

    @model_validator(mode="after")
    def content_identity(self) -> Self:
        if self.source == self.target:
            raise ValueError("DVI-GRAPH-EDGE: self edges are unsupported")
        if self.weaknesses != tuple(sorted(set(self.weaknesses))):
            raise ValueError("DVI-GRAPH-ORDER: weaknesses must be sorted and unique")
        if self.id != "edge:" + digest(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("DVI-GRAPH-ID: edge content differs from identity")
        _references(self.references)
        return self


def _references(values: tuple[GraphReference, ...]) -> None:
    keys = tuple((r.artifact, r.sha256, r.pointer, r.value_digest) for r in values)
    if keys != tuple(sorted(set(keys))):
        raise ValueError("DVI-GRAPH-ORDER: references must be sorted and unique")


def _edge_types(edge: GraphEdge, nodes: dict[str, GraphNode]) -> bool:
    left, right = nodes[edge.source].kind, nodes[edge.target].kind
    if edge.kind == "derived_from":
        return right in {"artifact", "variation_case", "evidence_field", "transform"}
    if edge.kind == "supported_by":
        return right in {"evidence_field", "oracle_decision", "variation_case", "counterfactual"}
    if edge.kind == "depends_on":
        return right in {
            "detector",
            "detection_intent",
            "data_source",
            "data_component",
            "transform",
            "counterfactual",
        }
    if edge.kind == "requires":
        return (left, right) in {("detection_intent", "evidence_field"), ("transform", "invariant")}
    if edge.kind in {"preserves", "violates"}:
        return (left, right) == ("transform", "invariant")
    if edge.kind == "normalizes_to":
        return (left, right) in {("evidence_field", "observable"), ("adapter", "semantic_signal")}
    if edge.kind == "maps_to":
        return right in {"schema_profile", "semantic_signal", "observable", "entity"}
    if edge.kind == "explains":
        return (left, right) == ("counterfactual", "finding")
    if edge.kind in {"weakens", "strengthens"}:
        return (left, right) == ("transform", "detector")
    if edge.kind == "mitigated_by":
        return (left, right) == ("finding", "recommendation")
    return edge.kind == "contradicted_by" and right == "oracle_decision"


class DetectionGraph(ValueModel):
    nodes: Annotated[tuple[GraphNode, ...], Field(max_length=8192)] = ()
    edges: Annotated[tuple[GraphEdge, ...], Field(max_length=32768)] = ()

    @model_validator(mode="after")
    def topology(self) -> Self:
        nodes = {n.id: n for n in self.nodes}
        if (
            tuple(nodes) != tuple(sorted(nodes))
            or len(nodes) != len(self.nodes)
            or len({(n.kind, n.key) for n in self.nodes}) != len(self.nodes)
        ):
            raise ValueError("DVI-GRAPH-ORDER: nodes must have unique sorted IDs")
        ids = tuple(e.id for e in self.edges)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("DVI-GRAPH-ORDER: edges must have unique sorted IDs")
        adjacent: dict[str, set[str]] = {n: set() for n in nodes}
        outgoing: dict[str, list[GraphEdge]] = {n: [] for n in nodes}
        for edge in self.edges:
            if edge.source not in nodes or edge.target not in nodes:
                raise ValueError("DVI-GRAPH-ENDPOINT: dangling edge")
            if not _edge_types(edge, nodes):
                raise ValueError("DVI-GRAPH-TYPE: relation has incompatible endpoint types")
            adjacent[edge.source].add(edge.target)
            adjacent[edge.target].add(edge.source)
            outgoing[edge.source].append(edge)
        roots = [n.id for n in self.nodes if n.kind == "artifact"]
        if self.nodes:
            if len(roots) != 1 or any(not a for a in adjacent.values()):
                raise ValueError("DVI-GRAPH-ORPHAN: require one artifact and connected nodes")
            visited, pending = set(), [roots[0]]
            while pending:
                current_id = pending.pop()
                if current_id not in visited:
                    visited.add(current_id)
                    pending.extend(adjacent[current_id] - visited)
            if visited != set(nodes):
                raise ValueError("DVI-GRAPH-ORPHAN: disconnected component")
        for node in self.nodes:
            edges = outgoing[node.id]
            if node.kind == "evidence_field" and not any(
                e.kind == "derived_from" and nodes[e.target].kind == "artifact" for e in edges
            ):
                raise ValueError("DVI-GRAPH-EVIDENCE: evidence needs its source artifact")
            if node.kind == "finding" and not any(
                e.kind == "supported_by" and nodes[e.target].kind == "evidence_field" for e in edges
            ):
                raise ValueError("DVI-GRAPH-FINDING: finding needs direct evidence")
            if node.executed and not any(e.kind in {"preserves", "violates"} for e in edges):
                raise ValueError("DVI-GRAPH-TRANSFORM: executed transform lacks invariant checks")
            if node.kind == "recommendation":
                causes = {
                    e.target
                    for e in edges
                    if e.kind == "depends_on" and nodes[e.target].kind == "counterfactual"
                }
                findings = {e.target for c in causes for e in outgoing[c] if e.kind == "explains"}
                if not causes or not any(
                    e.kind == "mitigated_by" and e.target == node.id
                    for f in findings
                    for e in outgoing[f]
                ):
                    raise ValueError("DVI-GRAPH-CAUSE: recommendation lacks its finding cause")
        return self


class GraphCount(ValueModel):
    kind: NodeKind | EdgeKind
    count: Count


class GraphSummary(ValueModel):
    nodes: Count
    edges: Count
    weak_edges: Count
    findings: Count
    recommendations: Count
    node_types: tuple[GraphCount, ...]
    edge_types: tuple[GraphCount, ...]
    orphan_nodes: tuple[Identifier, ...] = ()


class GraphReport(ValueModel):
    schema_version: Literal["1"] = "1"
    input_digest: Sha256
    source: CounterfactualSummary | None
    state: Literal["built", "unknown", "unsafe_rejected"]
    graph: DetectionGraph
    summary: GraphSummary
    reasons: tuple[Identifier, ...]
    limitations: NonEmpty

    @model_validator(mode="after")
    def reproduce(self) -> Self:
        from dvi_sentinel.knowledge_graph import LIMITATIONS, _checked_source, graph_summary
        from dvi_sentinel.knowledge_graph_projection import _project_graph

        if self.limitations != LIMITATIONS or self.summary != graph_summary(self.graph):
            raise ValueError("DVI-GRAPH-REPORT: summary or interpretation differs")
        if self.source is None:
            if self.state == "built" or self.graph.nodes or self.graph.edges or not self.reasons:
                raise ValueError("DVI-GRAPH-GATE: blocked report cannot export evidence")
        elif (
            self.state != "built"
            or self.reasons
            or self.input_digest != self.source.stable_digest()
            or self.graph != _project_graph(_checked_source(self.source))
        ):
            raise ValueError("DVI-GRAPH-REPORT: graph differs from pinned source evidence")
        return self


class WeakEdges(ValueModel):
    schema_version: Literal["1"] = "1"
    report_digest: Sha256
    graph_digest: Sha256
    edges: tuple[GraphEdge, ...]


class RecommendationGraph(ValueModel):
    schema_version: Literal["1"] = "1"
    report_digest: Sha256
    graph_digest: Sha256
    graph: DetectionGraph


class GraphSummaryArtifact(ValueModel):
    schema_version: Literal["1"] = "1"
    report_digest: Sha256
    graph_digest: Sha256
    input_digest: Sha256
    state: Literal["built", "unknown", "unsafe_rejected"]
    summary: GraphSummary
    reasons: tuple[Identifier, ...]
