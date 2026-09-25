"""Source paths, actual local causes, explicit weakness and graph integrity."""

import json
import runpy
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from dvi_sentinel.counterfactual_models import (
    CounterfactualBudget,
    CounterfactualDimension,
    CounterfactualInput,
    CounterfactualSummary,
)
from dvi_sentinel.counterfactuals import mine_counterfactuals
from dvi_sentinel.harness_models import LocalRule, RuleCondition, RuleHarnessConfig
from dvi_sentinel.knowledge_graph import (
    build_detection_graph,
    graph_artifacts,
    recommendation_view,
)
from dvi_sentinel.knowledge_graph_models import (
    DetectionGraph,
    GraphNode,
    GraphReference,
    GraphReport,
    GraphSummaryArtifact,
    RecommendationGraph,
    WeakEdges,
)
from dvi_sentinel.knowledge_graph_projection import _Builder, select_pointer
from dvi_sentinel.models import EntityRef, RawSource
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import canonical_json, digest, parse_json

ROOT = Path(__file__).resolve().parents[1]
fixture = runpy.run_path(str(ROOT / "examples/counterfactuals.py"))["fixture"]


def mine(request=None):
    request = request or fixture()
    return mine_counterfactuals(request, expected_digest=request.stable_digest())


def build(source):
    return build_detection_graph(source, expected_digest=source.stable_digest())


def changed(request, **updates):
    return CounterfactualInput.model_validate(request.model_dump(mode="python") | updates)


def resign(model, **updates):
    values = model.model_dump(mode="json", exclude={"id"}) | updates
    prefix = "node:" if isinstance(model, GraphNode) else "edge:"
    return type(model).model_validate(values | {"id": prefix + digest(values)})


def graph_with(graph, *, nodes=None, edges=None):
    return DetectionGraph(
        nodes=tuple(sorted(graph.nodes if nodes is None else nodes, key=lambda n: n.id)),
        edges=tuple(sorted(graph.edges if edges is None else edges, key=lambda e: e.id)),
    )


@pytest.fixture(scope="module")
def source():
    return mine()


@pytest.fixture(scope="module")
def report(source):
    return build(source)


def test_every_finding_reaches_observation_events_and_real_source(report, source):
    assert report.state == "built" and report.summary.findings == len(source.findings) == 1
    nodes = {n.id: n for n in report.graph.nodes}
    for finding in (n for n in nodes.values() if n.kind == "finding"):
        evidence = [
            nodes[e.target]
            for e in report.graph.edges
            if e.source == finding.id
            and e.kind == "supported_by"
            and nodes[e.target].kind == "evidence_field"
        ]
        assert {json.loads(n.fact_json)["role"] for n in evidence} == {"events", "observation"}
        for field in evidence:
            assert any(
                e.source == field.id
                and e.kind == "derived_from"
                and nodes[e.target].kind == "artifact"
                for e in report.graph.edges
            )
            for ref in field.references:
                actual = select_pointer(source.model_dump(mode="json"), ref.pointer)
                assert digest(actual) == ref.value_digest
                if json.loads(field.fact_json)["role"] == "observation":
                    assert actual["status"] == "complete" and actual["detections"] == []


def test_every_recommendation_has_tested_cause_controls_and_untested_remedy(report, source):
    nodes = {n.id: n for n in report.graph.nodes}
    recommendations = [n for n in nodes.values() if n.kind == "recommendation"]
    assert len(recommendations) == 1
    for recommendation in recommendations:
        assert json.loads(recommendation.fact_json)["remedy_tested"] is False
        causes = [
            nodes[e.target]
            for e in report.graph.edges
            if e.source == recommendation.id and e.kind == "depends_on"
        ]
        assert len(causes) == 1 and causes[0].kind == "counterfactual"
        cause = json.loads(causes[0].fact_json)
        assert cause["status"] == "minimal" and cause["dimensions"] == ["sensor", "vendor"]
        controls = [c for c in source.cases if c.case_id in cause["proper_subset_cases"]]
        assert len(controls) == 3 and all(c.outcome == "detected" for c in controls)
        remedy = next(
            e
            for e in report.graph.edges
            if e.target == recommendation.id and e.kind == "mitigated_by"
        )
        assert remedy.weaknesses == ("untested_remedy",)


def test_executed_transforms_link_recorded_invariant_results(report):
    nodes = {n.id: n for n in report.graph.nodes}
    executed = [n for n in nodes.values() if n.executed]
    assert executed
    for transform in executed:
        checks = [
            e for e in report.graph.edges if e.source == transform.id and e.kind == "preserves"
        ]
        assert checks and all(e.weaknesses == ("recorded_preservation",) for e in checks)
        assert all(json.loads(nodes[e.target].fact_json)["passed"] for e in checks)


def test_all_source_references_resolve_and_identify_exact_artifact_bytes(report, source):
    artifact_hash = sha256(json_bytes(source)).hexdigest()
    document = source.model_dump(mode="json")
    for row in (*report.graph.nodes, *report.graph.edges):
        for reference in row.references:
            assert reference.artifact == "counterfactual_summary.json"
            assert reference.sha256 == artifact_hash
            assert reference.value_digest == digest(select_pointer(document, reference.pointer))


def test_weak_edges_are_explicit_and_counted_without_confidence_probability(report):
    weak = [e for e in report.graph.edges if e.weaknesses]
    reasons = {reason for e in weak for reason in e.weaknesses}
    assert report.summary.weak_edges == len(weak) > 0
    assert {
        "missing_evidence",
        "unknown_evidence",
        "unavailable_check",
        "local_association",
        "untested_remedy",
        "unresolved_case",
    } <= reasons
    assert all(not hasattr(e, "confidence") for e in weak)
    assert report.summary.orphan_nodes == ()


def test_four_views_share_anchors_and_recommendation_closure(source, report):
    artifacts = graph_artifacts(source, expected_digest=source.stable_digest())
    assert set(artifacts) == {
        "detection_graph.json",
        "weak_edges.json",
        "recommendation_graph.json",
        "graph_summary.json",
    }
    assert GraphReport.model_validate(parse_json(artifacts["detection_graph.json"])) == report
    weak = WeakEdges.model_validate(parse_json(artifacts["weak_edges.json"]))
    recommendations = RecommendationGraph.model_validate(
        parse_json(artifacts["recommendation_graph.json"])
    )
    summary = GraphSummaryArtifact.model_validate(parse_json(artifacts["graph_summary.json"]))
    for view in (weak, recommendations, summary):
        assert view.report_digest == report.stable_digest()
        assert view.graph_digest == report.graph.stable_digest()
    assert weak.edges == tuple(e for e in report.graph.edges if e.weaknesses)
    assert summary.summary == report.summary and summary.input_digest == source.stable_digest()
    assert recommendations.graph == recommendation_view(report.graph)
    kinds = {n.kind for n in recommendations.graph.nodes}
    assert {
        "recommendation",
        "counterfactual",
        "finding",
        "evidence_field",
        "artifact",
        "variation_case",
    } <= kinds
    assert len(recommendations.graph.nodes) < len(report.graph.nodes)


def test_graph_serialization_is_deterministic_and_ids_cover_content(source, report):
    copied = CounterfactualSummary.model_validate(parse_json(json_bytes(source)))
    assert json_bytes(build(copied)) == json_bytes(report)
    assert [n.id for n in report.graph.nodes] == sorted(n.id for n in report.graph.nodes)
    assert [e.id for e in report.graph.edges] == sorted(e.id for e in report.graph.edges)
    assert len({n.id for n in report.graph.nodes}) == len(report.graph.nodes)


@pytest.mark.parametrize("mode", ["robust", "incomplete", "baseline_missed", "baseline_unknown"])
def test_no_finding_or_recommendation_in_unproved_cases(mode):
    request = fixture("robust" if mode == "robust" else "combination")
    if mode == "incomplete":
        request = changed(request, budget=CounterfactualBudget(max_cases=1))
    elif mode in {"baseline_missed", "baseline_unknown"}:
        expected = request.expected.model_copy(
            update={"signature": "absent"}
            if mode == "baseline_missed"
            else {"signature_contains": "fixture"}
        )
        request = changed(request, expected=expected)
    source = mine(request)
    if mode == "baseline_unknown":
        assert source.state == "unknown" and source.cases[0].outcome == "unknown"
    elif mode == "baseline_missed":
        assert source.state == "baseline_not_detected"
    graph = build(source)
    assert graph.state == "built"
    assert graph.summary.findings == graph.summary.recommendations == 0
    assert recommendation_view(graph.graph) == DetectionGraph()
    assert graph.summary.weak_edges > 0


@pytest.mark.parametrize("pin,state", [(None, "unknown"), ("0" * 64, "unsafe_rejected")])
def test_unpinned_input_never_reaches_projection(monkeypatch, source, pin, state):
    def forbidden(*args, **kwargs):
        pytest.fail("consumed unpinned evidence")

    monkeypatch.setattr("dvi_sentinel.knowledge_graph_projection._project_graph", forbidden)
    result = build_detection_graph(source, expected_digest=pin)
    assert result.state == state and result.source is None and result.summary.nodes == 0


def test_upstream_unknown_or_unsafe_source_stays_empty():
    request = fixture()
    for pin, expected_state in ((None, "unknown"), ("0" * 64, "unsafe_rejected")):
        source = mine_counterfactuals(request, expected_digest=pin)
        result = build(source)
        assert result.state == expected_state and result.source is None
        assert not result.graph.nodes


def test_unsafe_harness_is_checked_before_matching_or_projection(monkeypatch, source):
    request = source.input.model_copy(
        update={
            "harness": source.input.harness.model_copy(
                update={
                    "rules": (
                        source.input.harness.rules[0].model_copy(
                            update={"title": "https://8.8.8.8"}
                        ),
                        *source.input.harness.rules[1:],
                    )
                }
            )
        }
    )
    updated = source.model_copy(
        update={
            "input": request,
            "input_digest": request.stable_digest(),
            "cases": tuple(
                c.model_copy(update={"input_digest": request.stable_digest()}) for c in source.cases
            ),
        }
    )

    def forbidden(*args, **kwargs):
        pytest.fail("unsafe evidence reached an analyzer")

    monkeypatch.setattr("dvi_sentinel.knowledge_graph.match_detection", forbidden)
    monkeypatch.setattr("dvi_sentinel.knowledge_graph_projection._project_graph", forbidden)
    result = build(updated)
    assert result.state == "unsafe_rejected" and result.source is None


def test_changed_match_evidence_cannot_become_graph_support(source):
    case = next(c for c in source.cases if c.outcome == "missed")
    match = case.match.model_copy(update={"explanation": "Changed retained match evidence"})
    updated = source.model_copy(
        update={
            "cases": tuple(
                c.model_copy(update={"match": match}) if c == case else c for c in source.cases
            )
        }
    )
    assert build(updated).state == "unsafe_rejected"


def test_late_unsafe_candidate_blocks_all_matching(monkeypatch, source):
    case = next(c for c in reversed(source.cases) if c.steps and c.observation is not None)
    event = case.events[0].model_copy(
        update={"raw": RawSource.from_payload({"command": "fixture"}, adapter="jsonl")}
    )
    events = (event, *case.events[1:])
    candidate_digest = digest([e.model_dump(mode="json") for e in events])
    altered = case.model_copy(
        update={
            "events": events,
            "candidate_digest": candidate_digest,
            "steps": (
                *case.steps[:-1],
                case.steps[-1].model_copy(update={"output_digest": candidate_digest}),
            ),
        }
    )
    updated = source.model_copy(
        update={"cases": tuple(altered if c == case else c for c in source.cases)}
    )

    def forbidden(*args, **kwargs):
        pytest.fail("an earlier record was consumed before complete safety preflight")

    monkeypatch.setattr("dvi_sentinel.knowledge_graph.match_detection", forbidden)
    assert build(updated).state == "unsafe_rejected"


def test_builder_never_executes_detector_reads_files_or_uses_renderer(monkeypatch, source, report):
    def forbidden(*args, **kwargs):
        pytest.fail("graph construction attempted external I/O or detector execution")

    monkeypatch.setattr("dvi_sentinel.harness.RuleLogicHarness.evaluate", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert build(source) == report


@pytest.mark.parametrize(
    "part", ["node", "edge", "summary", "source", "pin", "interpretation", "state"]
)
def test_full_report_rejects_tampering(report, part):
    values = report.model_dump(mode="json")
    if part == "node":
        values["graph"]["nodes"][0]["label"] = "changed"
    elif part == "edge":
        values["graph"]["edges"][0]["explanation"] = "changed"
    elif part == "summary":
        values["summary"]["findings"] += 1
    elif part == "source":
        values["source"]["limitations"] = "changed"
    elif part == "pin":
        values["input_digest"] = "0" * 64
    elif part == "interpretation":
        values["limitations"] = "Guaranteed mitigation"
    else:
        values["state"] = "unknown"
    with pytest.raises(ValidationError):
        GraphReport.model_validate(values)


def test_resigned_graph_cannot_invent_fact_even_with_consistent_endpoints(report):
    original = next(n for n in report.graph.nodes if n.kind == "recommendation")
    replacement = resign(original, fact_json=canonical_json({"remedy_tested": True}))
    edges = [
        resign(
            e,
            source=replacement.id if e.source == original.id else e.source,
            target=replacement.id if e.target == original.id else e.target,
        )
        for e in report.graph.edges
    ]
    graph = graph_with(
        report.graph,
        nodes=[replacement if n == original else n for n in report.graph.nodes],
        edges=edges,
    )
    with pytest.raises(ValidationError, match="pinned source"):
        GraphReport.model_validate(report.model_dump(mode="python") | {"graph": graph})


@pytest.mark.parametrize(
    "damage",
    [
        "dangling",
        "orphan",
        "type",
        "duplicate_node",
        "duplicate_edge",
        "order",
        "finding",
        "recommendation",
        "transform",
        "evidence",
    ],
)
def test_graph_rejects_invalid_topology_and_missing_required_links(report, damage):
    graph = report.graph
    nodes, edges = list(graph.nodes), list(graph.edges)
    if damage == "dangling":
        edges[0] = resign(edges[0], target="node:" + "0" * 64)
    elif damage == "orphan":
        node = next(n for n in nodes if n.kind == "observable")
        edges = [e for e in edges if node.id not in (e.source, e.target)]
    elif damage == "type":
        e = next(e for e in edges if e.kind == "derived_from")
        edges[edges.index(e)] = resign(e, kind="mitigated_by")
    elif damage == "duplicate_node":
        nodes.append(nodes[0])
    elif damage == "duplicate_edge":
        edges.append(edges[0])
    elif damage == "order":
        with pytest.raises(ValidationError, match="ORDER"):
            DetectionGraph(nodes=tuple(reversed(nodes)), edges=tuple(edges))
        return
    else:
        node = (
            next(n for n in nodes if n.kind == damage and (damage != "transform" or n.executed))
            if damage != "evidence"
            else next(n for n in nodes if n.kind == "evidence_field")
        )
        relation = {
            "finding": "supported_by",
            "recommendation": "depends_on",
            "transform": "preserves",
            "evidence": "derived_from",
        }[damage]
        edges = [e for e in edges if not (e.source == node.id and e.kind == relation)]
    with pytest.raises(ValidationError):
        graph_with(graph, nodes=nodes, edges=edges)


def test_node_key_collision_and_edge_identity_are_rejected(source, report):
    builder = _Builder(source)
    builder.node("run", "test", "One", {"fact": 1}, ("",))
    with pytest.raises(ValueError, match="conflicting node key"):
        builder.node("run", "test", "Two", {"fact": 2}, ("",))
    with pytest.raises(ValidationError, match="self edges"):
        resign(report.graph.edges[0], target=report.graph.edges[0].source)
    with pytest.raises(ValidationError, match="sorted and unique"):
        resign(report.graph.edges[0], weaknesses=["unknown_evidence", "unknown_evidence"])


@pytest.mark.parametrize("pointer", ["x", "/a/~2", "/a/01", "/a/-1", "/a/2", "/missing"])
def test_reference_selector_rejects_invalid_or_unresolved_paths(pointer):
    with pytest.raises(ValueError, match="REFERENCE"):
        select_pointer({"a": [1, 2]}, pointer)


@settings(max_examples=20, deadline=None)
@given(st.text(alphabet="abc/~012", min_size=1, max_size=12))
def test_reference_selector_escapes_object_keys_exactly(key):
    pointer = "/" + key.replace("~", "~0").replace("/", "~1")
    assert select_pointer({key: 23}, pointer) == 23


def test_source_reference_syntax_and_order_are_strict(report):
    reference = report.graph.nodes[0].references[0]
    for pointer in ("not-a-pointer", "/~3"):
        with pytest.raises(ValidationError, match="REFERENCE"):
            GraphReference.model_validate(reference.model_dump() | {"pointer": pointer})
    node = report.graph.nodes[0]
    with pytest.raises(ValidationError, match="sorted and unique"):
        resign(node, references=[r.model_dump(mode="json") for r in (reference, reference)])
    with pytest.raises(ValidationError, match="canonical JSON"):
        resign(node, fact_json='{"z": 1}')


def test_real_invariant_rejection_is_a_weak_violation_without_finding():
    request = changed(
        fixture(),
        dimensions=(CounterfactualDimension(name="correlation", operation="drop:correlation_id"),),
        policy=VariationPolicy(families=("dropout",), optional_fields=("correlation_id",)),
    )
    report = build(mine(request))
    violations = [e for e in report.graph.edges if e.kind == "violates"]
    assert len(violations) == 1 and violations[0].weaknesses == ("recorded_preservation",)
    assert report.summary.findings == 0


def test_actual_paired_recovery_emits_strengthens_with_local_limit():
    request = fixture("single")
    rule = LocalRule(
        id="fixture:duplicate-control",
        detector="fixture:detector",
        signature="fixture:signal",
        title="Synthetic count control",
        conditions=(RuleCondition(field="category", operator="eq", value="flow"),),
        min_count=2,
    )
    request = changed(
        request,
        dimensions=(
            CounterfactualDimension(name="sensor", operation="drop:sensor"),
            CounterfactualDimension(name="copies", operation="duplicates"),
        ),
        policy=VariationPolicy(
            families=("dropout", "volume"), optional_fields=("sensor",), max_duplicates=1
        ),
        harness=RuleHarnessConfig(kind="rule_logic", rules=(*request.harness.rules, rule)),
    )
    source = mine(request)
    assert any(r.effect.recovery_pairs for r in source.rankings)
    graph = build(source).graph
    edges = [e for e in graph.edges if e.kind == "strengthens"]
    assert edges and all(e.weaknesses == ("local_association",) for e in edges)


def test_timely_wrong_signature_preserves_diagnostic_disagreement():
    request = fixture("single")
    rule = LocalRule(
        id="fixture:unrelated",
        detector="fixture:detector",
        signature="fixture:other",
        title="Synthetic unrelated alert",
        conditions=(RuleCondition(field="category", operator="eq", value="flow"),),
    )
    request = changed(
        request,
        dimensions=(CounterfactualDimension(name="sensor", operation="drop:sensor"),),
        harness=RuleHarnessConfig(kind="rule_logic", rules=(*request.harness.rules, rule)),
    )
    report = build(mine(request))
    nodes = {n.id: n for n in report.graph.nodes}
    opposing = [e for e in report.graph.edges if e.kind == "contradicted_by"]
    assert report.summary.findings == 1 and opposing
    assert any(json.loads(nodes[e.target].fact_json)["oracle_id"] == "temporal" for e in opposing)
    assert all(e.weaknesses == ("conflicting_evidence",) for e in opposing)


@pytest.mark.parametrize("kind", ["events", "detections"])
def test_retained_observation_counts_are_bounded(source, kind):
    updated = []
    for case in source.cases:
        if kind == "events" and case.steps:
            events = tuple(
                case.events[0].model_copy(update={"event_id": f"fixture:copy:{i}"})
                for i in range(64)
            )
            candidate_digest = digest([e.model_dump(mode="json") for e in events])
            case = case.model_copy(
                update={
                    "events": events,
                    "candidate_digest": candidate_digest,
                    "steps": (
                        *case.steps[:-1],
                        case.steps[-1].model_copy(update={"output_digest": candidate_digest}),
                    ),
                }
            )
        elif kind == "detections" and case.observation and case.observation.detections:
            detections = tuple(
                case.observation.detections[0].model_copy(update={"event_id": f"fixture:alert:{i}"})
                for i in range(64)
            )
            case = case.model_copy(
                update={
                    "observation": case.observation.model_copy(update={"detections": detections})
                }
            )
        updated.append(case)
    altered = source.model_copy(
        update={
            "cases": tuple(updated),
            "evaluated_events": sum(len(c.events) for c in updated),
        }
    )
    with pytest.raises(ValueError, match="128 retained events and 256 detections"):
        build(altered)


def test_explicit_entity_values_are_retained_without_inference():
    request = fixture("robust")
    event = request.events[0].model_copy(
        update={"entities": (EntityRef(kind="host", value="fixture.example"),)}
    )
    report = build(
        mine(changed(request, events=(event,), budget=CounterfactualBudget(max_cases=1)))
    )
    entities = [json.loads(n.fact_json) for n in report.graph.nodes if n.kind == "entity"]
    assert entities and all(e == {"kind": "host", "value": "fixture.example"} for e in entities)


def test_source_and_output_byte_bounds_fail_explicitly(monkeypatch, source):
    monkeypatch.setattr(
        "dvi_sentinel.knowledge_graph.canonical_json", lambda value: "x" * (4 * 1024 * 1024 + 1)
    )
    with pytest.raises(ValueError, match="source exceeds"):
        build(source)
    monkeypatch.undo()
    monkeypatch.setattr(
        "dvi_sentinel.knowledge_graph.json_bytes", lambda value: b"x" * (8 * 1024 * 1024 + 1)
    )
    with pytest.raises(ValueError, match="combined graph artifacts"):
        graph_artifacts(source, expected_digest=source.stable_digest())


def test_graph_collection_bounds(report):
    with pytest.raises(ValidationError):
        DetectionGraph(nodes=(report.graph.nodes[0],) * 8193)
    with pytest.raises(ValidationError):
        DetectionGraph(edges=(report.graph.edges[0],) * 32769)


def test_example_generates_real_graphs_and_refuses_overwrite(tmp_path):
    out = tmp_path / "graph-proof"
    cmd = [sys.executable, str(ROOT / "examples/knowledge_graph.py"), "--out", str(out)]
    first = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, check=True)
    assert "combination:" in first.stdout
    for mode, count in (("combination", 1), ("robust", 0), ("incomplete", 0)):
        directory = out / mode
        source_bytes = (directory / "counterfactual_summary.json").read_bytes()
        report = GraphReport.model_validate(
            parse_json((directory / "detection_graph.json").read_bytes())
        )
        assert report.summary.findings == count
        assert {r.sha256 for n in report.graph.nodes for r in n.references} == {
            sha256(source_bytes).hexdigest()
        }
        assert len(list(directory.glob("*.json"))) == 5
    second = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert second.returncode != 0 and "new local directory" in second.stderr
