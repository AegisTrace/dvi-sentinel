"""Deterministic relationships derived from a checked local study (A)."""

from hashlib import sha256

from pydantic import BaseModel, JsonValue

from dvi_sentinel.counterfactual_models import CounterfactualSummary
from dvi_sentinel.detection_intent import analyze_intent
from dvi_sentinel.intent_parsing import intent_from_rule
from dvi_sentinel.knowledge_graph import case_evidence
from dvi_sentinel.knowledge_graph_models import (
    DetectionGraph,
    EdgeKind,
    GraphEdge,
    GraphNode,
    GraphReference,
    NodeKind,
    WeakReason,
)
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.ontology import default_profile, extract_signal
from dvi_sentinel.oracle import evaluate_oracles
from dvi_sentinel.oracle_models import VOTER_IDS, OracleResult
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.serialization import canonical_json, digest


def select_pointer(document: JsonValue, pointer: str) -> JsonValue:
    """Resolve exact RFC 6901 tokens; no filesystem or arbitrary selector evaluation."""
    if pointer and not pointer.startswith("/"):
        raise ValueError("DVI-GRAPH-REFERENCE: invalid pointer")
    value = document
    for raw in pointer.split("/")[1:]:
        if "~" in raw.replace("~0", "").replace("~1", ""):
            raise ValueError("DVI-GRAPH-REFERENCE: invalid pointer escape")
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif (
            isinstance(value, list)
            and token.isascii()
            and token.isdecimal()
            and (token == "0" or not token.startswith("0"))
            and int(token) < len(value)
        ):
            value = value[int(token)]
        else:
            raise ValueError("DVI-GRAPH-REFERENCE: source pointer does not resolve")
    return value


class _Builder:
    def __init__(self, source: CounterfactualSummary) -> None:
        self.document: JsonValue = source.model_dump(mode="json")
        content = json_bytes(source)
        self.source_hash = sha256(content).hexdigest()
        self.nodes: dict[str, GraphNode] = {}
        self.keys: dict[tuple[NodeKind, str], str] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.artifact = self.node(
            "artifact",
            "source",
            "counterfactual_summary.json",
            {"sha256": self.source_hash, "size_bytes": len(content)},
            ("",),
        )

    def references(self, paths: tuple[str, ...]) -> tuple[GraphReference, ...]:
        return tuple(
            GraphReference(
                sha256=self.source_hash,
                pointer=p,
                value_digest=digest(select_pointer(self.document, p)),
            )
            for p in sorted(set(paths))
        )

    def node(
        self,
        kind: NodeKind,
        key: str,
        label: str,
        fact: BaseModel | JsonValue,
        paths: tuple[str, ...],
        *,
        executed: bool = False,
    ) -> str:
        fields: dict[str, JsonValue] = {
            "kind": kind,
            "key": key,
            "label": label,
            "fact_json": canonical_json(fact),
            "references": [r.model_dump(mode="json") for r in self.references(paths)],
            "executed": executed,
        }
        node = GraphNode.model_validate(fields | {"id": "node:" + digest(fields)})
        if (kind, key) in self.keys and self.keys[kind, key] != node.id:
            raise ValueError("DVI-GRAPH-IDENTITY: conflicting node key")
        self.keys[kind, key] = node.id
        self.nodes[node.id] = node
        if len(self.nodes) > 8192:
            raise ValueError("DVI-GRAPH-BOUNDS: more than 8192 nodes")
        if kind != "artifact":
            self.edge(
                "derived_from",
                node.id,
                self.artifact,
                paths,
                "Recorded or deterministically projected from the linked source values.",
            )
        return node.id

    def edge(
        self,
        kind: EdgeKind,
        source: str,
        target: str,
        paths: tuple[str, ...],
        explanation: str,
        weaknesses: tuple[WeakReason, ...] = (),
    ) -> None:
        fields: dict[str, JsonValue] = {
            "kind": kind,
            "source": source,
            "target": target,
            "explanation": explanation,
            "references": [r.model_dump(mode="json") for r in self.references(paths)],
            "weaknesses": [str(w) for w in sorted(set(weaknesses))],
        }
        edge = GraphEdge.model_validate(fields | {"id": "edge:" + digest(fields)})
        self.edges[edge.id] = edge
        if len(self.edges) > 32768:
            raise ValueError("DVI-GRAPH-BOUNDS: more than 32768 edges")

    def evidence(self, pointer: str, role: str) -> str:
        return self.node(
            "evidence_field",
            pointer,
            role,
            {"role": role, "value_digest": digest(select_pointer(self.document, pointer))},
            (pointer,),
        )

    def finish(self) -> DetectionGraph:
        return DetectionGraph(
            nodes=tuple(self.nodes[k] for k in sorted(self.nodes)),
            edges=tuple(self.edges[k] for k in sorted(self.edges)),
        )


def _event(g: _Builder, event: TelemetryEvent, path: str, profile: str) -> str:
    extraction = extract_signal(event)
    evidence = g.evidence(path, "event")
    signal = g.node(
        "semantic_signal", path, extraction.signal.signal_id, extraction.signal, (path,)
    )
    g.edge(
        "supported_by", signal, evidence, (path,), "Canonical meaning is projected from this event."
    )
    g.edge(
        "maps_to",
        signal,
        profile,
        (path,),
        "Uses the declared canonical ontology projection.",
        ("declared_source",),
    )
    adapter = g.node(
        "adapter", path, event.raw.adapter, {"adapter": event.raw.adapter}, (path + "/raw/adapter",)
    )
    g.edge(
        "normalizes_to",
        adapter,
        signal,
        (path,),
        "The event records this adapter; normalization is not replayed.",
        ("declared_source",),
    )
    data_source = g.node(
        "data_source",
        path,
        "Recorded telemetry source",
        {"adapter": event.raw.adapter, "sensor": event.raw.sensor, "vendor": event.raw.vendor},
        (path + "/raw",),
    )
    component = g.node(
        "data_component",
        path,
        event.semantics.category,
        {"category": event.semantics.category},
        (path + "/semantics/category",),
    )
    g.edge(
        "depends_on",
        signal,
        data_source,
        (path,),
        "Source attribution is retained producer metadata.",
        ("declared_source",),
    )
    g.edge(
        "depends_on",
        data_source,
        component,
        (path,),
        "The source record declares this event category.",
        ("declared_source",),
    )
    for index, entity in enumerate(extraction.signal.entities):
        entity_node = g.node(
            "entity", f"{path}:{index}", entity.kind, entity, (path + "/entities",)
        )
        g.edge(
            "maps_to",
            signal,
            entity_node,
            (path,),
            "Explicit entity values retained by the semantic projection.",
        )
    for binding in extraction.bindings:
        key = path + ":" + binding.specification.field
        field = g.node("evidence_field", key, binding.specification.field, binding, (path,))
        observable = g.node(
            "observable", key, binding.observable.field, binding.observable, (path,)
        )
        weakness: tuple[WeakReason, ...] = (
            ()
            if binding.observable.state == "known"
            else (
                "missing_evidence" if binding.observable.state == "missing" else "unknown_evidence",
            )
        )
        g.edge(
            "normalizes_to",
            field,
            observable,
            (path,),
            "Binding resolution retains known, missing and ambiguous values.",
            weakness,
        )
        g.edge(
            "supported_by",
            signal,
            field,
            (path,),
            "This binding supplies or limits the event meaning.",
            weakness,
        )
    return signal


def _oracle_weakness(result: OracleResult) -> tuple[WeakReason, ...]:
    if result.decision == "not_applicable":
        return ("unavailable_check",)
    if result.decision in {"unknown", "warn"} or result.uncertainty:
        return ("unknown_evidence",)
    return ()


def _project_graph(source: CounterfactualSummary) -> DetectionGraph:
    """Internal projection; callers must complete the authoritative preflight first."""
    assert source.input is not None
    request = source.input
    g = _Builder(source)
    run = g.node(
        "run",
        "study",
        "Local counterfactual study",
        {"input_digest": source.input_digest, "state": source.state, "seed": request.seed},
        ("",),
    )
    detector = g.node(
        "detector", "expected", request.expected.detector, request.expected, ("/input/expected",)
    )
    g.edge(
        "depends_on",
        run,
        detector,
        ("/input/expected",),
        "The study uses this detection expectation.",
    )
    profile = g.node(
        "schema_profile",
        "canonical-ontology",
        "Canonical ontology projection",
        default_profile(),
        ("/input/events",),
    )
    policy = g.node(
        "invariant",
        "policy",
        "Declared transformation contract",
        request.policy,
        ("/input/policy",),
    )
    transforms = {}
    for index, dimension in enumerate(request.dimensions):
        path = f"/input/dimensions/{index}"
        node = g.node(
            "transform", "dimension:" + dimension.name, dimension.operation, dimension, (path,)
        )
        transforms[dimension.name] = node
        g.edge(
            "requires",
            node,
            policy,
            (path, "/input/policy"),
            "The configured operation is subject to this policy.",
            ("declared_source",),
        )

    parsed_intents = tuple(intent_from_rule(rule) for rule in request.harness.rules)
    intent_nodes = []
    requirements: dict[tuple[int, str], str] = {}
    for index, parsed in enumerate(parsed_intents):
        path = f"/input/harness/rules/{index}"
        intent = g.node("detection_intent", path, parsed.intent.title, parsed, (path,))
        intent_nodes.append(intent)
        g.edge(
            "depends_on",
            detector,
            intent,
            (path,),
            "This local rule is retained in the study harness.",
            ("declared_source",),
        )
        for field in parsed.intent.fields:
            node = g.node("evidence_field", path + ":" + field.field, field.field, field, (path,))
            requirements[index, field.field] = node
            g.edge(
                "requires",
                intent,
                node,
                (path,),
                "Declared rule field requirement; execution evidence is separate.",
            )
    for index, event in enumerate(request.events):
        signal = _event(g, event, f"/input/events/{index}", profile)
        g.edge("maps_to", run, signal, (f"/input/events/{index}",), "Original input signal.")

    cases: dict[str, str] = {}
    observations: dict[str, str] = {}
    oracle_nodes: dict[str, list[tuple[str, OracleResult]]] = {}
    for index, case in enumerate(source.cases):
        path = f"/cases/{index}"
        node = g.node(
            "variation_case",
            case.case_id,
            case.outcome,
            {
                "case_id": case.case_id,
                "active": list(case.active),
                "outcome": case.outcome,
                "reason": case.reason,
            },
            (path,),
        )
        cases[case.case_id] = node
        g.edge(
            "supported_by",
            run,
            node,
            (path,),
            "Retained case accounting, including unexecuted or unresolved cases.",
            () if case.outcome in {"detected", "missed"} else ("unresolved_case",),
        )
        for active in case.active:
            g.edge(
                "depends_on",
                node,
                transforms[active],
                (path,),
                "The case declares this active operation.",
            )
        if case.observation is None:
            for rejection_index, rejection in enumerate(case.rejections):
                if rejection.category == "invariant" and not rejection.passed:
                    ref = f"{path}/rejections/{rejection_index}"
                    invariant = g.node("invariant", ref, rejection.constraint_id, rejection, (ref,))
                    proposal = g.node(
                        "transform",
                        path,
                        "Rejected combined proposal",
                        {"active": list(case.active)},
                        (path,),
                    )
                    g.edge(
                        "violates",
                        proposal,
                        invariant,
                        (ref,),
                        "Recorded check rejected the combined proposal before measurement.",
                        ("recorded_preservation",),
                    )
            continue
        observation = g.evidence(path + "/observation", "observation")
        observations[case.case_id] = observation
        g.edge(
            "supported_by",
            node,
            observation,
            (path,),
            "Measured harness observation for this case.",
        )
        for event_index, event in enumerate(case.events):
            event_path = f"{path}/events/{event_index}"
            signal = _event(g, event, event_path, profile)
            g.edge(
                "maps_to",
                node,
                signal,
                (event_path,),
                "Canonical signal in the measured candidate.",
            )
        for step_index, step in enumerate(case.steps):
            step_path = f"{path}/steps/{step_index}"
            transform = g.node(
                "transform", step_path, step.operation, step, (step_path,), executed=True
            )
            g.edge(
                "derived_from",
                node,
                transform,
                (step_path,),
                "Recorded transformation step for this candidate.",
            )
            for check_index, check in enumerate(step.preservation.checks):
                check_path = f"{step_path}/preservation/checks/{check_index}"
                invariant = g.node("invariant", check_path, check.id, check, (check_path,))
                g.edge(
                    "preserves" if check.passed else "violates",
                    transform,
                    invariant,
                    (check_path,),
                    "Recorded invariant result; the graph does not replay the transformation.",
                    ("recorded_preservation",),
                )
        evidence = case_evidence(source, case)
        oracle_nodes[case.case_id] = []
        for result in evaluate_oracles(evidence, expected_digest=evidence.stable_digest()):
            oracle = g.node(
                "oracle_decision",
                path + ":" + result.oracle_id,
                result.oracle_id,
                result,
                (path, "/input/expected"),
            )
            oracle_nodes[case.case_id].append((oracle, result))
            g.edge(
                "supported_by",
                oracle,
                observation,
                (path, "/input/expected"),
                "Check resolution uses these retained observations and expectations.",
                _oracle_weakness(result),
            )
            g.edge(
                "supported_by",
                node,
                oracle,
                (path,),
                "Diagnostic decision; a guard pass is not a vote against a gap.",
                _oracle_weakness(result),
            )
        for rule_index, parsed in enumerate(parsed_intents):
            analysis = analyze_intent(parsed, case.events)
            rule_path = f"/input/harness/rules/{rule_index}"
            for candidate in analysis.candidates:
                event_index = next(
                    i for i, event in enumerate(case.events) if event.event_id == candidate.event_id
                )
                event_path = f"{path}/events/{event_index}"
                for binding in candidate.bindings:
                    key = f"{event_path}:rule:{rule_index}:{binding.specification.field}"
                    observable = g.node(
                        "observable",
                        key,
                        binding.observable.field,
                        binding,
                        (event_path, rule_path),
                    )
                    checks = tuple(
                        c for c in candidate.checks if c.field == binding.specification.field
                    )
                    weakness: tuple[WeakReason, ...] = (
                        ("conflicting_evidence",)
                        if any(c.outcome == "contradicted" for c in checks)
                        else ("unknown_evidence",)
                        if any(c.outcome != "supported" for c in checks)
                        or binding.observable.state != "known"
                        else ()
                    )
                    g.edge(
                        "maps_to",
                        requirements[rule_index, binding.specification.field],
                        observable,
                        (event_path, rule_path),
                        "Rule field binding resolution; it does not replace whole-rule "
                        "or sequence evaluation.",
                        weakness,
                    )

    for index, finding in enumerate(source.findings):
        path = f"/findings/{index}"
        case_index = next(i for i, c in enumerate(source.cases) if c.case_id == finding.case_id)
        failure_index = next(
            i for i, f in enumerate(source.failure_sets) if f.case_id == finding.case_id
        )
        case_path = f"/cases/{case_index}"
        failure_path = f"/failure_sets/{failure_index}"
        node = g.node("finding", finding.case_id, "Observed local detection gap", finding, (path,))
        g.edge(
            "supported_by",
            node,
            observations[finding.case_id],
            (case_path + "/observation",),
            "Actual missed observation underlying the finding.",
        )
        g.edge(
            "supported_by",
            node,
            g.evidence(case_path + "/events", "events"),
            (case_path + "/events",),
            "Actual candidate event content underlying the finding.",
        )
        cause = g.node(
            "counterfactual",
            finding.case_id,
            "Verified local minimal change set",
            source.failure_sets[failure_index],
            (failure_path,),
        )
        g.edge(
            "explains",
            cause,
            node,
            (path, failure_path),
            "All proper subset controls detected; necessity is conditional on this local fixture.",
            ("local_association",),
        )
        g.edge(
            "supported_by",
            node,
            cause,
            (path, failure_path),
            "Recorded minimality and controls support local attribution.",
            ("local_association",),
        )
        for control in finding.control_cases:
            control_index = next(i for i, c in enumerate(source.cases) if c.case_id == control)
            g.edge(
                "supported_by",
                cause,
                cases[control],
                (f"/cases/{control_index}",),
                "A measured proper subset detects, constraining this local cause claim.",
            )
        for dimension_name in finding.necessary_dimensions:
            g.edge(
                "depends_on",
                cause,
                transforms[dimension_name],
                (path,),
                "Necessary within this tested minimal change set.",
                ("local_association",),
            )
        for oracle, result in oracle_nodes[finding.case_id]:
            opposing = (
                (result.oracle_id in VOTER_IDS and result.decision == "pass")
                or (
                    result.oracle_id not in VOTER_IDS
                    and result.decision in {"fail", "unsafe_rejected"}
                )
                or "contradictory_benign_context" in result.reason_codes
            )
            g.edge(
                "contradicted_by" if opposing else "supported_by",
                node,
                oracle,
                (case_path,),
                "Independent check retains its own decision and uncertainty; "
                "guard passes do not prove the gap.",
                ("conflicting_evidence",) if opposing else _oracle_weakness(result),
            )
        recommendation = g.node(
            "recommendation",
            finding.case_id,
            "Review dependency and retest",
            {
                "action": "Review the detector's dependence on the linked local change set; "
                "add these controls and retest any proposed change.",
                "dimensions": list(finding.necessary_dimensions),
                "remedy_tested": False,
            },
            (path, failure_path),
        )
        g.edge(
            "depends_on",
            recommendation,
            cause,
            (path, failure_path),
            "The recommendation is scoped to this observed cause and its controls.",
            ("local_association",),
        )
        g.edge(
            "mitigated_by",
            node,
            recommendation,
            (path,),
            "Proposed review and retest action; no mitigation has been tested.",
            ("untested_remedy",),
        )
    for index, ranking in enumerate(source.rankings):
        path = f"/rankings/{index}/effect"
        for count, relation in (
            (ranking.effect.loss_pairs, "weakens"),
            (ranking.effect.recovery_pairs, "strengthens"),
        ):
            if count:
                # Literal branches keep relation vocabulary explicit for the type checker.
                g.edge(
                    "weakens" if relation == "weakens" else "strengthens",
                    transforms[ranking.dimension.name],
                    detector,
                    (path,),
                    "Measured paired direction in this fixture; not a universal causal effect.",
                    ("local_association",),
                )
    return g.finish()
