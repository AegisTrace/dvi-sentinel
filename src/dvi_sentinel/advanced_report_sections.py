"""Compact human views of the exact evidence retained in the report (A)."""

from dvi_sentinel.advanced_report_evidence import ANALYSIS_PATHS
from dvi_sentinel.report_models import ReportDocument
from dvi_sentinel.report_rendering import Section, display
from dvi_sentinel.serialization import canonical_json, parse_json

ROW_LIMIT = 20


def percent(value: float | None) -> str:
    return f"{value:.1%}" if value is not None else "unavailable"


def recommendation(fact: str) -> str:
    value = parse_json(fact)
    assert isinstance(value, dict)
    dimensions = value["dimensions"]
    assert isinstance(dimensions, list)
    return str(value["action"]) + " Dimensions: " + ", ".join(str(d) for d in dimensions) + "."


def advanced_sections(report: ReportDocument) -> tuple[Section, ...]:
    evidence = report.advanced
    assert evidence is not None and report.lineage is not None
    run, frontier = report.run, report.frontier
    metrics = frontier.metrics
    items: list[Section] = []

    def section(
        title: str,
        paragraphs: tuple[str, ...],
        columns: tuple[str, ...] = (),
        rows: tuple[tuple[str, ...], ...] = (),
        references: tuple[str, ...] = (),
    ) -> None:
        if len(rows) > ROW_LIMIT:
            paragraphs += (
                f"Showing {ROW_LIMIT} of {len(rows)} rows; complete evidence is linked.",
            )
        items.append(
            Section(
                title.lower().replace("/", "-").replace(" ", "-"),
                title,
                paragraphs,
                columns,
                rows[:ROW_LIMIT],
                references,
            )
        )

    def source(name: str) -> tuple[str, ...]:
        return (ANALYSIS_PATHS[name],)

    optional = tuple(name for name in ANALYSIS_PATHS if getattr(evidence, name) is None)
    section(
        "Executive Summary",
        (
            f"{metrics.missed} missed, {metrics.detected} detected, {metrics.unknown} unknown and"
            f" {metrics.invalid} invalid variants; baseline excluded."
            f" {len(frontier.findings)} classified local findings.",
            "Read this overview, the fragility frontier and recommendations first."
            " Detailed evidence remains available in the linked artifacts.",
            "Oracle consensus: "
            + (evidence.oracle.state.replace("_", " ") if evidence.oracle else "not supplied")
            + "."
            " Statistical confidence: "
            + (
                ", ".join(
                    sorted(
                        {g.confidence_class.replace("_", " ") for g in evidence.confidence.groups}
                    )
                )
                or evidence.confidence.state
                if evidence.confidence
                else "not supplied"
            )
            + ".",
            "Optional analyses not supplied: " + (", ".join(optional) or "none") + "."
            " Absence does not establish resilience or a passing gate.",
            "All conclusions apply to local synthetic fixtures and the sampled cases only.",
        ),
        references=("score.json", "report.json"),
    )
    section(
        "Scenario and Inputs",
        (
            run.configuration.metadata.description,
            f"Scenario: {run.scenario_id}; seed: {run.seed}; run: {run.run_id}.",
            f"{len(evidence.semantics)} baseline events; {len(report.cases)} total cases."
            f" Started {run.started_at.isoformat()}; finished {run.finished_at.isoformat()}.",
        ),
        ("Captured fixture", "Role", "SHA-256"),
        tuple((f.artifact_path, f.role, f.sha256) for f in run.fixtures),
        ("run.json", "scenario.json", "normalized_events.jsonl"),
    )
    section(
        "Semantic Signal",
        (
            "Default ontology extraction from the verified baseline. Unknown and ambiguous bindings"
            " remain unresolved; equal incomplete signals do not prove equivalence.",
        ),
        ("Event", "Meaning", "State", "Semantic digest", "Loss findings"),
        tuple(
            (
                s.event_id,
                f"{s.signal.category} / {s.signal.action}",
                s.state,
                s.signal.semantic_digest,
                str(len(s.findings)),
            )
            for s in evidence.semantics
        ),
        ("normalized_events.jsonl", "report.json"),
    )
    intent = evidence.intent
    section(
        "Detection Intent",
        (
            (
                f"{intent.parsed.intent.title}. State: {intent.state};"
                f" scope: {intent.analysis_scope}."
                " Metadata evidence support is distinct from detector execution."
            )
            if intent
            else "Not supplied: no V2 detection-intent analysis was captured.",
        ),
        ("Event", "Support", "Checks"),
        tuple(
            (c.event_id, c.state, "; ".join(f"{x.code}: {x.outcome}" for x in c.checks))
            for c in intent.candidates
        )
        if intent
        else (),
        source("intent") if intent else (),
    )
    mapping = evidence.mapping
    section(
        "Schema/Profile Mapping",
        (
            (f"State: {mapping.state}. {mapping.explanation}")
            if mapping
            else "Not supplied: no V2 schema/profile mapping analysis was captured.",
            "Legacy cross-schema comparison: "
            + ("available in the linked evidence." if report.differential else "not supplied."),
        ),
        ("Representation", "State", "Differences"),
        tuple((r.representation, r.state, str(len(r.differences))) for r in mapping.results)
        if mapping
        else (),
        (source("mapping") if mapping else ())
        + (("differential_schema_report.json",) if report.differential else ()),
    )
    temporal = evidence.temporal
    section(
        "Temporal and Correlation Evidence",
        (
            (
                f"Recorded state: {temporal.state}. Checks are tied to the baseline input digest;"
                " unknown precision and absent correlation keys are not filled in."
            )
            if temporal
            else "Not supplied: no V2 temporal/correlation analysis was captured.",
        ),
        ("Predicate / key", "State", "Explanation"),
        tuple((t.check.predicate, t.check.outcome, t.check.explanation) for t in temporal.traces)
        + tuple((c.key, c.outcome, c.explanation) for c in temporal.correlation_evidence)
        if temporal
        else (),
        source("temporal") if temporal else (),
    )
    oracle = evidence.oracle
    section(
        "Oracle Consensus",
        (
            (f"{oracle.state}: {oracle.explanation}")
            if oracle
            else "Not supplied: no multi-oracle consensus or consensus claim is available.",
            (
                f"Claim: {oracle.claim}; subject: {oracle.subject_id}. {oracle.confidence_basis}"
                " Oracle confidence is a heuristic, not a statistical probability."
            )
            if oracle
            else "Detection counts alone do not establish oracle agreement.",
        ),
        ("Oracle", "Decision", "Explanation"),
        tuple((d.oracle_id, d.decision, d.explanation) for d in oracle.decisions) if oracle else (),
        source("oracle") if oracle else (),
    )
    section(
        "Fragility Frontier",
        (
            f"Detection rate: {display(metrics.detection_rate)};"
            f" miss rate: {display(metrics.miss_rate)};"
            f" unknown rate: {display(metrics.unknown_rate)}.",
            "Distances compare cases within a family only. Boundaries describe sampled cases."
            " Invalid transformations are excluded from detected/missed/unknown outcomes.",
            "Regression: "
            + (report.regression.status if report.regression else "not measured")
            + ".",
        ),
        ("Family", "Detected", "Missed", "Unknown", "Easiest missed"),
        tuple(
            (
                f.family,
                str(f.metrics.detected),
                str(f.metrics.missed),
                str(f.metrics.unknown),
                f"{f.easiest_safe_missed.case_id} @ {f.easiest_safe_missed.distance:g}"
                if f.easiest_safe_missed
                else "unavailable",
            )
            for f in frontier.families
        ),
        ("score.json", "matches.jsonl", "variations.jsonl"),
    )
    counter = evidence.counterfactual
    section(
        "Counterfactual Explanation",
        (
            (f"State: {counter.state}; evaluations: {counter.evaluations}. {counter.limitations}")
            if counter
            else "Not supplied: no V2 counterfactual study was captured.",
            "Legacy assumption probes: " + str(len(report.probes)) + "."
            " Local tested associations do not establish universal causality.",
        ),
        ("Case", "Necessary dimensions", "Controls", "Interpretation"),
        tuple(
            (f.case_id, ", ".join(f.necessary_dimensions), str(len(f.control_cases)), f.statement)
            for f in counter.findings
        )
        if counter
        else (),
        (source("counterfactual") if counter else ())
        + (("assumption_probes.jsonl",) if report.probes else ()),
    )
    minimum = evidence.minimum
    section(
        "Minimal Reproducer",
        (
            (f"Oracle-aware shrinking: {minimum.state}. {minimum.explanation} {minimum.minimality}")
            if minimum
            else "Not supplied: no oracle-aware minimum was captured.",
            (
                f"Legacy minimum: {report.minimal.status};"
                f" {len(report.minimal.events)} events retained."
                f" {report.minimal.minimality} This result has no V2 oracle-preservation claim."
            )
            if report.minimal
            else "No legacy minimum was captured either.",
        ),
        references=(source("minimum") if minimum else ())
        + (("minimal_case.json",) if report.minimal else ()),
    )
    confidence = evidence.confidence
    section(
        "Statistical Confidence",
        (
            (f"State: {confidence.state}. {confidence.calibration_note}")
            if confidence
            else "Not supplied: confidence intervals and seed stability were not measured.",
            "Intervals exclude unknown outcomes from known denominators; identification bounds and"
            " warnings remain in the full evidence. Cohorts may include linked historical seeds.",
        ),
        ("Cohort / group", "Class", "Known detection", "Wilson interval", "Warnings"),
        tuple(
            (
                f"{g.side} / seed {g.seed} / {g.scope_id}",
                g.confidence_class.replace("_", " "),
                f"{g.detection_interval.numerator}/{g.detection_interval.denominator}",
                f"{g.detection_interval.confidence_level:.0%}: "
                f"{percent(g.detection_interval.lower)} to {percent(g.detection_interval.upper)}",
                ", ".join(w.replace("_", " ") for w in g.warnings) or "none",
            )
            for g in confidence.groups
        )
        if confidence
        else (),
        source("confidence") if confidence else (),
    )
    graph = evidence.graph
    section(
        "Knowledge Graph Summary",
        (
            (
                f"State: {graph.state}; {graph.summary.nodes} nodes, {graph.summary.edges} edges,"
                f" {graph.summary.findings} findings. {graph.limitations}"
            )
            if graph
            else "Not supplied: no knowledge graph was captured.",
        ),
        references=source("graph") if graph else (),
    )
    section(
        "Weak Edges",
        (
            (
                f"{graph.summary.weak_edges} edges carry explicit weaknesses."
                " These describe evidence limitations and conditional associations."
            )
            if graph
            else "Not supplied: weak edges cannot be assessed without the knowledge graph.",
        ),
        ("Relation", "Weaknesses", "Explanation"),
        tuple(
            (e.kind, ", ".join(e.weaknesses), e.explanation)
            for e in graph.graph.edges
            if e.weaknesses
        )
        if graph
        else (),
        source("graph") if graph else (),
    )
    section(
        "Recommendations",
        (
            "Review unknown evidence and sampled misses before extending any conclusion."
            " Reproduce the linked cases and test any proposed detector change.",
            "Graph recommendations are untested proposals linked to measured local causes."
            if graph
            else "No graph-derived recommendations are available without captured evidence.",
        ),
        ("Proposal", "Evidence pointer"),
        tuple(
            (
                recommendation(n.fact_json),
                "; ".join(r.artifact + "#" + r.pointer for r in n.references),
            )
            for n in graph.graph.nodes
            if n.kind == "recommendation"
        )
        if graph
        else (),
        source("graph") + (source("counterfactual") if graph.source else ())
        if graph
        else ("score.json",),
    )
    section(
        "Limitations",
        report.limitations
        + (
            "Native analyses are scoped to their retained inputs; temporal checks and local causal"
            " observations are recorded evidence, not an independent detector replay.",
            "The readable tables show at most 20 rows each. Full report JSON and source artifacts"
            " retain the detail. This report supports at most 128 baseline events.",
        ),
    )
    section(
        "Reproduction Commands",
        (
            "Recorded invocation (JSON argument array, displayed as data and never executed):",
            canonical_json(list(run.command)),
            "Regenerate from the extracted verified bundle: dvi report . --advanced --overwrite",
            "Retain the original scenario and captured fixture mapping for engine replay."
            " Report generation consumes evidence; it does not rerun detectors.",
            f"Tool version: {run.tool_version}; commit: {run.git_commit or 'not supplied'}.",
        ),
        references=("run.json", "scenario.json"),
    )
    section(
        "Artifact Provenance",
        (
            f"Evidence inventory SHA-256: {report.provenance.evidence_digest}",
            f"Evidence DAG SHA-256: {report.lineage.evidence_sha256};"
            f" {report.lineage.artifacts} evidence artifacts,"
            f" {report.lineage.parent_links} parent links.",
            "Relative links resolve inside this bundle. The archive contains a complete verified"
            " bundle with its own manifest/DAG; no nested archive is included.",
            "Hashes establish recorded consistency. Keep an external manifest pin for authenticity"
            " checks; a fully replaced bundle is not authenticated by its own hashes.",
        ),
        references=("provenance.json", "provenance_dag.json", "manifest.json"),
    )
    section(
        "Safety Boundary",
        (
            "Local only. Synthetic fixtures only. No target execution or network activity.",
            "The report contains no JavaScript, remote fonts or external resources."
            " Commands and telemetry are escaped text. Open report.html locally after extracting"
            " the archive, keeping report_assets and evidence files alongside it.",
        ),
    )
    return tuple(items)
