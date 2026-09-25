"""Bind existing run/report artifacts to a versioned, locally verifiable DAG."""

from collections.abc import Mapping

from dvi_sentinel.artifact_models import LINEAGE_FILES, ArtifactIssue, RunRecord
from dvi_sentinel.lineage import (
    bound_contents,
    build_lineage,
    byte_digest,
    encoded,
    lineage_artifacts,
    verify_lineage,
)
from dvi_sentinel.lineage_models import (
    ArtifactKind,
    LineageSpec,
    LineageSummary,
    ProvenanceDAG,
)
from dvi_sentinel.serialization import canonical_json, parse_json

PRESENTATION_FILES = {
    "report.json",
    "report.md",
    "report.html",
    "provenance.json",
    "regression.json",
}


def run_specifications(contents: Mapping[str, bytes]) -> tuple[LineageSpec, ...]:
    """Fixed dependency recipes for the existing run contract, never inferred from names."""
    record = RunRecord.model_validate(parse_json(contents["run.json"]))
    specs: list[LineageSpec] = []

    def add(path: str, kind: ArtifactKind, *parents: str, source: bool = False) -> None:
        if path in contents:
            specs.append(
                LineageSpec(
                    path=path, kind=kind, source=source, parents=tuple(sorted(set(parents)))
                )
            )

    add("scenario.json", "scenario", source=True)
    for fixture in record.fixtures:
        add(fixture.artifact_path, "input_fixture", source=True)
    telemetry = tuple(f.artifact_path for f in record.fixtures if f.role == "telemetry")
    detector = tuple(f.artifact_path for f in record.fixtures if f.role == "detector_results")
    add("normalized_events.jsonl", "normalized_events", "scenario.json", *telemetry)
    add("variations.jsonl", "variation_case", "scenario.json", "normalized_events.jsonl")
    add("observations.jsonl", "observation", "scenario.json", "variations.jsonl", *detector)
    add(
        "run.json",
        "run_record",
        "scenario.json",
        "normalized_events.jsonl",
        "variations.jsonl",
        *(f.artifact_path for f in record.fixtures),
    )
    add("matches.jsonl", "match_result", "scenario.json", "observations.jsonl", "variations.jsonl")
    add(
        "assumption_probes.jsonl",
        "counterfactual_result",
        "scenario.json",
        "normalized_events.jsonl",
        *detector,
    )
    add(
        "differential_schema_report.json",
        "schema_projection",
        "scenario.json",
        "normalized_events.jsonl",
        *detector,
    )
    optional = (
        ("differential_schema_report.json",)
        if "differential_schema_report.json" in contents
        else ()
    )
    add(
        "score.json",
        "score_result",
        "scenario.json",
        "matches.jsonl",
        "variations.jsonl",
        "assumption_probes.jsonl",
        *optional,
    )
    add(
        "comparison.json",
        "analysis",
        "run.json",
        "score.json",
        "matches.jsonl",
        "observations.jsonl",
        "assumption_probes.jsonl",
        *optional,
    )
    add(
        "minimal_case.json",
        "shrunk_case",
        "scenario.json",
        "variations.jsonl",
        "observations.jsonl",
        "normalized_events.jsonl",
        *detector,
    )
    for path in ("minimal_case.md", "shrinking_trace.jsonl", "root_cause.json"):
        add(path, "shrunk_case", "minimal_case.json")
    add("regression_baseline.json", "input_fixture", source=True)
    add("regression_thresholds.json", "configuration", source=True)
    add(
        "regression.json",
        "analysis",
        "comparison.json",
        "regression_baseline.json",
        "regression_thresholds.json",
    )
    evidence = tuple(sorted(contents.keys() - LINEAGE_FILES - PRESENTATION_FILES))
    add("provenance.json", "report", *evidence)
    add(
        "report.json",
        "report",
        *evidence,
        "provenance.json",
        *(("regression.json",) if "regression.json" in contents else ()),
    )
    for path in ("report.md", "report.html"):
        add(path, "report", "report.json")
    return tuple(sorted(specs, key=lambda s: s.path))


def extra_specifications(
    dag: ProvenanceDAG, contents: Mapping[str, bytes]
) -> tuple[LineageSpec, ...]:
    known = {s.path for s in run_specifications(contents)}
    return tuple(
        n.specification()
        for n in dag.nodes
        if n.artifact.path in contents and n.artifact.path not in known
    )


def evidence_summary(dag: ProvenanceDAG) -> LineageSummary:
    evidence = ProvenanceDAG(
        nodes=tuple(n for n in dag.nodes if n.artifact.path not in PRESENTATION_FILES)
    )
    return LineageSummary(
        evidence_sha256=byte_digest(encoded(evidence)),
        artifacts=len(evidence.nodes),
        parent_links=sum(len(n.parents) for n in evidence.nodes),
        roots=tuple(n.artifact.path for n in evidence.nodes if n.source),
    )


def with_artifact_lineage(
    contents: Mapping[str, bytes],
    *,
    declarations: tuple[LineageSpec, ...] = (),
) -> dict[str, bytes]:
    """Explicitly upgrade a run bundle; unknown extra artifacts require producer declarations."""
    bound_contents(contents)
    files = {p: b for p, b in contents.items() if p not in LINEAGE_FILES}
    record = RunRecord.model_validate(parse_json(files["run.json"]))
    scenario = (canonical_json(record.configuration) + "\n").encode("utf-8")
    if "scenario.json" in files and files["scenario.json"] != scenario:
        raise ValueError("DVI-LINEAGE-SCENARIO: captured configuration differs")
    files["scenario.json"] = scenario
    dag = build_lineage(files, run_specifications(files) + declarations)
    integrity = verify_lineage(dag, files)
    if not integrity.valid:
        raise ValueError("DVI-LINEAGE-INTEGRITY: orphan or invalid artifact cannot be published")
    if PRESENTATION_FILES & files.keys():
        _verify_report(files, evidence_summary(dag))
    files.update(lineage_artifacts(dag, files))
    bound_contents(files)
    return files


def verify_bundle_lineage(contents: Mapping[str, bytes]) -> tuple[ArtifactIssue, ...]:
    """Verify already-confined bytes, including materialized views and report references."""
    issues: list[ArtifactIssue] = []
    try:
        dag = ProvenanceDAG.model_validate(parse_json(contents["provenance_dag.json"]))
        files = {p: b for p, b in contents.items() if p not in LINEAGE_FILES}
        integrity = verify_lineage(dag, files)
        issues.extend(
            ArtifactIssue(
                code="DVI-LINEAGE-" + i.code.upper(),
                path=i.path,
                explanation="Artifact or its parent lineage failed integrity",
            )
            for i in integrity.issues
        )
        for name, expected in lineage_artifacts(dag, files).items():
            if contents.get(name) != expected:
                issues.append(
                    ArtifactIssue(
                        code="DVI-LINEAGE-VIEW",
                        path=name,
                        explanation="Canonical lineage view differs",
                    )
                )
        # Incomplete/tampered evidence has already produced transitive failures.
        if issues:
            return tuple(issues)
        specs = {n.artifact.path: n.specification() for n in dag.nodes}
        if any(specs.get(s.path) != s for s in run_specifications(files)):
            raise ValueError("fixed run parent recipe differs")
        record = RunRecord.model_validate(parse_json(files["run.json"]))
        if files.get("scenario.json") != (canonical_json(record.configuration) + "\n").encode():
            raise ValueError("scenario differs from run")
        if PRESENTATION_FILES & files.keys():
            _verify_report(files, evidence_summary(dag))
    except (KeyError, ValueError, RecursionError):
        issues.append(
            ArtifactIssue(
                code="DVI-LINEAGE-CONTRACT",
                path="provenance_dag.json",
                explanation="DAG, parent recipe or report summary is invalid",
            )
        )
    return tuple(issues)


def _verify_report(contents: Mapping[str, bytes], summary: LineageSummary) -> None:
    # Local imports keep the artifact/report model dependencies acyclic.
    from dvi_sentinel.report_models import ReportDocument
    from dvi_sentinel.report_rendering import render_html, render_markdown

    report = ReportDocument.model_validate(parse_json(contents["report.json"]))
    if (
        report.schema_version != "2"
        or report.lineage != summary
        or contents["provenance.json"] != encoded(report.provenance)
        or contents["report.md"] != render_markdown(report).encode("utf-8")
        or contents["report.html"] != render_html(report).encode("utf-8")
    ):
        raise ValueError("report does not match its provenance summary or renderings")
