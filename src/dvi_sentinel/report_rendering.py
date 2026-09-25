"""Shared report sections rendered as escaped Markdown or dependency-free local HTML."""

import html
import re
from dataclasses import dataclass
from importlib.resources import files

from jinja2 import Environment, StrictUndefined

from dvi_sentinel.report_models import ReportDocument
from dvi_sentinel.score_models import Ratio
from dvi_sentinel.scoring import outcome
from dvi_sentinel.serialization import canonical_json


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    paragraphs: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    rows: tuple[tuple[str, ...], ...] = ()


def display(value: object) -> str:
    if value is None:
        return "unavailable"
    if isinstance(value, Ratio):
        percent = f"{value.value:.1%}" if value.value is not None else "unavailable"
        return f"{value.numerator}/{value.denominator} ({percent})"
    return str(value)


def sections(report: ReportDocument) -> tuple[Section, ...]:
    run, score = report.run, report.frontier
    items = [
        Section(
            "scenario",
            "Scenario and safety",
            (
                run.configuration.metadata.description,
                f"Scenario: {run.scenario_id}; run: {run.run_id}; seed: {run.seed}.",
                "Attested: local only, synthetic only, no execution."
                " These are fixture observations.",
                f"Started: {run.started_at.isoformat()}; finished: {run.finished_at.isoformat()}.",
                f"Scenario SHA-256: {run.scenario_digest}",
                f"Normalized input SHA-256: {run.normalized_input_digest}",
                f"Detector SHA-256: {run.detector_digest}",
            ),
        ),
        Section(
            "frontier",
            "Resilience frontier",
            (
                "Variant metrics exclude the baseline. Invalid semantic transformations are"
                " excluded from detected/missed/unknown outcomes.",
                "Zero denominators and absent latency samples are unavailable."
                " Completeness measures evidence availability.",
            ),
            ("Metric", "Measured value"),
            tuple(
                (name.replace("_", " "), display(getattr(score.metrics, name)))
                for name in type(score.metrics).model_fields
            )
            + (
                ("adapter disagreement", display(score.adapter_disagreement_rate)),
                ("adapter unknown", str(score.adapter_unknown)),
            ),
        ),
        Section(
            "families",
            "Variation families",
            (
                "Distances are comparable within each family only;"
                " boundaries describe sampled cases.",
            ),
            (
                "Family",
                "Detected",
                "Missed",
                "Unknown",
                "Invalid",
                "Hardest detected",
                "Easiest missed",
            ),
            tuple(
                (
                    f.family,
                    display(f.metrics.detection_rate),
                    display(f.metrics.miss_rate),
                    display(f.metrics.unknown_rate),
                    str(f.metrics.invalid),
                    f"{f.hardest_safe_detected.case_id} @ {f.hardest_safe_detected.distance:g}"
                    if f.hardest_safe_detected
                    else "unavailable",
                    f"{f.easiest_safe_missed.case_id} @ {f.easiest_safe_missed.distance:g}"
                    if f.easiest_safe_missed
                    else "unavailable",
                )
                for f in score.families
            ),
        ),
        Section(
            "findings",
            "Fragility findings",
            (
                "No classified fragility findings in the measured evidence."
                if not score.findings
                else "Each finding has file/record/field references in provenance.json."
                " Associations do not establish universal causality.",
            ),
            ("Finding", "Class", "Source case", "Interpretation"),
            tuple((f.id, f.finding_class, f.case_id, f.rationale) for f in score.findings),
        ),
        Section(
            "cases",
            "Detected, missed, unknown and invalid cases",
            (),
            ("Case", "Family", "Outcome", "Reason", "Delay (ms)", "Missing / contradictory"),
            tuple(
                (
                    c.case_id,
                    c.family,
                    outcome(c),
                    c.match.reason if c.match else "No match evidence",
                    display(c.match.alert_delay_ms) if c.match else "unavailable",
                    "; ".join((*c.match.missing_evidence, *c.match.contradictory_evidence))
                    if c.match
                    else "unavailable",
                )
                for c in report.cases
            ),
        ),
        Section(
            "probes",
            "Assumption probes",
            (
                "Assumption probes were not requested."
                if not report.probes
                else "Robust means only that the expected detection survived"
                " this tested counterfactual.",
            ),
            ("Probe", "Hypothesis", "Result", "Reason"),
            tuple(
                (p.spec.name, p.spec.hypothesis, p.observed_result, p.reason) for p in report.probes
            ),
        ),
        Section(
            "schemas",
            "Cross-schema differential",
            (
                "Cross-schema comparison was not requested."
                if report.differential is None
                else "Each representation is compared against the declared canonical reference."
                " Unsupported or lossy mappings remain explicit.",
            ),
            ("Representation", "Status", "Reason", "Differences"),
            tuple(
                (
                    c.representation,
                    c.status,
                    c.reason,
                    "; ".join(f"{d.finding_class}: {d.path}" for d in c.differences),
                )
                for c in report.differential.cases
            )
            if report.differential
            else (),
        ),
    ]
    minimal = report.minimal
    items.append(
        Section(
            "minimal",
            "Minimal reproducer and root cause",
            (
                (
                    f"{minimal.original_case_id}: {minimal.status};"
                    f" {len(minimal.events)} events retained;"
                    f" {len(minimal.trace)} reduction attempts.",
                    minimal.minimality,
                    minimal.root_cause.rationale,
                    f"Root-cause status: {minimal.root_cause.status}; final reason:"
                    f" {minimal.final.reason if minimal.final else 'unavailable'}.",
                )
                if minimal
                else ("Failure shrinking was not requested; no minimum or root cause is claimed.",)
            ),
            ("Ablation", "Association", "Matcher reason"),
            tuple(
                (a.reduction, a.association, a.match.reason if a.match else "unavailable")
                for a in minimal.root_cause.ranked
            )
            if minimal
            else (),
        )
    )
    regression = report.regression
    if report.lineage is not None:
        lineage = report.lineage
        items.append(
            Section(
                "lineage",
                "Artifact lineage and integrity",
                (
                    f"Provenance DAG: {lineage.dag_artifact}.",
                    f"Evidence DAG SHA-256: {lineage.evidence_sha256}",
                    f"{lineage.artifacts} evidence artifacts; {lineage.parent_links} parent links;"
                    f" {len(lineage.roots)} declared source roots.",
                    "The summary excludes presentation and integrity-control files to avoid"
                    " circular hashes. The final manifest covers every file; the full DAG"
                    " also binds these reports to their evidence parents.",
                    "A changed or missing parent invalidates descendants. Hashes establish"
                    " recorded consistency, not authorship or an independent detector replay.",
                ),
            )
        )
    items.append(
        Section(
            "regression",
            "Baseline regression comparison",
            (
                (
                    f"Status: {regression.status}; exit status: {regression.exit_status}.",
                    *regression.reasons,
                    f"New misses: {', '.join(regression.newly_missed) or 'none'}.",
                    f"Recovered: {', '.join(regression.recovered) or 'none'}.",
                )
                if regression
                else ("No baseline bundle was supplied; regression was not measured.",)
            ),
            ("Metric", "Previous", "Current", "Delta"),
            tuple(
                (m.metric, display(m.previous), display(m.current), display(m.delta))
                for m in regression.metrics
            )
            if regression
            else (),
        )
    )
    items.extend(
        (
            Section(
                "reproduction",
                "Reproduction and artifact references",
                (
                    "Invocation recorded as a JSON argument array"
                    " (data only; never executed by the report):",
                    canonical_json(list(run.command)),
                    f"Tool version: {run.tool_version};"
                    f" git commit: {run.git_commit or 'not supplied'}.",
                    "Use the captured fixture paths mapped in run.json"
                    " when the original checkout is unavailable.",
                    f"Evidence inventory SHA-256: {report.provenance.evidence_digest}",
                ),
                ("Source fixture", "Captured artifact", "SHA-256"),
                tuple((f.source_path, f.artifact_path, f.sha256) for f in run.fixtures),
            ),
            Section("limitations", "Limitations", report.limitations),
        )
    )
    return tuple(items)


def _markdown(value: str) -> str:
    escaped = html.escape(value, quote=True).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~:-])", r"\\\1", escaped)


def render_markdown(report: ReportDocument) -> str:
    lines = [
        f"# {_markdown(report.run.configuration.reporting.title)}",
        "",
        "DVI Sentinel · Local fixture report",
        "",
    ]
    for section in sections(report):
        lines.extend((f"## {section.title}", ""))
        for paragraph in section.paragraphs:
            lines.extend((_markdown(paragraph), ""))
        if section.rows:
            lines.extend(
                (
                    "| " + " | ".join(section.columns) + " |",
                    "| " + " | ".join("---" for _ in section.columns) + " |",
                )
            )
            lines.extend(
                "| " + " | ".join(_markdown(cell) for cell in row) + " |" for row in section.rows
            )
            lines.append("")
    lines.extend(("## Artifact inventory", ""))
    lines.extend(
        f"- [{a.path}]({a.path}) — SHA-256 `{a.sha256}`" for a in report.provenance.artifacts
    )
    return "\n".join(lines) + "\n"


def render_html(report: ReportDocument) -> str:
    template = (
        files("dvi_sentinel").joinpath("templates/report.html.j2").read_text(encoding="utf-8")
    )
    environment = Environment(
        autoescape=True, undefined=StrictUndefined, keep_trailing_newline=True
    )
    return environment.from_string(template).render(report=report, sections=sections(report))
