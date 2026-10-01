"""Explicit local V2 analysis commands over the existing native engines (C)."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from dvi_sentinel.cli.analysis_io import capture, destination, execute, finish
from dvi_sentinel.cli.analysis_models import EventInput, ExplorationInput, TemporalInput
from dvi_sentinel.cli.common import fail
from dvi_sentinel.confidence import confidence_artifacts
from dvi_sentinel.confidence_models import ConfidenceInput, ConfidenceReport
from dvi_sentinel.constraint_models import ExplorationPlan
from dvi_sentinel.counterfactual_models import CounterfactualInput, CounterfactualSummary
from dvi_sentinel.counterfactuals import counterfactual_artifacts
from dvi_sentinel.detection_intent import intent_artifacts
from dvi_sentinel.exploration import exploration_artifacts
from dvi_sentinel.intent_models import IntentAnalysis
from dvi_sentinel.intent_parsing import parse_intent
from dvi_sentinel.knowledge_graph import graph_artifacts
from dvi_sentinel.knowledge_graph_models import GraphReport
from dvi_sentinel.local_fixtures import MAX_SCENARIO_BYTES
from dvi_sentinel.mapping_models import MappingExport
from dvi_sentinel.ontology import export_ontology, ontology_artifacts
from dvi_sentinel.ontology_models import OntologyExport
from dvi_sentinel.oracle_consensus import oracle_artifacts
from dvi_sentinel.oracle_models import OracleConsensus, OracleEvidence
from dvi_sentinel.schema_mapping import mapping_artifacts
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.temporal import temporal_artifacts
from dvi_sentinel.temporal_models import TemporalSummary

Input = Annotated[Path, typer.Argument(help="Local typed JSON input; see docs/cli.md.")]
Out = Annotated[Path | None, typer.Option(help="Write native artifacts to a new local directory.")]
Json = Annotated[bool, typer.Option("--json", help="Print the complete typed result and digests.")]
Pin = Annotated[str | None, typer.Option("--input-sha256", help="Require this input file SHA-256.")]
Seed = Annotated[int | None, typer.Option(min=0, max=2**63 - 1, help="Override the input seed.")]


class RuleFormat(StrEnum):
    dvi = "dvi"
    sigma_metadata = "sigma_metadata"
    v1_rule = "v1_rule"


def ontology_command(
    input: Input, out: Out = None, json_output: Json = False, input_sha256: Pin = None
) -> None:
    """Extract semantic signals, bindings and losses from canonical events."""
    execute(
        "ontology",
        input,
        EventInput,
        lambda r: ontology_artifacts(export_ontology(r.events)),
        "semantic_ontology.json",
        OntologyExport,
        lambda r: (
            f"{sum(e.state == 'known' for e in r.extractions)}/{len(r.extractions)} signals known"
        ),
        out,
        json_output,
        input_sha256,
    )


def map_schema_command(
    input: Input, out: Out = None, json_output: Json = False, input_sha256: Pin = None
) -> None:
    """Measure roundtrip losses through seven local schema/metadata subsets."""
    execute(
        "map-schema",
        input,
        EventInput,
        lambda r: mapping_artifacts(r.events),
        "mapping_report.json",
        MappingExport,
        lambda r: (
            f"{len(r.reports)} roundtrips; "
            f"{sum(x.decision == 'lossy' for x in r.reports)} lossy; "
            f"{sum(x.decision == 'unknown' for x in r.reports)} unknown"
        ),
        out,
        json_output,
        input_sha256,
    )


def analyze_rule_command(
    rule: Annotated[Path, typer.Argument(help="Local YAML/JSON intent or rule declaration.")],
    events: Annotated[Path, typer.Option(help="Canonical EventInput JSON.")],
    format: Annotated[
        RuleFormat, typer.Option(help="Explicit local declaration format.")
    ] = RuleFormat.dvi,
    out: Out = None,
    json_output: Json = False,
    input_sha256: Pin = None,
    events_sha256: Annotated[
        str | None, typer.Option(help="Require this events file SHA-256.")
    ] = None,
) -> None:
    """Analyze rule intent against evidence; unsupported conditions remain unknown."""
    try:
        output = destination(out)
        declaration = capture(rule, role="rule", expected=input_sha256, limit=MAX_SCENARIO_BYTES)
        source = capture(events, role="events", expected=events_sha256)
        request = EventInput.model_validate(parse_json(source.content))
        parsed = parse_intent(declaration.content.decode("utf-8"), format.value)
        files = intent_artifacts(parsed, request.events)
        result = IntentAnalysis.model_validate(parse_json(files["semantic_loss_report.json"]))
        finish(
            "analyze-rule",
            files,
            result,
            f"{result.state}; {len(result.candidates)} event candidates",
            (declaration, source),
            output,
            json_output,
        )
    except (ValueError, OSError, RecursionError, OverflowError) as exc:
        fail(exc, json_output)


def temporal_command(
    input: Input, out: Out = None, json_output: Json = False, input_sha256: Pin = None
) -> None:
    """Evaluate bounded time, sequence and correlation predicates."""
    execute(
        "temporal",
        input,
        TemporalInput,
        lambda r: temporal_artifacts(
            r.events, window_ms=r.window_ms, pattern=r.pattern, precision_digits=r.precision_digits
        ),
        "temporal_summary.json",
        TemporalSummary,
        lambda r: (
            f"{r.state}; {len(r.traces)} predicate decisions; "
            f"{sum(t.check.outcome == 'unknown' for t in r.traces)} unknown"
        ),
        out,
        json_output,
        input_sha256,
    )


def _oracle_summary(result: OracleConsensus) -> str:
    if result.blocking_oracles:
        raise ValueError(
            "DVI-CLI-GATE: blocked oracle evidence: " + ", ".join(result.blocking_oracles)
        )
    return f"{result.state}; {len(result.decisions)} oracle decisions; {result.explanation}"


def oracles_command(
    input: Input, out: Out = None, json_output: Json = False, input_sha256: Pin = None
) -> None:
    """Recompute nine evidence checks and retain consensus uncertainty."""
    execute(
        "oracles",
        input,
        OracleEvidence,
        lambda r: oracle_artifacts(r, expected_digest=r.stable_digest()),
        "oracle_consensus.json",
        OracleConsensus,
        _oracle_summary,
        out,
        json_output,
        input_sha256,
    )


def explore_command(
    input: Input,
    out: Out = None,
    seed: Seed = None,
    json_output: Json = False,
    input_sha256: Pin = None,
) -> None:
    """Plan feasible covering cases from an explicit bounded parameter space."""
    execute(
        "explore",
        input,
        ExplorationInput,
        lambda r: exploration_artifacts(
            r.events, r.space, r.policy, seed=r.seed if seed is None else seed, budget=r.budget
        ),
        "constraint_plan.json",
        ExplorationPlan,
        lambda r: (
            f"{r.covering.state}; {len(r.cases)} selected; "
            f"{len(r.invalid)} rejected; {len(r.skipped)} skipped; seed {r.seed}"
        ),
        out,
        json_output,
        input_sha256,
    )


def _explain(request: CounterfactualInput, seed: int | None) -> dict[str, bytes]:
    if seed is not None:
        request = CounterfactualInput.model_validate(request.model_dump() | {"seed": seed})
    return counterfactual_artifacts(request, expected_digest=request.stable_digest())


def _explanation_summary(result: CounterfactualSummary) -> str:
    if result.input is None or result.state == "unsafe_rejected":
        raise ValueError("DVI-CLI-GATE: counterfactual safety or integrity gate blocked the input")
    return (
        f"{result.state}; {len(result.findings)} minimal local findings; "
        f"{result.evaluations} evaluations"
    )


def explain_command(
    input: Input,
    out: Out = None,
    seed: Seed = None,
    json_output: Json = False,
    input_sha256: Pin = None,
) -> None:
    """Mine conditional local counterfactual causes using an explicit rule harness."""
    execute(
        "explain",
        input,
        CounterfactualInput,
        lambda r: _explain(r, seed),
        "counterfactual_summary.json",
        CounterfactualSummary,
        _explanation_summary,
        out,
        json_output,
        input_sha256,
    )


def _confidence(request: ConfidenceInput, seed: int | None) -> dict[str, bytes]:
    if seed is not None:
        settings = request.settings.model_dump() | {"bootstrap_seed": seed}
        request = ConfidenceInput.model_validate(request.model_dump() | {"settings": settings})
    return confidence_artifacts(request, expected_digest=request.stable_digest())


def _confidence_summary(result: ConfidenceReport) -> str:
    if result.input is None or any(g.blocking for g in result.gates):
        raise ValueError("DVI-CLI-GATE: confidence safety or integrity gate blocked the input")
    classes = ", ".join(sorted({g.confidence_class.replace("_", " ") for g in result.groups}))
    return f"{result.state}; {len(result.groups)} groups; {classes or 'no eligible groups'}"


def confidence_command(
    input: Input,
    out: Out = None,
    seed: Seed = None,
    json_output: Json = False,
    input_sha256: Pin = None,
) -> None:
    """Measure conditional intervals, seed agreement and regression uncertainty."""
    execute(
        "confidence",
        input,
        ConfidenceInput,
        lambda r: _confidence(r, seed),
        "confidence.json",
        ConfidenceReport,
        _confidence_summary,
        out,
        json_output,
        input_sha256,
    )


def _graph_summary(result: GraphReport) -> str:
    if result.source is None:
        raise ValueError("DVI-CLI-GATE: graph safety or integrity gate blocked the input")
    return (
        f"{result.state}; {result.summary.nodes} nodes; {result.summary.edges} edges; "
        f"{result.summary.weak_edges} weak edges; recommendations remain untested"
    )


def graph_command(
    input: Input, out: Out = None, json_output: Json = False, input_sha256: Pin = None
) -> None:
    """Build linked knowledge-graph views from a retained counterfactual summary."""
    execute(
        "graph",
        input,
        CounterfactualSummary,
        lambda r: graph_artifacts(r, expected_digest=r.stable_digest()),
        "detection_graph.json",
        GraphReport,
        _graph_summary,
        out,
        json_output,
        input_sha256,
    )
