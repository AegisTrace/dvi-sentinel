"""Check typed evidence and derived metrics after the manifest byte checks pass."""

import hashlib
from pathlib import Path

from pydantic import BaseModel

from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_models import (
    MAX_ARTIFACT_BYTES,
    ArtifactManifest,
    RunRecord,
    VariationArtifact,
    VariationDigest,
)
from dvi_sentinel.comparison import snapshot_from_plan
from dvi_sentinel.comparison_models import ComparisonSnapshot
from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.harness_models import FixtureResults, HarnessResult
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.scenario_io import parse_scenario
from dvi_sentinel.score_models import CaseAssessment, ResilienceFrontier
from dvi_sentinel.scoring import summarize
from dvi_sentinel.serialization import canonical_json, digest, parse_json
from dvi_sentinel.shrinking import shrink_artifacts
from dvi_sentinel.shrinking_models import MinimalCounterexample
from dvi_sentinel.variation_models import VariationPlan


def read_model[T: BaseModel](root: Path, path: str, model: type[T]) -> T:
    return model.model_validate(parse_json(read_fixture(root, path, limit=MAX_ARTIFACT_BYTES)))


def read_jsonl[T: BaseModel](root: Path, path: str, model: type[T]) -> tuple[T, ...]:
    contents = read_fixture(root, path, limit=MAX_ARTIFACT_BYTES).decode("utf-8")
    return tuple(model.model_validate(parse_json(line)) for line in contents.splitlines())


def _require(condition: bool, explanation: str) -> None:
    if not condition:
        raise ValueError(f"DVI-ARTIFACT-CONTRACT: {explanation}")


def _fixtures(root: Path, record: RunRecord, events: tuple[TelemetryEvent, ...]) -> None:
    telemetry = tuple(f for f in record.fixtures if f.role == "telemetry")
    _require(len(telemetry) == len(record.configuration.inputs), "fixture coverage differs")
    normalized: list[TelemetryEvent] = []
    for source, entry in zip(record.configuration.inputs, telemetry, strict=True):
        raw = read_fixture(root, entry.artifact_path)
        parsed = normalize(raw, source.format)
        _require(
            entry.source_path == source.path
            and parsed.input_digest == entry.sha256
            and parsed.parser_success
            and digest([e.model_dump(mode="json") for e in parsed.events])
            == entry.normalized_digest,
            "captured telemetry differs from its provenance",
        )
        normalized.extend(parsed.events)
    _require(tuple(normalized) == events, "captured fixtures normalize to different events")
    detector = tuple(f for f in record.fixtures if f.role == "detector_results")
    configuration = record.configuration.harness
    _require(len(detector) == (1 if configuration.kind == "fixture" else 0), "detector capture")
    fixture_digest = None
    if configuration.kind == "fixture":
        entry = detector[0]
        raw = read_fixture(root, entry.artifact_path)
        FixtureResults.model_validate(parse_json(raw))
        fixture_digest = hashlib.sha256(raw).hexdigest()
        _require(
            entry.source_path == configuration.path and entry.sha256 == fixture_digest,
            "detector fixture digest differs",
        )
    _require(
        record.detector_digest
        == digest(
            {
                "configuration": configuration.model_dump(mode="json"),
                "fixture_sha256": fixture_digest,
            }
        ),
        "detector configuration digest differs",
    )


def validate_contract(root: Path, record: RunRecord, manifest: ArtifactManifest) -> None:
    events = read_jsonl(root, "normalized_events.jsonl", TelemetryEvent)
    cases = tuple(v.variation for v in read_jsonl(root, "variations.jsonl", VariationArtifact))
    plan = VariationPlan.model_validate(record.planning | {"cases": cases})
    scenario = parse_scenario(canonical_json(record.configuration))
    _require(
        bool(cases) and cases[0].family == "baseline" and cases[0].events == events,
        "baseline is not the original event sequence",
    )
    _require(
        plan.stable_digest() == record.plan_digest
        and plan.input_digest
        == record.normalized_input_digest
        == digest([e.model_dump(mode="json") for e in events])
        and plan.config_digest
        == record.config_digest
        == digest(
            {
                "policy": scenario.variations.model_dump(mode="json"),
                "event_budget": plan.event_budget,
            }
        )
        and plan.scenario_id == record.scenario_id
        and plan.seed == record.seed
        and plan.tool_version == record.tool_version
        and scenario.stable_digest() == record.scenario_digest
        and digest(scenario.model_dump(mode="json", exclude={"harness"}))
        == record.comparison_scenario_digest,
        "plan, scenario, or normalized input digest differs",
    )
    _require(
        record.variations
        == tuple(
            VariationDigest(
                case_id=c.id,
                sha256=c.stable_digest(),
                events_sha256=digest([e.model_dump(mode="json") for e in c.events]),
            )
            for c in cases
        ),
        "variation fingerprint inventory differs",
    )
    _fixtures(root, record, events)
    observations = read_jsonl(root, "observations.jsonl", HarnessResult)
    indexed = {o.case_id: o for o in observations}
    _require(
        len(indexed) == len(observations) == len(cases) and set(indexed) == {c.id for c in cases},
        "observation coverage differs",
    )
    rows = []
    for case in cases:
        preservation = check_candidate(
            events, case.events, case.lineage, scenario.variations, case.family
        )
        _require(preservation == case.preservation, "independent invariant checks differ")
        rows.append(
            CaseAssessment(
                case_id=case.id,
                family=case.family,
                distance=case.distance,
                preservation=preservation,
                parser_success=True,
                match=match_detection(
                    scenario.expected, indexed[case.id], case.events, preservation=preservation
                ),
            )
        )
    _require(
        read_jsonl(root, "matches.jsonl", MatchResult) == tuple(r.match for r in rows),
        "stored matches differ from observation evidence",
    )
    probes = read_jsonl(root, "assumption_probes.jsonl", AssumptionProbe)
    paths = {entry.path for entry in manifest.artifacts}
    differential = (
        read_model(root, "differential_schema_report.json", DifferentialReport)
        if "differential_schema_report.json" in paths
        else None
    )
    _require(
        all(p.input_digest == record.normalized_input_digest for p in probes)
        and (
            differential is None
            or (
                differential.input_digest == record.normalized_input_digest
                and differential.events == events
            )
        ),
        "optional analysis uses different input",
    )
    snapshot = snapshot_from_plan(
        plan,
        tuple(rows),
        scenario_digest=record.comparison_scenario_digest,
        detector_digest=record.detector_digest,
        probes=probes,
        differential=differential,
    )
    _require(
        read_model(root, "comparison.json", ComparisonSnapshot) == snapshot, "comparison differs"
    )
    _require(
        read_model(root, "score.json", ResilienceFrontier)
        == summarize(tuple(rows), probes=probes, differential=differential),
        "derived score differs",
    )
    shrink_paths = {
        "minimal_case.json",
        "minimal_case.md",
        "shrinking_trace.jsonl",
        "root_cause.json",
    }
    if paths & shrink_paths:
        _require(paths >= shrink_paths, "incomplete shrinking evidence")
        minimal = read_model(root, "minimal_case.json", MinimalCounterexample)
        _require(
            minimal.original_events == events
            and minimal.expected == scenario.expected
            and minimal.policy == scenario.variations,
            "shrinking context differs",
        )
        for name, text in shrink_artifacts(minimal).items():
            _require(
                read_fixture(root, name, limit=MAX_ARTIFACT_BYTES) == text.encode("utf-8"),
                "shrinking evidence differs",
            )
    _require(
        record.run_id
        == "run:"
        + digest(
            {
                "scenario": record.scenario_digest,
                "plan": record.plan_digest,
                "detector": record.detector_digest,
            }
        )[:24],
        "run ID differs from deterministic identity",
    )
