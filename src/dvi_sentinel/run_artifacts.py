"""Assemble real local run evidence into a deterministic, versioned artifact bundle."""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel

from dvi_sentinel import __version__
from dvi_sentinel.adapters import normalize
from dvi_sentinel.artifact_models import (
    MAX_ARTIFACT_BYTES,
    MAX_BUNDLE_BYTES,
    FixtureDigest,
    RunRecord,
    VariationArtifact,
    VariationDigest,
)
from dvi_sentinel.artifact_store import ArtifactError
from dvi_sentinel.comparison import snapshot_from_plan
from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.harness_models import FixtureResults, HarnessResult
from dvi_sentinel.invariants import check_candidate
from dvi_sentinel.matching import match_detection
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.scenario import FixtureInput, Scenario
from dvi_sentinel.score_models import CaseAssessment
from dvi_sentinel.scoring import summarize
from dvi_sentinel.serialization import canonical_json, digest, parse_json
from dvi_sentinel.shrinking import shrink_artifacts
from dvi_sentinel.shrinking_models import MinimalCounterexample
from dvi_sentinel.variation_models import VariationPlan


@dataclass(frozen=True)
class FixtureCapture:
    specification: FixtureInput
    content: bytes


@dataclass(frozen=True)
class RunEvidence:
    scenario: Scenario
    fixtures: tuple[FixtureCapture, ...]
    plan: VariationPlan
    observations: tuple[HarnessResult, ...]
    probes: tuple[AssumptionProbe, ...] = ()
    differential: DifferentialReport | None = None
    minimal: MinimalCounterexample | None = None
    harness_fixture: bytes | None = None


def json_bytes(value: BaseModel) -> bytes:
    encoded = (canonical_json(value) + "\n").encode("utf-8")
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ArtifactError("DVI-ARTIFACT-SIZE: JSON artifact exceeds 32 MiB")
    return encoded


def jsonl_bytes(values: Iterable[BaseModel]) -> bytes:
    output = bytearray()
    for value in values:
        line = json_bytes(value)
        if len(output) + len(line) > MAX_ARTIFACT_BYTES:
            raise ArtifactError("DVI-ARTIFACT-SIZE: JSONL artifact exceeds 32 MiB")
        output.extend(line)
    return bytes(output)


def build_run_artifacts(
    evidence: RunEvidence,
    *,
    started_at: datetime,
    finished_at: datetime,
    command: tuple[str, ...] = ("dvi", "run"),
    git_commit: str | None = None,
) -> dict[str, bytes]:
    scenario, plan = evidence.scenario, evidence.plan
    if tuple(capture.specification for capture in evidence.fixtures) != scenario.inputs:
        raise ArtifactError("DVI-ARTIFACT-INPUT: captures must match all declared fixture inputs")
    files: dict[str, bytes] = {}
    fingerprints = []
    events: list[TelemetryEvent] = []
    for index, capture in enumerate(evidence.fixtures):
        parsed = normalize(capture.content, capture.specification.format)
        if not parsed.parser_success:
            raise ArtifactError("DVI-ARTIFACT-INPUT: completed-run fixtures must normalize safely")
        events.extend(parsed.events)
        extension = "csv" if capture.specification.format == "csv" else "jsonl"
        path = f"fixtures/telemetry-{index:03d}.{extension}"
        files[path] = capture.content
        fingerprints.append(
            FixtureDigest(
                source_path=capture.specification.path,
                artifact_path=path,
                role="telemetry",
                sha256=parsed.input_digest,
                normalized_digest=digest([e.model_dump(mode="json") for e in parsed.events]),
            )
        )
    original = tuple(events)
    input_digest = digest([event.model_dump(mode="json") for event in original])
    if (
        plan.scenario_id != scenario.metadata.id
        or plan.input_digest != input_digest
        or plan.tool_version != __version__
    ):
        raise ArtifactError("DVI-ARTIFACT-IDENTITY: scenario, plan, or normalized input differs")
    if not plan.cases or plan.cases[0].family != "baseline" or plan.cases[0].events != original:
        raise ArtifactError("DVI-ARTIFACT-BASELINE: plan must start with the original sequence")
    if plan.config_digest != digest(
        {"policy": scenario.variations.model_dump(mode="json"), "event_budget": plan.event_budget}
    ):
        raise ArtifactError("DVI-ARTIFACT-CONFIG: planner policy differs from scenario")
    detector_fixture_digest = None
    if scenario.harness.kind == "fixture":
        if evidence.harness_fixture is None:
            raise ArtifactError("DVI-ARTIFACT-HARNESS: fixture harness source must be captured")
        if len(evidence.harness_fixture) > 2 * 1024 * 1024:
            raise ArtifactError("DVI-ARTIFACT-HARNESS: fixture exceeds 2 MiB")
        FixtureResults.model_validate(parse_json(evidence.harness_fixture))
        path = "fixtures/detector-results.json"
        files[path] = evidence.harness_fixture
        detector_fixture_digest = hashlib.sha256(evidence.harness_fixture).hexdigest()
        fingerprints.append(
            FixtureDigest(
                source_path=scenario.harness.path,
                artifact_path=path,
                role="detector_results",
                sha256=detector_fixture_digest,
                normalized_digest=None,
            )
        )
    elif evidence.harness_fixture is not None:
        raise ArtifactError("DVI-ARTIFACT-HARNESS: unexpected fixture source for a rule harness")
    detector_digest = digest(
        {
            "configuration": scenario.harness.model_dump(mode="json"),
            "fixture_sha256": detector_fixture_digest,
        }
    )
    observations = {observation.case_id: observation for observation in evidence.observations}
    if len(observations) != len(evidence.observations) or set(observations) != {
        case.id for case in plan.cases
    }:
        raise ArtifactError("DVI-ARTIFACT-OBSERVATIONS: require one observation per planned case")
    assessments = []
    for case in plan.cases:
        independent = check_candidate(
            original, case.events, case.lineage, scenario.variations, case.family
        )
        if independent != case.preservation:
            raise ArtifactError(
                "DVI-ARTIFACT-INVARIANT: stored checks differ from independent validation"
            )
        assessments.append(
            CaseAssessment(
                case_id=case.id,
                family=case.family,
                distance=case.distance,
                preservation=independent,
                parser_success=True,
                match=match_detection(
                    scenario.expected, observations[case.id], case.events, preservation=independent
                ),
            )
        )
    if (
        any(probe.input_digest != input_digest for probe in evidence.probes)
        or (
            evidence.differential is not None and evidence.differential.input_digest != input_digest
        )
        or (
            evidence.minimal is not None
            and (
                evidence.minimal.original_events != original
                or evidence.minimal.expected != scenario.expected
                or evidence.minimal.policy != scenario.variations
            )
        )
    ):
        raise ArtifactError("DVI-ARTIFACT-EVIDENCE: analysis belongs to different input events")
    rows = tuple(assessments)
    comparison_digest = digest(scenario.model_dump(mode="json", exclude={"harness"}))
    snapshot = snapshot_from_plan(
        plan,
        rows,
        scenario_digest=comparison_digest,
        detector_digest=detector_digest,
        probes=evidence.probes,
        differential=evidence.differential,
    )
    scenario_digest = scenario.stable_digest()
    plan_digest = plan.stable_digest()
    run_id = (
        "run:"
        + digest({"scenario": scenario_digest, "plan": plan_digest, "detector": detector_digest})[
            :24
        ]
    )
    record = RunRecord(
        tool_version=__version__,
        run_id=run_id,
        scenario_id=scenario.metadata.id,
        seed=plan.seed,
        started_at=started_at,
        finished_at=finished_at,
        command=command,
        configuration=scenario,
        scenario_digest=scenario_digest,
        comparison_scenario_digest=comparison_digest,
        config_digest=plan.config_digest,
        normalized_input_digest=input_digest,
        detector_digest=detector_digest,
        planning=plan.model_dump(mode="json", exclude={"cases"}),
        plan_digest=plan_digest,
        fixtures=tuple(fingerprints),
        variations=tuple(
            VariationDigest(
                case_id=case.id,
                sha256=case.stable_digest(),
                events_sha256=snapshot.case_input_digests[case.id],
            )
            for case in plan.cases
        ),
        policy_attestation=scenario.safety,
        git_commit=git_commit,
    )
    files.update(
        {
            "run.json": json_bytes(record),
            "score.json": json_bytes(
                summarize(rows, probes=evidence.probes, differential=evidence.differential)
            ),
            "variations.jsonl": jsonl_bytes(
                VariationArtifact(variation=case) for case in plan.cases
            ),
            "normalized_events.jsonl": jsonl_bytes(original),
            "matches.jsonl": jsonl_bytes(row.match for row in rows if row.match is not None),
            "observations.jsonl": jsonl_bytes(observations[case.id] for case in plan.cases),
            "assumption_probes.jsonl": jsonl_bytes(evidence.probes),
            "comparison.json": json_bytes(snapshot),
        }
    )
    if evidence.differential:
        files["differential_schema_report.json"] = json_bytes(evidence.differential)
    if evidence.minimal:
        files.update(
            {
                name: text.encode("utf-8")
                for name, text in shrink_artifacts(evidence.minimal).items()
            }
        )
    if (
        any(len(content) > MAX_ARTIFACT_BYTES for content in files.values())
        or sum(map(len, files.values())) > MAX_BUNDLE_BYTES
    ):
        raise ArtifactError("DVI-ARTIFACT-SIZE: completed run exceeds artifact resource bounds")
    return files
