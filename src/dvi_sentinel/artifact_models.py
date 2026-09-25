"""Versioned run provenance, portable manifest entries, and verification evidence."""

import re
from typing import Annotated, Literal

from pydantic import Field, JsonValue, StrictInt, field_validator, model_validator

from dvi_sentinel.models import Identifier, NonEmpty, Sha256, Timestamp, ValueModel
from dvi_sentinel.scenario import SafetyDeclaration, Scenario
from dvi_sentinel.variation_models import VariationCase

MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_ARTIFACTS = 128
LINEAGE_FILES = {"provenance_dag.json", "artifact_lineage.json", "integrity_report.json"}
REQUIRED_ARTIFACTS = {
    "run.json",
    "score.json",
    "variations.jsonl",
    "normalized_events.jsonl",
    "matches.jsonl",
    "assumption_probes.jsonl",
    "observations.jsonl",
    "comparison.json",
}


def portable_path(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,199}", value) or any(
        part in {"", ".", ".."}
        or part.endswith(".")
        or part.split(".")[0]
        in {
            "con",
            "prn",
            "aux",
            "nul",
            *(f"com{i}" for i in range(1, 10)),
            *(f"lpt{i}" for i in range(1, 10)),
        }
        for part in value.split("/")
    ):
        raise ValueError("DVI-ARTIFACT-PATH: require a portable relative artifact path")
    return value


class FixtureDigest(ValueModel):
    source_path: NonEmpty
    artifact_path: NonEmpty
    role: Literal["telemetry", "detector_results"]
    sha256: Sha256
    normalized_digest: Sha256 | None

    _path = field_validator("artifact_path")(portable_path)


class VariationDigest(ValueModel):
    case_id: Identifier
    sha256: Sha256
    events_sha256: Sha256


class RunRecord(ValueModel):
    schema_version: Literal["1"] = "1"
    product: Literal["dvi-sentinel"] = "dvi-sentinel"
    tool_version: NonEmpty
    run_id: Identifier
    scenario_id: Identifier
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    started_at: Timestamp
    finished_at: Timestamp
    command: tuple[NonEmpty, ...]
    configuration: Scenario
    scenario_digest: Sha256
    comparison_scenario_digest: Sha256
    config_digest: Sha256
    normalized_input_digest: Sha256
    detector_digest: Sha256
    planning: dict[str, JsonValue]
    plan_digest: Sha256
    fixtures: tuple[FixtureDigest, ...]
    variations: tuple[VariationDigest, ...]
    policy_attestation: SafetyDeclaration
    git_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")] | None = None

    @model_validator(mode="after")
    def coherent(self) -> "RunRecord":
        if self.finished_at < self.started_at:
            raise ValueError("run end precedes its start")
        if (
            self.configuration.metadata.id != self.scenario_id
            or self.policy_attestation != self.configuration.safety
        ):
            raise ValueError("scenario identity and policy attestation must match configuration")
        if len({entry.case_id for entry in self.variations}) != len(self.variations):
            raise ValueError("duplicate variation IDs")
        return self


class ArtifactEntry(ValueModel):
    path: NonEmpty
    sha256: Sha256
    size_bytes: Annotated[StrictInt, Field(ge=0, le=MAX_ARTIFACT_BYTES)]
    _path = field_validator("path")(portable_path)


class ArtifactManifest(ValueModel):
    schema_version: Literal["1", "2"] = "1"
    product: Literal["dvi-sentinel"] = "dvi-sentinel"
    tool_version: NonEmpty
    run_id: Identifier
    artifacts: Annotated[tuple[ArtifactEntry, ...], Field(max_length=MAX_ARTIFACTS)]

    @model_validator(mode="after")
    def coherent(self) -> "ArtifactManifest":
        paths = [entry.path for entry in self.artifacts]
        if paths != sorted(set(paths)) or "manifest.json" in paths:
            raise ValueError(
                "manifest paths must be unique, sorted, and exclude the manifest itself"
            )
        if not set(paths) >= REQUIRED_ARTIFACTS:
            raise ValueError("manifest is missing a required artifact")
        if self.schema_version == "2":
            if not set(paths) >= LINEAGE_FILES | {"scenario.json"}:
                raise ValueError("schema-2 manifest requires complete provenance DAG artifacts")
        elif set(paths) & LINEAGE_FILES:
            raise ValueError("lineage artifacts require manifest schema version 2")
        if sum(entry.size_bytes for entry in self.artifacts) > MAX_BUNDLE_BYTES:
            raise ValueError("artifact bundle exceeds 128 MiB")
        return self


class ArtifactIssue(ValueModel):
    code: NonEmpty
    path: NonEmpty
    explanation: NonEmpty


class ArtifactVerification(ValueModel):
    valid: bool
    manifest_digest: Sha256 | None = None
    run_id: Identifier | None = None
    issues: tuple[ArtifactIssue, ...] = ()


class VariationArtifact(ValueModel):
    schema_version: Literal["1"] = "1"
    variation: VariationCase
