"""Bounded content and parent-hash contracts for local artifact provenance."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from dvi_sentinel.artifact_models import MAX_ARTIFACTS, ArtifactEntry, portable_path
from dvi_sentinel.models import NonEmpty, Sha256, ValueModel
from dvi_sentinel.serialization import digest

ArtifactKind = Literal[
    "scenario",
    "input_fixture",
    "normalized_events",
    "schema_projection",
    "variation_case",
    "oracle_decision",
    "match_result",
    "score_result",
    "counterfactual_result",
    "shrunk_case",
    "report",
    "benchmark_result",
    "configuration",
    "run_record",
    "observation",
    "analysis",
]
Paths = Annotated[tuple[NonEmpty, ...], Field(max_length=MAX_ARTIFACTS)]


def ordered_paths(values: tuple[str, ...]) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError("DVI-LINEAGE-ORDER: paths must be unique and sorted")
    for value in values:
        portable_path(value)
    return values


class LineageSpec(ValueModel):
    path: NonEmpty
    kind: ArtifactKind
    source: StrictBool = False
    parents: Paths = ()
    _path = field_validator("path")(portable_path)
    _parents = field_validator("parents")(ordered_paths)

    @model_validator(mode="after")
    def roots(self) -> Self:
        if self.path in self.parents or (
            self.source
            and (self.parents or self.kind not in {"scenario", "input_fixture", "configuration"})
        ):
            raise ValueError("DVI-LINEAGE-SOURCE: invalid source or self-parent")
        return self


class ParentHash(ValueModel):
    path: NonEmpty
    sha256: Sha256
    lineage_sha256: Sha256
    _path = field_validator("path")(portable_path)


class LineageNode(ValueModel):
    artifact: ArtifactEntry
    kind: ArtifactKind
    source: StrictBool
    parents: Annotated[tuple[ParentHash, ...], Field(max_length=MAX_ARTIFACTS)]
    lineage_sha256: Sha256

    def specification(self) -> LineageSpec:
        return LineageSpec(
            path=self.artifact.path,
            kind=self.kind,
            source=self.source,
            parents=tuple(p.path for p in self.parents),
        )

    @model_validator(mode="after")
    def identity(self) -> Self:
        self.specification()
        if self.lineage_sha256 != digest(self.model_dump(mode="json", exclude={"lineage_sha256"})):
            raise ValueError("DVI-LINEAGE-HASH: derived identity differs")
        return self


class ProvenanceDAG(ValueModel):
    schema_version: Literal["1"] = "1"
    nodes: Annotated[tuple[LineageNode, ...], Field(min_length=1, max_length=MAX_ARTIFACTS)]

    @model_validator(mode="after")
    def topology(self) -> Self:
        ordered_paths(tuple(n.artifact.path for n in self.nodes))
        indexed = {n.artifact.path: n for n in self.nodes}
        for node in self.nodes:
            for parent in node.parents:
                actual = indexed.get(parent.path)
                if actual is None:
                    raise ValueError("DVI-LINEAGE-PARENT: missing parent node")
                if (parent.sha256, parent.lineage_sha256) != (
                    actual.artifact.sha256,
                    actual.lineage_sha256,
                ):
                    raise ValueError("DVI-LINEAGE-PARENT: parent hash reference differs")
        topological_order(tuple(n.specification() for n in self.nodes))
        return self


def topological_order(specifications: tuple[LineageSpec, ...]) -> tuple[str, ...]:
    pending = {s.path: set(s.parents) for s in specifications}
    if len(pending) != len(specifications) or not pending or len(pending) > MAX_ARTIFACTS:
        raise ValueError("DVI-LINEAGE-BOUNDS: require 1..128 unique artifact paths")
    if any(parents - pending.keys() for parents in pending.values()):
        raise ValueError("DVI-LINEAGE-PARENT: missing parent node")
    done: list[str] = []
    while pending:
        ready = sorted(path for path, parents in pending.items() if not parents)
        if not ready:
            raise ValueError("DVI-LINEAGE-CYCLE: cyclic parent references")
        done.extend(ready)
        for path in ready:
            del pending[path]
        for parents in pending.values():
            parents.difference_update(ready)
    return tuple(done)


class LineageEntry(ValueModel):
    path: NonEmpty
    lineage_sha256: Sha256
    ancestors: Paths
    _path = field_validator("path")(portable_path)
    _ancestors = field_validator("ancestors")(ordered_paths)


class ArtifactLineage(ValueModel):
    schema_version: Literal["1"] = "1"
    dag_sha256: Sha256
    entries: Annotated[tuple[LineageEntry, ...], Field(max_length=MAX_ARTIFACTS)]


class IntegrityIssue(ValueModel):
    path: NonEmpty
    code: Literal["missing", "changed", "untracked", "orphan", "parent_invalid"]
    severity: Literal["error", "warning"]
    _path = field_validator("path")(portable_path)


class IntegrityReport(ValueModel):
    schema_version: Literal["1"] = "1"
    dag_sha256: Sha256
    context: Literal["inspection", "bundle"]
    valid: StrictBool
    checked_artifacts: Annotated[StrictInt, Field(ge=0, le=MAX_ARTIFACTS)]
    invalidated: Annotated[tuple[NonEmpty, ...], Field(max_length=MAX_ARTIFACTS * 2)]
    issues: Annotated[tuple[IntegrityIssue, ...], Field(max_length=MAX_ARTIFACTS * 4)]
    _invalidated = field_validator("invalidated")(ordered_paths)


class LineageSummary(ValueModel):
    schema_version: Literal["1"] = "1"
    dag_artifact: Literal["provenance_dag.json"] = "provenance_dag.json"
    evidence_sha256: Sha256
    artifacts: Annotated[StrictInt, Field(ge=1, le=MAX_ARTIFACTS)]
    parent_links: Annotated[StrictInt, Field(ge=0, le=MAX_ARTIFACTS**2)]
    roots: Paths
    scope: Literal["evidence_excluding_reports_and_integrity_controls"] = (
        "evidence_excluding_reports_and_integrity_controls"
    )
    _roots = field_validator("roots")(ordered_paths)
