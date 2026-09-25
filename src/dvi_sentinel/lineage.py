"""Pure deterministic DAG construction, ancestry and transitive integrity checks."""

import hashlib
from collections.abc import Mapping
from typing import Literal

from pydantic import JsonValue

from dvi_sentinel.artifact_models import (
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACTS,
    MAX_BUNDLE_BYTES,
    ArtifactEntry,
    portable_path,
)
from dvi_sentinel.lineage_models import (
    ArtifactLineage,
    IntegrityIssue,
    IntegrityReport,
    LineageEntry,
    LineageNode,
    LineageSpec,
    ParentHash,
    ProvenanceDAG,
    topological_order,
)
from dvi_sentinel.models import ValueModel
from dvi_sentinel.serialization import canonical_json, digest


def encoded(value: ValueModel) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def byte_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bound_contents(contents: Mapping[str, bytes]) -> None:
    if (
        len(contents) > MAX_ARTIFACTS
        or any(len(data) > MAX_ARTIFACT_BYTES for data in contents.values())
        or sum(map(len, contents.values())) > MAX_BUNDLE_BYTES
    ):
        raise ValueError("DVI-LINEAGE-BOUNDS: artifact bytes/count exceed bundle limits")
    for path in contents:
        portable_path(path)


def build_lineage(
    contents: Mapping[str, bytes], specifications: tuple[LineageSpec, ...]
) -> ProvenanceDAG:
    bound_contents(contents)
    order = topological_order(specifications)
    specs = {s.path: s for s in specifications}
    if contents.keys() != specs.keys():
        raise ValueError("DVI-LINEAGE-INVENTORY: each artifact needs exactly one declaration")
    nodes: dict[str, LineageNode] = {}
    for path in order:
        spec, data = specs[path], contents[path]
        entry = ArtifactEntry(path=path, sha256=byte_digest(data), size_bytes=len(data))
        parents = tuple(
            ParentHash(
                path=p, sha256=nodes[p].artifact.sha256, lineage_sha256=nodes[p].lineage_sha256
            )
            for p in spec.parents
        )
        identity: dict[str, JsonValue] = {
            "artifact": entry.model_dump(mode="json"),
            "kind": spec.kind,
            "source": spec.source,
            "parents": [p.model_dump(mode="json") for p in parents],
        }
        nodes[path] = LineageNode(
            artifact=entry,
            kind=spec.kind,
            source=spec.source,
            parents=parents,
            lineage_sha256=digest(identity),
        )
    return ProvenanceDAG(nodes=tuple(nodes[path] for path in sorted(nodes)))


def artifact_lineage(dag: ProvenanceDAG) -> ArtifactLineage:
    dag = ProvenanceDAG.model_validate(dag.model_dump(mode="json"))
    nodes = {n.artifact.path: n for n in dag.nodes}
    ancestors: dict[str, set[str]] = {}
    for path in topological_order(tuple(n.specification() for n in dag.nodes)):
        ancestors[path] = set()
        for parent in nodes[path].parents:
            ancestors[path].update((parent.path, *ancestors[parent.path]))
    return ArtifactLineage(
        dag_sha256=byte_digest(encoded(dag)),
        entries=tuple(
            LineageEntry(
                path=path,
                lineage_sha256=nodes[path].lineage_sha256,
                ancestors=tuple(sorted(ancestors[path])),
            )
            for path in sorted(nodes)
        ),
    )


def verify_lineage(
    dag: ProvenanceDAG,
    contents: Mapping[str, bytes],
    *,
    context: Literal["inspection", "bundle"] = "bundle",
) -> IntegrityReport:
    """Inspect supplied bytes only; no path in a DAG can trigger a file read."""
    if context not in {"inspection", "bundle"}:
        raise ValueError("DVI-LINEAGE-CONTEXT: unknown verification context")
    dag = ProvenanceDAG.model_validate(dag.model_dump(mode="json"))
    bound_contents(contents)
    issues: list[IntegrityIssue] = []
    invalid: set[str] = set()
    nodes = {n.artifact.path: n for n in dag.nodes}
    used = {p.path for n in dag.nodes for p in n.parents}
    for path in topological_order(tuple(n.specification() for n in dag.nodes)):
        node = nodes[path]
        data = contents.get(path)
        codes: list[Literal["missing", "changed", "orphan", "parent_invalid"]] = []
        if data is None:
            codes.append("missing")
        elif len(data) != node.artifact.size_bytes or byte_digest(data) != node.artifact.sha256:
            codes.append("changed")
        if (not node.source and not node.parents) or (node.source and path not in used):
            codes.append("orphan")
        if any(p.path in invalid for p in node.parents):
            codes.append("parent_invalid")
        for code in codes:
            severity: Literal["warning", "error"] = (
                "warning" if code == "orphan" and context == "inspection" else "error"
            )
            issues.append(IntegrityIssue(path=path, code=code, severity=severity))
            if severity == "error":
                invalid.add(path)
    for path in sorted(contents.keys() - nodes.keys()):
        issues.append(IntegrityIssue(path=path, code="untracked", severity="error"))
        invalid.add(path)
    return IntegrityReport(
        dag_sha256=byte_digest(encoded(dag)),
        context=context,
        valid=not invalid,
        checked_artifacts=len(dag.nodes),
        invalidated=tuple(sorted(invalid)),
        issues=tuple(sorted(issues, key=lambda i: (i.path, i.code))),
    )


def lineage_artifacts(dag: ProvenanceDAG, contents: Mapping[str, bytes]) -> dict[str, bytes]:
    return {
        "provenance_dag.json": encoded(dag),
        "artifact_lineage.json": encoded(artifact_lineage(dag)),
        "integrity_report.json": encoded(verify_lineage(dag, contents)),
    }
