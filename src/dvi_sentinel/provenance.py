"""Resolve each classified finding to immutable file, record, and field references."""

from dvi_sentinel.artifact_models import ArtifactEntry, RunRecord
from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.models import TelemetryEvent
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.report_models import (
    EventProvenance,
    EvidenceReference,
    FindingProvenance,
    ProvenanceReport,
)
from dvi_sentinel.score_models import ResilienceFrontier
from dvi_sentinel.serialization import digest
from dvi_sentinel.variation_models import VariationCase


def build_provenance(
    record: RunRecord,
    artifacts: tuple[ArtifactEntry, ...],
    events: tuple[TelemetryEvent, ...],
    cases: tuple[VariationCase, ...],
    probes: tuple[AssumptionProbe, ...],
    differential: DifferentialReport | None,
    score: ResilienceFrontier,
) -> ProvenanceReport:
    indexed = {entry.path: entry for entry in artifacts}

    def ref(path: str, *, line: int | None = None, pointer: str = "") -> EvidenceReference:
        return EvidenceReference(
            artifact=path, sha256=indexed[path].sha256, line=line, pointer=pointer
        )

    normalized = tuple(
        EventProvenance(
            event_id=event.event_id,
            record_digest=event.stable_digest(),
            raw_digest=event.raw.raw_digest,
            reference=ref("normalized_events.jsonl", line=index + 1),
        )
        for index, event in enumerate(events)
    )
    traces = []
    for index, finding in enumerate(score.findings):
        references = [
            ref("run.json", pointer="/configuration"),
            ref("score.json", pointer=f"/findings/{index}"),
        ]
        original_ids = tuple(event.event_id for event in events)
        if finding.source == "variation":
            position, case = next((i, c) for i, c in enumerate(cases) if c.id == finding.case_id)
            original_ids = tuple(
                dict.fromkeys(
                    e.original_event_id for e in case.lineage if e.original_event_id is not None
                )
            )
            references.extend(
                (
                    ref("variations.jsonl", line=position + 1, pointer="/variation"),
                    ref("matches.jsonl", line=position + 1),
                    ref("observations.jsonl", line=position + 1),
                )
            )
        elif finding.source == "probe":
            position, probe = next((i, p) for i, p in enumerate(probes) if p.id == finding.case_id)
            references.extend(
                (
                    ref("assumption_probes.jsonl", line=position + 1, pointer="/events"),
                    ref(
                        "assumption_probes.jsonl",
                        line=position + 1,
                        pointer="/candidate_match" if probe.candidate_match else "/candidate",
                    ),
                    ref("assumption_probes.jsonl", line=position + 1, pointer="/preservation"),
                )
            )
        else:
            if differential is None:
                raise ValueError("DVI-REPORT-PROVENANCE: differential finding lacks evidence")
            position = next(i for i, c in enumerate(differential.cases) if c.id == finding.case_id)
            references.append(ref("differential_schema_report.json", pointer=f"/cases/{position}"))
        references.append(ref("normalized_events.jsonl"))
        references.extend(ref(f.artifact_path) for f in record.fixtures)
        traces.append(
            FindingProvenance(
                finding_id=finding.id,
                scenario_id=record.scenario_id,
                scenario_digest=record.scenario_digest,
                fixture_artifacts=tuple(f.artifact_path for f in record.fixtures),
                event_ids=original_ids,
                references=tuple(references),
            )
        )
    return ProvenanceReport(
        run_id=record.run_id,
        evidence_digest=digest([a.model_dump(mode="json") for a in artifacts]),
        artifacts=artifacts,
        events=normalized,
        findings=tuple(traces),
    )
