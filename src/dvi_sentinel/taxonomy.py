"""Evidence-linked associations, not causal attribution or statistical discovery."""

from dvi_sentinel.differential_models import DifferentialReport
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.score_models import CaseAssessment, FragilityClass, FragilityFinding
from dvi_sentinel.serialization import digest

VARIATION_CLASSES: dict[str, FragilityClass] = {
    "timing": "timestamp_timezone",
    "ordering": "ordering",
    "metadata": "optional_field_dependency",
    "dropout": "optional_field_dependency",
    "noise": "noise_sensitivity",
    "volume": "volume_sensitivity",
}
PROBE_CLASSES: dict[str, FragilityClass] = {
    "timestamp_precision": "timestamp_timezone",
    "timezone": "timestamp_timezone",
    "ordering": "ordering",
    "optional_field": "optional_field_dependency",
    "schema_alias": "schema",
    "severity_normalization": "severity_normalization",
    "sensor_vendor": "optional_field_dependency",
    "correlation": "correlation_key_dependency",
    "labels_tags": "optional_field_dependency",
    "duplicates": "volume_sensitivity",
    "benign_noise": "noise_sensitivity",
    "bounded_volume": "volume_sensitivity",
}
SCHEMA_CLASSES: dict[str, FragilityClass] = {
    "adapter_disagreement": "adapter_disagreement",
    "schema_fragility": "schema",
    "field_mapping_loss": "schema",
    "timestamp_precision_drift": "timestamp_timezone",
    "severity_normalization_drift": "severity_normalization",
    "optional_field_loss": "optional_field_dependency",
    "correlation_key_loss": "correlation_key_dependency",
}


def classify_findings(
    rows: tuple[CaseAssessment, ...],
    baseline_detected: bool,
    probes: tuple[AssumptionProbe, ...],
    differential: DifferentialReport | None,
) -> tuple[FragilityFinding, ...]:
    findings: dict[str, FragilityFinding] = {}

    def add(finding: FragilityFinding) -> None:
        findings[finding.id] = finding

    if baseline_detected:
        for row in rows:
            if (
                row.family in VARIATION_CLASSES
                and row.preservation.valid
                and row.parser_success is True
                and row.match
                and row.match.status == "missed"
            ):
                kind = VARIATION_CLASSES[row.family]
                add(
                    FragilityFinding(
                        id="finding:"
                        + digest({"class": kind, "source": "variation", "id": row.case_id})[:24],
                        finding_class=kind,
                        source="variation",
                        case_id=row.case_id,
                        evidence_paths=(
                            f"variations/{row.case_id}/preservation",
                            f"matches/{row.case_id}",
                        ),
                        rationale="Family-associated miss; causal attribution is not established",
                    )
                )
    for probe in probes:
        if probe.observed_result == "fragile" and probe.preservation and probe.preservation.valid:
            kind = PROBE_CLASSES[probe.spec.finding_class]
            add(
                FragilityFinding(
                    id="finding:" + digest({"class": kind, "source": "probe", "id": probe.id})[:24],
                    finding_class=kind,
                    source="probe",
                    case_id=probe.id,
                    evidence_paths=(f"assumption_probes/{probe.id}",),
                    rationale=probe.confidence_rationale,
                )
            )
    if differential:
        for case in differential.cases:
            if case.status != "disagree":
                continue
            for kind in sorted({SCHEMA_CLASSES[d.finding_class] for d in case.differences}):
                add(
                    FragilityFinding(
                        id="finding:"
                        + digest({"class": kind, "source": "differential", "id": case.id})[:24],
                        finding_class=kind,
                        source="differential",
                        case_id=case.id,
                        evidence_paths=(f"differential_schema_report/{case.id}/differences",),
                        rationale="Measured disagreement against the declared canonical reference",
                    )
                )
    return tuple(
        sorted(
            findings.values(),
            key=lambda finding: (finding.finding_class, finding.source, finding.case_id),
        )
    )
