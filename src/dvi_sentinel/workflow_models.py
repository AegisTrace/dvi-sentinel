"""Public workflow summaries and explicit CI gate outcomes."""

from typing import Literal

from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel


class RunSummary(ValueModel):
    schema_version: Literal["1"] = "1"
    status: Literal["completed"] = "completed"
    exit_status: Literal[0] = 0
    run_id: Identifier
    output: NonEmpty
    report: NonEmpty
    manifest_digest: Sha256
    detected: int
    missed: int
    unknown: int
    invalid: int
    findings: int


class GateDecision(ValueModel):
    name: NonEmpty
    status: Literal["pass", "fail", "unknown"]
    observed: float | str | None
    threshold: float | None = None
    explanation: NonEmpty


class GateResult(ValueModel):
    schema_version: Literal["1"] = "1"
    run_id: Identifier
    status: Literal["passed", "failed", "unknown"]
    exit_status: Literal[0, 1, 2]
    decisions: tuple[GateDecision, ...]


class DoctorCheck(ValueModel):
    name: NonEmpty
    status: Literal["pass", "fail"]
    value: NonEmpty


class DoctorReport(ValueModel):
    schema_version: Literal["1"] = "1"
    status: Literal["ready", "unavailable"]
    exit_status: Literal[0, 2]
    checks: tuple[DoctorCheck, ...]
