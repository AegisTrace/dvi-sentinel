"""Versioned expert benchmark declarations and retained native engine evidence (D)."""

from typing import Annotated, Literal, Self, get_args

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from dvi_sentinel.artifact_models import ArtifactEntry, ArtifactIssue, portable_path
from dvi_sentinel.benchmark_models import BenchmarkCheck, BenchmarkResult, MinimalExpectation
from dvi_sentinel.confidence_models import ConfidenceClass, ConfidenceReport
from dvi_sentinel.intent_models import IntentAnalysis
from dvi_sentinel.lineage_models import IntegrityReport, ProvenanceDAG
from dvi_sentinel.match_models import MatchResult
from dvi_sentinel.metamorphic_models import MetamorphicReport, RepresentationId
from dvi_sentinel.models import Identifier, NonEmpty, Sha256, ValueModel
from dvi_sentinel.oracle_models import ConsensusState, OracleConsensus
from dvi_sentinel.score_models import Ratio
from dvi_sentinel.serialization import canonical_json
from dvi_sentinel.shrinking_models import MinimalCounterexample
from dvi_sentinel.temporal_models import TemporalCheck
from dvi_sentinel.variation_models import VariationCase

Category = Literal[
    "schema_alias_fragility",
    "timestamp_precision_fragility",
    "timezone_fragility",
    "sequence_window_fragility",
    "correlation_key_fragility",
    "severity_mapping_fragility",
    "optional_field_dependency",
    "benign_noise_sensitivity",
    "adapter_disagreement",
    "normalization_loss",
    "rule_intent_mismatch",
    "sensor_source_drift",
    "cross_profile_semantic_loss",
    "oracle_disagreement",
    "statistical_small_sample_warning",
    "provenance_tamper_detection",
]
CATEGORIES: tuple[Category, ...] = get_args(Category)
PathName = Annotated[str, Field(min_length=1, max_length=200)]
Slug = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_-]*$")]


class LegacyOperation(ValueModel):
    kind: Literal["legacy"] = "legacy"
    case_id: Identifier


class SequenceOperation(ValueModel):
    kind: Literal["sequence"] = "sequence"
    change_fixture: PathName
    _path = field_validator("change_fixture")(portable_path)


class MappingOperation(ValueModel):
    kind: Literal["mapping"] = "mapping"
    representation: RepresentationId
    supplied_fixture: PathName | None = None

    @model_validator(mode="after")
    def path(self) -> Self:
        if self.supplied_fixture is not None:
            portable_path(self.supplied_fixture)
        return self


class IntentOperation(ValueModel):
    kind: Literal["intent"] = "intent"
    intent_fixture: PathName
    _path = field_validator("intent_fixture")(portable_path)


class OracleOperation(ValueModel):
    kind: Literal["oracle"] = "oracle"


class StatisticalOperation(ValueModel):
    kind: Literal["statistical"] = "statistical"


class ProvenanceOperation(ValueModel):
    kind: Literal["provenance"] = "provenance"
    mutation: Literal["none", "append_newline"]


Operation = Annotated[
    LegacyOperation
    | SequenceOperation
    | MappingOperation
    | IntentOperation
    | OracleOperation
    | StatisticalOperation
    | ProvenanceOperation,
    Field(discriminator="kind"),
]


class MinimumResult(ValueModel):
    status: Literal["minimized", "not_applicable", "unavailable"]
    value: MinimalExpectation | None = None
    maximum_time_shift_us: Annotated[StrictInt, Field(ge=0)] | None = None
    reason: Literal["verified_local_minimum", "no_detection_failure", "analysis_only", "unresolved"]

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if (
            (self.status == "minimized") != (self.value is not None)
            or ((self.status == "minimized") != (self.reason == "verified_local_minimum"))
            or (self.status == "unavailable") != (self.reason == "unresolved")
        ):
            raise ValueError("DVI-EXPERT-MINIMUM: inconsistent availability")
        return self


ScoreMetric = Literal[
    "detection_rate",
    "adapter_disagreement_rate",
    "agreement_rate",
    "intent_support_rate",
    "integrity_rate",
]


class ScoreRange(ValueModel):
    metric: ScoreMetric
    minimum: Annotated[float, Field(ge=0, le=1)] | None
    maximum: Annotated[float, Field(ge=0, le=1)] | None

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if (self.minimum is None) != (self.maximum is None) or (
            self.minimum is not None and self.maximum is not None and self.minimum > self.maximum
        ):
            raise ValueError("DVI-EXPERT-RANGE: bounds must both be null or ordered ratios")
        return self


class ExpertCase(ValueModel):
    benchmark_id: Slug
    category: Category
    control: StrictBool
    scenario: PathName
    fixtures: Annotated[tuple[PathName, ...], Field(min_length=1, max_length=20)]
    operation: Operation
    expected_findings: Annotated[tuple[Identifier, ...], Field(max_length=32)]
    expected_state: NonEmpty
    expected_minimal_reproducer: MinimumResult
    expected_score_range: ScoreRange
    expected_oracle_consensus: ConsensusState | Literal["not_applicable"]
    expected_confidence_class: ConfidenceClass | Literal["not_applicable"]
    proof_command: tuple[str, ...]
    _scenario = field_validator("scenario")(portable_path)

    @model_validator(mode="after")
    def declaration(self) -> Self:
        for values in (self.fixtures, self.expected_findings):
            if values != tuple(sorted(set(values))):
                raise ValueError("DVI-EXPERT-ORDER: paths and findings must be unique/sorted")
        for path in self.fixtures:
            portable_path(path)
        expected_kind = {
            "sequence_window_fragility": "sequence",
            "normalization_loss": "mapping",
            "cross_profile_semantic_loss": "mapping",
            "rule_intent_mismatch": "intent",
            "sensor_source_drift": "intent",
            "oracle_disagreement": "oracle",
            "statistical_small_sample_warning": "statistical",
            "provenance_tamper_detection": "provenance",
        }.get(self.category, "legacy")
        if self.operation.kind != expected_kind:
            raise ValueError("DVI-EXPERT-OPERATION: category requires its declared engine")
        if self.proof_command != (
            "python",
            "examples/run_v2_benchmarks.py",
            "--case",
            self.benchmark_id,
            "--out",
            f"runs/benchmarks/{self.benchmark_id}",
        ):
            raise ValueError("DVI-EXPERT-COMMAND: require the inert fixed example command")
        return self


class ExpertSuite(ValueModel):
    schema_version: Literal["2"] = "2"
    seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)] = 42
    event_budget: Annotated[StrictInt, Field(ge=1, le=1024)] = 256
    cases: Annotated[tuple[ExpertCase, ...], Field(min_length=32, max_length=32)]

    @model_validator(mode="after")
    def coverage(self) -> Self:
        if len({c.benchmark_id for c in self.cases}) != len(self.cases):
            raise ValueError("DVI-EXPERT-IDENTITY: benchmark IDs must be unique")
        if {(c.category, c.control) for c in self.cases} != {
            (category, control) for category in CATEGORIES for control in (False, True)
        }:
            raise ValueError(
                "DVI-EXPERT-COVERAGE: require one diagnostic/control pair per category"
            )
        return self


class TimingChange(ValueModel):
    event_id: Identifier
    delta_ms: Annotated[StrictInt, Field(ge=-60_000, le=60_000)]


class LegacyEvidence(ValueModel):
    kind: Literal["legacy"] = "legacy"
    result: BenchmarkResult


class SequenceEvidence(ValueModel):
    kind: Literal["sequence"] = "sequence"
    baseline: MatchResult
    candidate: VariationCase
    match: MatchResult
    window: TemporalCheck
    minimum: MinimalCounterexample | None


class MappingEvidence(ValueModel):
    kind: Literal["mapping"] = "mapping"
    report: MetamorphicReport


class IntentEvidence(ValueModel):
    kind: Literal["intent"] = "intent"
    report: IntentAnalysis


class OracleBenchmarkEvidence(ValueModel):
    kind: Literal["oracle"] = "oracle"
    report: OracleConsensus


class StatisticalEvidence(ValueModel):
    kind: Literal["statistical"] = "statistical"
    report: ConfidenceReport


class ProvenanceEvidence(ValueModel):
    kind: Literal["provenance"] = "provenance"
    dag: ProvenanceDAG
    observed: tuple[ArtifactEntry, ...]
    integrity: IntegrityReport
    bundle_issues: tuple[ArtifactIssue, ...]


NativeEvidence = Annotated[
    LegacyEvidence
    | SequenceEvidence
    | MappingEvidence
    | IntentEvidence
    | OracleBenchmarkEvidence
    | StatisticalEvidence
    | ProvenanceEvidence,
    Field(discriminator="kind"),
]


class MeasuredScore(ValueModel):
    metric: ScoreMetric
    ratio: Ratio
    unknown: Annotated[StrictInt, Field(ge=0, le=1024)] = 0
    scope: NonEmpty


class MeasuredSummary(ValueModel):
    findings: tuple[Identifier, ...]
    state: NonEmpty
    minimum: MinimumResult
    score: MeasuredScore
    oracle_consensus: ConsensusState | Literal["not_applicable"] = "not_applicable"
    oracle_scope: NonEmpty = "Not applicable: this diagnostic does not aggregate detection oracles."
    confidence_class: ConfidenceClass | Literal["not_applicable"] = "not_applicable"
    confidence_scope: NonEmpty = (
        "Not applicable: this diagnostic is not a statistical trial cohort."
    )


def acceptance_checks(case: ExpertCase, observed: MeasuredSummary) -> tuple[BenchmarkCheck, ...]:
    pairs = (
        (
            "findings",
            canonical_json(list(case.expected_findings)),
            canonical_json(list(observed.findings)),
        ),
        ("state", canonical_json(case.expected_state), canonical_json(observed.state)),
        (
            "minimum",
            canonical_json(case.expected_minimal_reproducer),
            canonical_json(observed.minimum),
        ),
        (
            "score_metric",
            canonical_json(case.expected_score_range.metric),
            canonical_json(observed.score.metric),
        ),
        (
            "oracle_consensus",
            canonical_json(case.expected_oracle_consensus),
            canonical_json(observed.oracle_consensus),
        ),
        (
            "confidence_class",
            canonical_json(case.expected_confidence_class),
            canonical_json(observed.confidence_class),
        ),
    )
    checks = [BenchmarkCheck(name=n, expected=e, observed=o, passed=e == o) for n, e, o in pairs]
    bounds, value = case.expected_score_range, observed.score.ratio.value
    passed = (
        value is None
        if bounds.minimum is None
        else (
            value is not None
            and bounds.maximum is not None
            and bounds.minimum <= value <= bounds.maximum
        )
    )
    checks.append(
        BenchmarkCheck(
            name="score_range",
            passed=passed,
            expected=canonical_json([bounds.minimum, bounds.maximum]),
            observed=canonical_json(value),
        )
    )
    return tuple(checks)


class ExpertResult(ValueModel):
    case: ExpertCase
    sources: Annotated[tuple[ArtifactEntry, ...], Field(min_length=3, max_length=24)]
    evidence: NativeEvidence
    measured: MeasuredSummary
    checks: tuple[BenchmarkCheck, ...]

    @model_validator(mode="after")
    def linked(self) -> Self:
        paths = tuple(entry.path for entry in self.sources)
        if paths != tuple(sorted(set(paths))) or not {
            "v2/suite.json",
            self.case.scenario,
            *self.case.fixtures,
        }.issubset(paths):
            raise ValueError("DVI-EXPERT-SOURCES: missing or unordered source pins")
        if self.evidence.kind != self.case.operation.kind or (
            self.checks != acceptance_checks(self.case, self.measured)
        ):
            raise ValueError("DVI-EXPERT-CHECKS: evidence/checks differ from declaration")
        return self

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)


class ExpertReport(ValueModel):
    schema_version: Literal["2"] = "2"
    tool_version: NonEmpty
    suite: ExpertSuite
    suite_sha256: Sha256
    scope: Literal["full_suite", "selected_case"]
    results: Annotated[tuple[ExpertResult, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def coverage(self) -> Self:
        cases = {c.benchmark_id: c for c in self.suite.cases}
        ids = tuple(r.case.benchmark_id for r in self.results)
        if ids != tuple(sorted(set(ids))) or any(
            cases.get(r.case.benchmark_id) != r.case for r in self.results
        ):
            raise ValueError("DVI-EXPERT-RESULTS: selected cases must match suite declarations")
        if (self.scope == "full_suite" and set(ids) != set(cases)) or (
            self.scope == "selected_case" and len(ids) != 1
        ):
            raise ValueError("DVI-EXPERT-SCOPE: result coverage differs from scope")
        if any(
            next(e for e in r.sources if e.path == "v2/suite.json").sha256 != self.suite_sha256
            for r in self.results
        ):
            raise ValueError("DVI-EXPERT-SOURCES: suite byte pin differs")
        return self

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)
