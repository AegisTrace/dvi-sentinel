"""Confined input preparation and finite expert benchmark orchestration (R/A)."""

from pathlib import Path

from dvi_sentinel import __version__
from dvi_sentinel.artifact_models import ArtifactEntry, portable_path
from dvi_sentinel.benchmark_models import BenchmarkCase, BenchmarkSuite
from dvi_sentinel.benchmarks import run_benchmark_case
from dvi_sentinel.expert_benchmark_engines import measure_native
from dvi_sentinel.expert_benchmark_models import (
    ExpertCase,
    ExpertReport,
    ExpertResult,
    ExpertSuite,
    LegacyEvidence,
    NativeEvidence,
    acceptance_checks,
)
from dvi_sentinel.expert_benchmark_summary import summarize_expert
from dvi_sentinel.lineage import byte_digest
from dvi_sentinel.local_fixtures import MAX_SCENARIO_BYTES, read_fixture
from dvi_sentinel.scenario_io import parse_scenario
from dvi_sentinel.serialization import parse_json
from dvi_sentinel.workflow import PreparedScenario, prepare_scenario

MAX_INPUT_BYTES = 16 * 1024 * 1024
LEGACY_CATEGORIES = {
    "schema_alias": "schema_alias_fragility",
    "timestamp_precision": "timestamp_precision_fragility",
    "timezone": "timezone_fragility",
    "correlation_key": "correlation_key_fragility",
    "severity_mapping": "severity_mapping_fragility",
    "optional_field": "optional_field_dependency",
    "benign_noise": "benign_noise_sensitivity",
    "adapter_disagreement": "adapter_disagreement",
}


def plain_local_path(path: Path) -> Path:
    """Reject network paths and existing links/junctions before resolution or any read/write."""
    if str(path).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (path, *path.parents)
    ):
        raise ValueError("DVI-EXPERT-PATH: require a plain local path without links or junctions")
    return path.resolve()


def _inventory(case: ExpertCase, scenario_bytes: bytes, legacy: BenchmarkCase | None) -> set[str]:
    scenario = parse_scenario(scenario_bytes.decode("utf-8"))
    policy = scenario.variations
    if policy.max_variants > 8 or policy.max_noise_events > 8 or policy.max_duplicates > 8:
        raise ValueError("DVI-EXPERT-BOUNDS: at most eight variants, noise events and duplicates")
    parent = Path(case.scenario).parent
    required = {(parent / fixture.path).as_posix() for fixture in scenario.inputs}
    if scenario.harness.kind == "fixture":
        required.add((parent / scenario.harness.path).as_posix())
    operation = case.operation
    if operation.kind == "sequence":
        required.add(operation.change_fixture)
    elif operation.kind == "intent":
        required.add(operation.intent_fixture)
    elif operation.kind == "mapping" and operation.supplied_fixture:
        required.add(operation.supplied_fixture)
    if legacy is not None and legacy.comparison_fixture:
        required.add(legacy.comparison_fixture)
    for path in required:
        portable_path(path)
    if required != set(case.fixtures):
        raise ValueError("DVI-EXPERT-INVENTORY: declared fixtures differ from actual engine inputs")
    return required


def run_expert_benchmarks(root: Path, *, case_id: str | None = None) -> ExpertReport:
    """Execute a complete paired suite or one selected case, without network or subprocess I/O."""
    root = plain_local_path(root)
    cached = {"v2/suite.json": read_fixture(root, "v2/suite.json", limit=MAX_SCENARIO_BYTES)}
    suite = ExpertSuite.model_validate(parse_json(cached["v2/suite.json"]))
    selected = tuple(
        sorted(
            (c for c in suite.cases if case_id is None or c.benchmark_id == case_id),
            key=lambda c: c.benchmark_id,
        )
    )
    if not selected:
        raise ValueError("DVI-EXPERT-SELECTION: benchmark ID does not exist")
    legacy_suite = None
    if any(c.operation.kind == "legacy" for c in selected):
        cached["suite.json"] = read_fixture(root, "suite.json", limit=MAX_SCENARIO_BYTES)
        legacy_suite = BenchmarkSuite.model_validate(parse_json(cached["suite.json"]))
        if legacy_suite.seed != suite.seed or legacy_suite.event_budget != suite.event_budget:
            raise ValueError("DVI-EXPERT-LEGACY: reused suite seed and budget must match")
    prepared_cases: list[tuple[ExpertCase, PreparedScenario, BenchmarkCase | None, set[str]]] = []
    for case in selected:
        legacy = None
        if case.operation.kind == "legacy" and legacy_suite is not None:
            legacy = next((c for c in legacy_suite.cases if c.id == case.operation.case_id), None)
            if (
                legacy is None
                or legacy.scenario != case.scenario
                or (LEGACY_CATEGORIES.get(legacy.family) != case.category)
            ):
                raise ValueError("DVI-EXPERT-LEGACY: case must identify the same scenario/category")
        if case.scenario not in cached:
            cached[case.scenario] = read_fixture(root, case.scenario, limit=MAX_SCENARIO_BYTES)
        required = _inventory(case, cached[case.scenario], legacy)
        for path in sorted(required):
            if path not in cached:
                cached[path] = read_fixture(root, path)
            if sum(map(len, cached.values())) > MAX_INPUT_BYTES:
                raise ValueError("DVI-EXPERT-BOUNDS: selected unique inputs exceed 16 MiB")
        prepared = prepare_scenario(root / case.scenario)
        if len(prepared.events) > (8 if legacy else 64):
            raise ValueError("DVI-EXPERT-BOUNDS: at most 8 legacy or 64 native events per case")
        if prepared.scenario != parse_scenario(cached[case.scenario].decode("utf-8")) or any(
            capture.content
            != cached[(Path(case.scenario).parent / capture.specification.path).as_posix()]
            for capture in prepared.fixtures
        ):
            raise ValueError("DVI-EXPERT-SOURCES: inputs changed during preparation")
        paths = {"v2/suite.json", case.scenario, *required}
        if legacy:
            paths.add("suite.json")
        prepared_cases.append((case, prepared, legacy, paths))
    results = []
    evidence: NativeEvidence
    for case, prepared, legacy, paths in prepared_cases:
        if legacy is not None and legacy_suite is not None:
            native = run_benchmark_case(root, legacy_suite, legacy)
            if any(byte_digest(cached[p]) != pin for p, pin in native.source_digests.items()):
                raise ValueError("DVI-EXPERT-SOURCES: legacy evidence differs from captured input")
            evidence = LegacyEvidence(result=native)
        else:
            evidence = measure_native(
                prepared, case.operation, cached, seed=suite.seed, event_budget=suite.event_budget
            )
        measured = summarize_expert(evidence)
        results.append(
            ExpertResult(
                case=case,
                sources=tuple(
                    ArtifactEntry(path=p, sha256=byte_digest(cached[p]), size_bytes=len(cached[p]))
                    for p in sorted(paths)
                ),
                evidence=evidence,
                measured=measured,
                checks=acceptance_checks(case, measured),
            )
        )
    if any(read_fixture(root, p) != content for p, content in cached.items()):
        raise ValueError("DVI-EXPERT-SOURCES: inputs changed during execution")
    return ExpertReport(
        tool_version=__version__,
        suite=suite,
        suite_sha256=byte_digest(cached["v2/suite.json"]),
        scope="full_suite" if case_id is None else "selected_case",
        results=tuple(results),
    )
