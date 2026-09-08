from pathlib import Path

import pytest

from dvi_sentinel.adapters import normalize
from dvi_sentinel.harness import FixtureHarness, RuleLogicHarness
from dvi_sentinel.harness_models import (
    FixtureCase,
    FixtureResults,
    HarnessRequest,
    RuleHarnessConfig,
)
from dvi_sentinel.models import DetectionEvent, RawSource, TelemetryEvent
from dvi_sentinel.policy import PolicyError
from dvi_sentinel.probe_models import AssumptionProbe
from dvi_sentinel.probe_sources import semantic_projection, source_variant
from dvi_sentinel.probes import probes_jsonl, probes_markdown, run_probes
from dvi_sentinel.scenario import VariationPolicy
from dvi_sentinel.serialization import canonical_json, parse_json

ROOT = Path(__file__).parents[1] / "examples"


def events():
    return normalize((ROOT / "probes/events.jsonl").read_bytes(), "jsonl").events


def config():
    return RuleHarnessConfig.model_validate(parse_json((ROOT / "probes/rules.json").read_bytes()))


def policy():
    return VariationPolicy(
        families=("timing", "ordering", "metadata", "dropout", "noise", "volume"),
        order_independent=True,
        max_duplicates=3,
        max_noise_events=1,
        optional_fields=("sensor", "vendor", "confidence", "correlation_id", "labels", "tags"),
    )


@pytest.mark.parametrize(
    ("name", "signature"),
    [
        ("timestamp_precision", "precision"),
        ("timezone", "timezone"),
        ("ordering", "ordering"),
        ("drop:sensor", "optional"),
        ("schema_alias", "alias"),
        ("severity_normalization", "severity"),
        ("name:sensor", "naming"),
        ("drop:correlation_id", "correlation"),
        ("drop:labels", "labels"),
        ("drop:tags", "tags"),
        ("duplicates", "duplicates"),
        ("benign_noise", "noise"),
        ("bounded_volume", "volume"),
    ],
)
def test_known_fragility_with_preserved_intent(name, signature):
    rules = RuleHarnessConfig(
        kind="rule_logic", rules=tuple(r for r in config().rules if r.id == signature)
    )
    results = {p.spec.name: p for p in run_probes(events(), policy(), RuleLogicHarness(rules))}
    result = results[name]
    assert result.observed_result == "fragile"
    assert result.missing_identities == (("lab", signature),)
    assert result.preservation.valid
    assert result.candidate.status == "complete"
    for event in result.events:
        if event.event_id in {e.event_id for e in events()}:
            assert event.semantics == events()[0].semantics
    if signature == "volume":
        assert results["duplicates"].observed_result == "robust"


def test_robust_negative_control_and_determinism():
    rules = RuleHarnessConfig(
        kind="rule_logic", rules=tuple(r for r in config().rules if r.id == "robust")
    )
    harness = RuleLogicHarness(rules)
    before = canonical_json([e.model_dump(mode="json") for e in events()])
    first = run_probes(events(), policy(), harness)
    assert {p.observed_result for p in first} == {"robust", "not_applicable"}
    assert len({p.id for p in first}) == len(first) == 16
    assert [p.spec.name for p in first] == sorted(p.spec.name for p in first)
    assert probes_jsonl(first) == probes_jsonl(run_probes(events(), policy(), harness))
    assert (
        tuple(
            AssumptionProbe.model_validate_json(line) for line in probes_jsonl(first).splitlines()
        )
        == first
    )
    assert canonical_json([e.model_dump(mode="json") for e in events()]) == before
    assert "unknown is not a measured miss" in probes_markdown(first)


def test_missing_candidate_and_empty_or_ambiguous_baseline_are_unknown():
    detection = (
        RuleLogicHarness(config())
        .evaluate(HarnessRequest(case_id="baseline", events=events()))
        .detections[0]
    )
    for detections in (
        (),
        (detection,),
        (
            detection,
            DetectionEvent.model_validate(
                detection.model_dump() | {"event_id": "duplicate:identity"}
            ),
        ),
    ):
        harness = FixtureHarness(
            FixtureResults(cases=(FixtureCase(case_id="baseline", detections=detections),))
        )
        results = run_probes(events(), policy(), harness)
        assert "fragile" not in {p.observed_result for p in results}
        assert next(p for p in results if p.spec.name == "ordering").observed_result == "unknown"


def test_permissions_budget_and_collision_are_explicit():
    harness = RuleLogicHarness(config())
    assert all(
        p.observed_result == "not_applicable"
        for p in run_probes(events(), VariationPolicy(), harness)
    )
    bounded = run_probes(events(), policy(), harness, event_budget=2)
    assert all(p.observed_result in {"unknown", "not_applicable"} for p in bounded)
    assert sum(len(p.events) for p in bounded) == 0
    collision = (
        TelemetryEvent.model_validate(events()[0].model_dump() | {"event_id": "probe:duplicate:0"}),
        events()[1],
    )
    result = next(
        p for p in run_probes(collision, policy(), harness) if p.spec.name == "duplicates"
    )
    assert result.observed_result == "invalid" and result.candidate is None
    assert any(not c.passed and c.id == "DVI-INV-IDENTITY" for c in result.preservation.checks)


def test_unsafe_baseline_is_rejected_before_harness():
    unsafe = (
        TelemetryEvent.model_validate(
            events()[0].model_dump()
            | {"raw": RawSource.from_payload({"command": "inert"}, adapter="jsonl")}
        ),
    )
    with pytest.raises(PolicyError):
        run_probes(unsafe, policy(), RuleLogicHarness(config()))


@pytest.mark.parametrize("adapter", ["jsonl", "csv", "suricata_eve"])
@pytest.mark.parametrize(
    "mode", ["timestamp_precision", "timezone", "schema_alias", "severity_normalization"]
)
def test_source_representations_reparse_independently(adapter, mode):
    filename = {
        "jsonl": "generic.jsonl",
        "csv": "generic.csv",
        "suricata_eve": "suricata_eve.jsonl",
    }[adapter]
    baseline = normalize((ROOT / "telemetry" / filename).read_bytes(), adapter).events
    for event in baseline:
        changed = source_variant(event, mode)
        assert semantic_projection(changed) == semantic_projection(event)
        assert changed.event_id == event.event_id
        if changed.raw.payload != event.raw.payload:
            assert changed.raw.raw_digest != event.raw.raw_digest


def test_precision_does_not_round_or_alter_timezone():
    first = events()[0]
    changed = source_variant(first, "timestamp_precision")
    assert changed.raw.original_timestamp == "2026-01-01T00:00:00Z"
    assert changed.timestamp == first.timestamp
    precise = normalize((ROOT / "telemetry/generic.jsonl").read_bytes(), "jsonl").events[0]
    assert source_variant(precise, "timestamp_precision") == precise


def test_all_findings_have_resolvable_embedded_evidence():
    results = run_probes(events(), policy(), RuleLogicHarness(config()))
    candidates = [
        canonical_json([e.model_dump(mode="json") for e in p.events])
        for p in results
        if p.candidate
    ]
    assert len(candidates) == len(set(candidates))
    for probe in results:
        data = probe.model_dump(mode="json")
        for path in probe.evidence_paths:
            assert path.startswith("#/") and data[path[2:]] is not None
        assert ("lab", "robust") not in probe.missing_identities


def test_representation_drift_is_invalid_and_not_evaluated():
    # A normalized event with richer metadata than its raw flat representation
    # cannot be reconstructed faithfully; the independent projection detects it.
    original = tuple(
        TelemetryEvent.model_validate(e.model_dump() | {"confidence": 0.5}) for e in events()
    )
    results = run_probes(original, policy(), RuleLogicHarness(config()))
    result = next(p for p in results if p.spec.name == "schema_alias")
    assert result.observed_result == "invalid" and result.candidate is None
    assert not result.preservation.checks[0].passed
