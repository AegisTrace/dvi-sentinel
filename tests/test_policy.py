from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from dvi_sentinel.local_fixtures import local_file, read_fixture
from dvi_sentinel.models import RawSource, TelemetryEvent
from dvi_sentinel.policy import (
    PolicyError,
    documentation_identifier,
    evaluate_events,
    inspect_content,
)
from dvi_sentinel.scenario_io import load_scenario, parse_scenario
from dvi_sentinel.serialization import canonical_json

EXAMPLE = Path(__file__).parents[1] / "examples" / "foundation_scenario.yaml"


def scenario_data() -> dict:
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))


def rejected(data: dict, rule: str) -> None:
    with pytest.raises(PolicyError) as error:
        parse_scenario(yaml.safe_dump(data))
    assert rule in {decision.rule_id for decision in error.value.decisions}
    assert all(decision.path and decision.explanation for decision in error.value.decisions)


def test_example_roundtrip_and_allow_decision() -> None:
    scenario, decisions = load_scenario(EXAMPLE)
    assert scenario.metadata.id == "example-flow"
    assert [(d.rule_id, d.decision) for d in decisions] == [("DVI-POL-000", "allow")]
    assert parse_scenario(canonical_json(scenario)) == scenario


@pytest.mark.parametrize(
    "key,rule",
    [
        ("command", "004"),
        ("S H E L L", "004"),
        ("ｅｘｅｃ", "004"),
        ("payload", "005"),
        ("exploit", "005"),
        ("malware", "005"),
        ("password", "006"),
        ("credentials", "006"),
        ("stealth", "007"),
        ("persistence", "007"),
        ("privilege_escalation", "007"),
        ("scan", "008"),
        ("target", "008"),
        ("destructive", "008"),
    ],
)
def test_prohibited_structural_fields(key: str, rule: str) -> None:
    rejected(scenario_data() | {key: "inert test marker"}, f"DVI-POL-{rule}")


def test_unknown_field_and_invalid_bounds_rejected() -> None:
    rejected(scenario_data() | {"plugin": "unknown"}, "DVI-POL-001")
    data = scenario_data()
    data["variations"]["max_variants"] = 1001
    rejected(data, "DVI-POL-001")
    data["variations"]["max_variants"] = True
    rejected(data, "DVI-POL-001")


@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_explicit_safety_declaration(value: object) -> None:
    data = scenario_data()
    data["safety"]["local_only"] = value
    rejected(data, "DVI-POL-003")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        "a: 1\na: 2",
        "x: &a [1]\ny: *a",
        "x: !!python/object:os.system {}",
        "? [a,b]\n: 1",
        "x: [",
        "x: " + "[" * 30 + "0" + "]" * 30,
    ],
)
def test_ambiguous_or_malformed_yaml(text: str) -> None:
    with pytest.raises(PolicyError):
        parse_scenario(text)


@pytest.mark.parametrize(
    "relative",
    [
        "../escape.jsonl",
        "/tmp/escape",
        "C:/file",
        "a\\b",
        "//host/share",
        "a/../b",
        "a/%2e%2e/b",
        "nul",
        "CON.txt",
        "a.",
        "a/./b",
        "a//b",
        "file:stream",
        "",
    ],
)
def test_unsafe_paths_fail_before_read(tmp_path: Path, relative: str) -> None:
    with pytest.raises(PolicyError, match="DVI-POL-002"):
        local_file(tmp_path, relative)


def test_missing_large_invalid_utf8_and_valid_local_files(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="DVI-POL-009"):
        read_fixture(tmp_path, "missing.jsonl")
    path = tmp_path / "data.jsonl"
    path.write_bytes(b"12345")
    assert read_fixture(tmp_path, path.name) == b"12345"
    with pytest.raises(PolicyError, match="DVI-POL-010"):
        read_fixture(tmp_path, path.name, limit=4)
    path.write_bytes(b"\xff")
    with pytest.raises(PolicyError, match="UTF-8"):
        load_scenario(path)


def test_symlink_fixture_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.jsonl"
    try:
        link.symlink_to(target)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows requires symlink privilege; real symlink case runs in Linux CI")
        raise
    with pytest.raises(PolicyError, match="DVI-POL-002"):
        local_file(tmp_path, link.name)


def test_unc_root_rejected_without_access() -> None:
    with pytest.raises(PolicyError, match="DVI-POL-002"):
        local_file(Path("//fixture-host/share"), "data.jsonl")


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "8.8.8.8",
        "::1",
        "::ffff:192.0.2.1",
        "real-service.com",
        "2130706433",
        "example.com.evil.com",
        "localhost",
    ],
)
def test_non_documentation_identifiers(value: str) -> None:
    assert not documentation_identifier(value)
    assert inspect_content({"address": value})[0].rule_id == "DVI-POL-011"


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.1",
        "198.51.100.255",
        "203.0.113.1",
        "2001:db8::1",
        "example.com",
        "Sensor.EXAMPLE.",
        "dns.test",
        "no.invalid",
        "sub.example.org",
    ],
)
def test_documentation_identifiers(value: str) -> None:
    assert documentation_identifier(value)
    assert not inspect_content({"hostname": value})


@pytest.mark.parametrize(
    "value",
    [
        "https://real-service.com/path",
        "http://user:secret@example.com/",
        "file:///etc/passwd",
        "https%3A%2F%2Freal-service.com",
        "http://[broken",
        "ftp://example.com/",
    ],
)
def test_unsafe_urls(value: str) -> None:
    assert inspect_content({"description": value})[0].rule_id == "DVI-POL-011"


def test_inert_descriptions_and_documentation_urls_are_allowed() -> None:
    assert not inspect_content({"description": "A fixture about malware detection, not execution."})
    assert not inspect_content({"url": "https://example.com/synthetic"})
    assert not inspect_content({"http": {"url": "/status"}})
    assert inspect_content({"http": {"url": "//real-service.com"}})[0].rule_id == "DVI-POL-011"


def test_ordering_and_dropout_require_valid_declarations() -> None:
    data = scenario_data()
    data["variations"] = {"families": ["ordering"]}
    rejected(data, "DVI-POL-012")
    data["variations"]["order_independent"] = True
    assert parse_scenario(yaml.safe_dump(data)).variations.order_independent
    data["expected"]["labels"] = ["required"]
    data["variations"]["optional_fields"] = ["labels"]
    rejected(data, "DVI-POL-012")
    data["variations"]["optional_fields"] = ["sensor", "sensor"]
    rejected(data, "DVI-POL-001")


def test_baseline_only_scenario_warns(tmp_path: Path) -> None:
    data = scenario_data()
    data["variations"] = {}
    (tmp_path / "canonical_event.json").write_text("{}", encoding="utf-8")
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    _, decisions = load_scenario(path)
    assert decisions[-1].decision == "warn"
    assert decisions[-1].rule_id == "DVI-POL-013"


def test_events_check_normalized_and_raw_data() -> None:
    event = TelemetryEvent.model_validate_json(
        EXAMPLE.with_name("canonical_event.json").read_text()
    )
    assert not evaluate_events((event,))
    data = event.model_dump()
    data["semantics"]["source"]["address"] = "8.8.8.8"
    changed = TelemetryEvent.model_validate(data)
    assert evaluate_events((changed,))[0].rule_id == "DVI-POL-011"
    data = event.model_dump()
    data["raw"] = RawSource.from_payload({"command": "inert"}, adapter="jsonl")
    assert evaluate_events((TelemetryEvent.model_validate(data),))[0].rule_id == "DVI-POL-004"


@given(st.integers(min_value=0, max_value=255))
def test_documentation_network_boundary(octet: int) -> None:
    assert documentation_identifier(f"192.0.2.{octet}")
    assert not documentation_identifier(f"192.0.3.{octet}")
