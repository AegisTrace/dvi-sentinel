"""Bounded YAML parsing and scenario safety validation."""

from pathlib import Path

import yaml
from pydantic import ValidationError
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken

from dvi_sentinel.local_fixtures import MAX_SCENARIO_BYTES, read_fixture
from dvi_sentinel.policy import PolicyDecision, PolicyError, inspect_content, reject
from dvi_sentinel.scenario import Scenario


def _check_yaml_node(node: Node, depth: int = 0) -> None:
    if depth > 24:
        raise reject("DVI-POL-010", "$", "YAML nesting exceeds 24 levels")
    if isinstance(node, MappingNode):
        keys: set[str] = set()
        for key, value in node.value:
            if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                raise reject("DVI-POL-001", "$", "YAML object keys must be strings")
            if key.value in keys:
                raise reject("DVI-POL-001", key.value, "duplicate YAML key")
            keys.add(key.value)
            _check_yaml_node(value, depth + 1)
    elif isinstance(node, SequenceNode):
        for item in node.value:
            _check_yaml_node(item, depth + 1)


def parse_local_yaml(text: str, *, kind: str = "document") -> object:
    """Shared inert YAML syntax/content boundary; callers validate their own typed schema."""
    if len(text.encode("utf-8")) > MAX_SCENARIO_BYTES:
        raise reject("DVI-POL-010", "$", f"{kind} exceeds size limit")
    try:
        for token in yaml.scan(text):
            if isinstance(token, AliasToken | AnchorToken):
                raise reject("DVI-POL-001", "$", "YAML anchors and aliases are unsupported")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        if node is None:
            raise reject("DVI-POL-001", "$", f"empty {kind}")
        _check_yaml_node(node)
        data = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise reject("DVI-POL-001", "$", "invalid or unsupported YAML syntax") from exc
    decisions = inspect_content(data)
    if decisions:
        raise PolicyError(decisions)
    return data


def parse_scenario(text: str) -> Scenario:
    data = parse_local_yaml(text, kind="scenario")
    try:
        scenario = Scenario.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(
            tuple(
                PolicyDecision(
                    rule_id="DVI-POL-003"
                    if error["loc"] and error["loc"][0] == "safety"
                    else "DVI-POL-001",
                    decision="reject",
                    path=".".join(str(p) for p in error["loc"]) or "$",
                    explanation=error["msg"],
                )
                for error in exc.errors(include_input=False)
            )
        ) from exc
    if "ordering" in scenario.variations.families and not scenario.variations.order_independent:
        raise reject(
            "DVI-POL-012", "variations.order_independent", "ordering requires explicit permission"
        )
    protected: set[str] = set(scenario.expected.required_fields)
    protected.update(
        name for name in ("labels", "tags", "correlation_id") if getattr(scenario.expected, name)
    )
    if protected.intersection(scenario.variations.optional_fields):
        raise reject(
            "DVI-POL-012", "variations.optional_fields", "cannot drop required detection evidence"
        )
    return scenario


def load_scenario(path: Path) -> tuple[Scenario, tuple[PolicyDecision, ...]]:
    text = read_fixture(path.parent, path.name, limit=MAX_SCENARIO_BYTES)
    try:
        scenario = parse_scenario(text.decode("utf-8"))
    except UnicodeError as exc:
        raise reject("DVI-POL-001", str(path), "scenario must be UTF-8") from exc
    for fixture in scenario.inputs:
        read_fixture(path.parent, fixture.path)
    if scenario.harness.kind == "fixture":
        read_fixture(path.parent, scenario.harness.path)
    decisions = [
        PolicyDecision(
            rule_id="DVI-POL-000",
            decision="allow",
            path="safety",
            explanation="strict local synthetic scenario contract accepted",
        )
    ]
    if not scenario.variations.families:
        decisions.append(
            PolicyDecision(
                rule_id="DVI-POL-013",
                decision="warn",
                path="variations",
                explanation="no variation families requested",
            )
        )
    return scenario, tuple(decisions)
