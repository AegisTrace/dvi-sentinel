"""Structural safety decisions and bounded local scenario/fixture reads."""

import re
import unicodedata
from ipaddress import ip_address, ip_network
from typing import Literal
from urllib.parse import unquote, urlsplit

from dvi_sentinel.models import TelemetryEvent, ValueModel

DOCUMENTATION_NETWORKS = tuple(
    ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


class PolicyDecision(ValueModel):
    rule_id: str
    decision: Literal["allow", "reject", "warn"]
    path: str
    explanation: str


class PolicyError(ValueError):
    """A rejected operation with stable, machine-readable policy evidence."""

    def __init__(self, decisions: tuple[PolicyDecision, ...]) -> None:
        self.decisions = decisions
        super().__init__("; ".join(f"{d.rule_id} {d.path}: {d.explanation}" for d in decisions))


def reject(rule: str, path: str, explanation: str) -> PolicyError:
    return PolicyError(
        (PolicyDecision(rule_id=rule, decision="reject", path=path, explanation=explanation),)
    )


def documentation_identifier(value: str) -> bool:
    """Validate an address/hostname without DNS, sockets, or URL requests."""
    text = value.rstrip(".").lower()
    try:
        address = ip_address(text)
    except ValueError:
        return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", text)) and (
            text in {"example.com", "example.net", "example.org"}
            or text.endswith(
                (".example", ".test", ".invalid", ".example.com", ".example.net", ".example.org")
            )
        )
    return any(
        address.version == network.version and address in network
        for network in DOCUMENTATION_NETWORKS
    )


def _normalized_key(value: str) -> str:
    return re.sub(r"[\W_]", "", unicodedata.normalize("NFKC", value).casefold())


def inspect_content(value: object, path: str = "$") -> tuple[PolicyDecision, ...]:
    """Inspect inert structured content; this is supplementary to the allowlisted DSL."""
    decisions: list[PolicyDecision] = []
    forbidden = {
        "command": "004",
        "commands": "004",
        "shell": "004",
        "subprocess": "004",
        "exec": "004",
        "execute": "004",
        "script": "004",
        "payload": "005",
        "exploit": "005",
        "malware": "005",
        "credential": "006",
        "credentials": "006",
        "password": "006",
        "token": "006",
        "stealth": "007",
        "persistence": "007",
        "privilegeescalation": "007",
        "scan": "008",
        "reconnaissance": "008",
        "target": "008",
        "live": "008",
        "destructive": "008",
        "delete": "008",
    }
    network_keys = {
        "address",
        "ip",
        "srcip",
        "destip",
        "dstip",
        "hostname",
        "domain",
        "dnsname",
        "rrname",
        "url",
        "uri",
        "host",
    }

    def inspect(item: object, location: str, key: str = "", depth: int = 0) -> None:
        if depth > 24:
            raise reject("DVI-POL-010", location, "content nesting exceeds 24 levels")
        if isinstance(item, dict):
            for name in sorted(item, key=str):
                if not isinstance(name, str):
                    raise reject("DVI-POL-001", location, "object keys must be strings")
                normalized = _normalized_key(name)
                child = f"{location}.{name}"
                if normalized in forbidden:
                    decisions.append(
                        PolicyDecision(
                            rule_id=f"DVI-POL-{forbidden[normalized]}",
                            decision="reject",
                            path=child,
                            explanation="prohibited capability or content field",
                        )
                    )
                inspect(item[name], child, normalized, depth + 1)
        elif isinstance(item, list | tuple):
            for index, child_value in enumerate(item):
                inspect(child_value, f"{location}[{index}]", key, depth + 1)
        elif isinstance(item, str):
            normalized_text = unicodedata.normalize("NFKC", unquote(item)).strip()
            urls = re.findall(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+", normalized_text)
            for url in urls:
                try:
                    parsed = urlsplit(url)
                    safe = (
                        parsed.scheme in {"http", "https"}
                        and parsed.username is None
                        and parsed.hostname is not None
                        and documentation_identifier(parsed.hostname)
                    )
                except ValueError:
                    safe = False
                if not safe:
                    decisions.append(
                        PolicyDecision(
                            rule_id="DVI-POL-011",
                            decision="reject",
                            path=location,
                            explanation="URL must use HTTP(S) documentation identifiers",
                        )
                    )
            if key in network_keys and not urls and not documentation_identifier(normalized_text):
                decisions.append(
                    PolicyDecision(
                        rule_id="DVI-POL-011",
                        decision="reject",
                        path=location,
                        explanation="network identifier is outside documentation space",
                    )
                )

    inspect(value, path)
    return tuple(decisions)


def evaluate_events(events: tuple[TelemetryEvent, ...]) -> tuple[PolicyDecision, ...]:
    """Reusable pre/post-transformation checks over normalized and retained raw content."""
    decisions: list[PolicyDecision] = []
    for index, event in enumerate(events):
        normalized = event.model_dump(mode="json", exclude={"raw"})
        decisions.extend(inspect_content(normalized, f"events[{index}]"))
        metadata = event.raw.model_dump(mode="json", exclude={"payload_json", "raw_digest"})
        decisions.extend(inspect_content(metadata, f"events[{index}].source"))
        decisions.extend(inspect_content(event.raw.payload, f"events[{index}].raw"))
    return tuple(decisions)
