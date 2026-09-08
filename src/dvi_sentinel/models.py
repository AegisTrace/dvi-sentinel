"""Validated DVI-native telemetry and detection value objects."""

import json
import re
from datetime import UTC, datetime
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StrictFloat,
    StrictInt,
    field_validator,
    model_validator,
)

from dvi_sentinel.serialization import canonical_json, digest

NonEmpty = Annotated[str, Field(min_length=1, max_length=1024, pattern=r"\S")]
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[\w.:/-]+$")]
Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def utc_timestamp(value: object) -> datetime:
    """Require explicit timezone and at most microsecond precision; reject epoch guesses."""
    if isinstance(value, str):
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
            value,
        ):
            raise ValueError("DVI-EVT-TIME: use RFC3339 with timezone and <=6 fractional digits")
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("DVI-EVT-TIME: invalid calendar timestamp") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("DVI-EVT-TIME: timezone-aware datetime required")
    try:
        return value.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValueError("DVI-EVT-TIME: timestamp outside UTC datetime range") from exc


Timestamp = Annotated[datetime, BeforeValidator(utc_timestamp)]


class ValueModel(BaseModel):
    """Reject unknown fields and non-finite values; all nested collections are immutable."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, validate_default=True, allow_inf_nan=False
    )

    def stable_digest(self) -> str:
        return digest(self)


class Severity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ValidationWarning(ValueModel):
    code: Identifier
    path: NonEmpty
    explanation: NonEmpty


class EntityRef(ValueModel):
    kind: Literal["host", "sensor", "service", "flow"]
    value: NonEmpty


class NetworkEndpoint(ValueModel):
    address: IPv4Address | IPv6Address
    port: Annotated[StrictInt, Field(ge=0, le=65535)] | None = None

    @field_validator("address", mode="before")
    @classmethod
    def address_is_text(cls, value: object) -> object:
        if not isinstance(value, str | IPv4Address | IPv6Address):
            raise ValueError("DVI-EVT-IP: IP address must be text or an IP value")
        if isinstance(value, str) and "%" in value:
            raise ValueError("DVI-EVT-IP: scoped addresses are unsupported")
        return value


class EventSemantics(ValueModel):
    """Defensive meaning, independently comparable to source representation."""

    category: Literal["flow", "dns", "http", "alert"]
    action: NonEmpty
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    protocol: Literal["tcp", "udp", "icmp", "other"] | None = None
    source: NetworkEndpoint | None = None
    destination: NetworkEndpoint | None = None
    dns_name: NonEmpty | None = None
    http_method: NonEmpty | None = None
    http_path: NonEmpty | None = None


class RawSource(ValueModel):
    """An immutable canonical JSON snapshot; payload access returns a fresh copy."""

    adapter: Identifier
    payload_json: str
    raw_digest: Sha256
    record_index: Annotated[StrictInt, Field(ge=1)] | None = None
    original_timestamp: str | None = None
    sensor: NonEmpty | None = None
    vendor: NonEmpty | None = None

    @model_validator(mode="after")
    def verify_payload(self) -> Self:
        try:
            payload = json.loads(self.payload_json)
            if not isinstance(payload, dict) or canonical_json(payload) != self.payload_json:
                raise ValueError("payload must be a canonical JSON object")
            if digest(payload) != self.raw_digest:
                raise ValueError("raw digest mismatch")
        except (ValueError, TypeError) as exc:
            raise ValueError(f"DVI-EVT-RAW: {exc}") from exc
        return self

    @classmethod
    def from_payload(
        cls,
        payload: dict[str, JsonValue],
        *,
        adapter: str,
        record_index: int | None = None,
        original_timestamp: str | None = None,
        sensor: str | None = None,
        vendor: str | None = None,
    ) -> Self:
        """Capture parsed JSON without keeping a mutable caller-owned reference."""
        return cls(
            adapter=adapter,
            payload_json=canonical_json(payload),
            raw_digest=digest(payload),
            record_index=record_index,
            original_timestamp=original_timestamp,
            sensor=sensor,
            vendor=vendor,
        )

    @property
    def payload(self) -> dict[str, JsonValue]:
        parsed: dict[str, JsonValue] = json.loads(self.payload_json)
        return parsed


class Evidence(ValueModel):
    path: NonEmpty
    description: NonEmpty


class TelemetryEvent(ValueModel):
    schema_version: Literal["1"] = "1"
    event_id: Identifier
    timestamp: Timestamp
    observed_at: Timestamp | None = None
    semantics: EventSemantics
    raw: RawSource
    severity: Severity = Severity.UNKNOWN
    confidence: Annotated[StrictFloat, Field(ge=0, le=1)] | None = None
    labels: tuple[NonEmpty, ...] = ()
    tags: tuple[NonEmpty, ...] = ()
    correlation_id: Identifier | None = None
    entities: tuple[EntityRef, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    warnings: tuple[ValidationWarning, ...] = ()

    @field_validator("severity", mode="before")
    @classmethod
    def severity_is_integer(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("DVI-EVT-SEVERITY: use normalized integer 0..5")
        return value

    @field_validator("labels", "tags")
    @classmethod
    def stable_sets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class DetectionEvent(TelemetryEvent):
    detector: NonEmpty
    signature: NonEmpty
    title: NonEmpty
    related_event_ids: tuple[Identifier, ...] = ()
    techniques: tuple[NonEmpty, ...] = ()

    @model_validator(mode="after")
    def alert_category(self) -> Self:
        if self.semantics.category != "alert":
            raise ValueError("DVI-EVT-DETECTION: detection semantics category must be alert")
        return self

    @field_validator("related_event_ids", "techniques")
    @classmethod
    def stable_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))
