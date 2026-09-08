"""Bounded deterministic JSONL/CSV/EVE ingestion with per-record diagnostics."""

import csv
import hashlib
import io
from pathlib import Path

from pydantic import JsonValue, ValidationError

from dvi_sentinel.adapter_mapping import normalize_record
from dvi_sentinel.local_fixtures import MAX_FIXTURE_BYTES, read_fixture
from dvi_sentinel.models import TelemetryEvent, ValueModel
from dvi_sentinel.policy import PolicyError, evaluate_events, inspect_content
from dvi_sentinel.scenario import FixtureInput
from dvi_sentinel.serialization import parse_json


class AdapterIssue(ValueModel):
    code: str
    record_index: int | None
    path: str
    explanation: str


class NormalizationResult(ValueModel):
    adapter: str
    input_digest: str
    events: tuple[TelemetryEvent, ...]
    errors: tuple[AdapterIssue, ...]

    @property
    def parser_success(self) -> bool:
        return bool(self.events) and not self.errors


def normalize(content: bytes, adapter: str) -> NormalizationResult:
    """Parse bytes without filesystem or network access; never silently drop invalid records."""
    events: list[TelemetryEvent] = []
    errors: list[AdapterIssue] = []
    seen_ids: set[str] = set()

    def error(code: str, index: int | None, explanation: str, path: str = "$") -> None:
        errors.append(
            AdapterIssue(code=code, record_index=index, path=path, explanation=explanation)
        )

    def consume(record: JsonValue, index: int) -> None:
        try:
            if not isinstance(record, dict):
                raise ValueError("DVI-ADAPTER-FIELD: each record must be an object")
            decisions = inspect_content(record)
            if decisions:
                raise PolicyError(decisions)
            event = normalize_record(record, adapter, index)
            decisions = evaluate_events((event,))
            if decisions:
                raise PolicyError(decisions)
            if event.event_id in seen_ids:
                raise ValueError("DVI-ADAPTER-DUPLICATE-ID: event ID appears more than once")
            seen_ids.add(event.event_id)
            events.append(event)
        except PolicyError as exc:
            for decision in exc.decisions:
                error(
                    "DVI-ADAPTER-POLICY",
                    index,
                    f"{decision.rule_id}: {decision.explanation}",
                    decision.path,
                )
        except ValidationError as exc:
            for item in exc.errors(include_input=False):
                error("DVI-ADAPTER-FIELD", index, item["msg"], ".".join(map(str, item["loc"])))
        except (ValueError, TypeError, RecursionError) as exc:
            message = str(exc)
            code = (
                message.split(":", 1)[0]
                if message.startswith("DVI-ADAPTER-")
                else "DVI-ADAPTER-FIELD"
            )
            error(code, index, message)

    try:
        if len(content) > MAX_FIXTURE_BYTES:
            raise ValueError("DVI-ADAPTER-SIZE: fixture exceeds 2 MiB")
        text = content.decode("utf-8-sig")
        if adapter in {"jsonl", "suricata_eve"}:
            for index, line in enumerate(text.splitlines(), 1):
                if index > 10_000:
                    raise ValueError("DVI-ADAPTER-SIZE: record limit exceeded")
                if not line.strip():
                    continue
                try:
                    record = parse_json(line)
                except (ValueError, RecursionError) as exc:
                    error("DVI-ADAPTER-JSON", index, str(exc))
                    continue
                consume(record, index)
        elif adapter == "csv":
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            header = next(reader, [])
            if not header or any(not name for name in header) or len(set(header)) != len(header):
                raise ValueError("DVI-ADAPTER-CSV: unique nonempty headers required")
            for index, cells in enumerate(reader, 2):
                if index > 10_001:
                    raise ValueError("DVI-ADAPTER-SIZE: record limit exceeded")
                if not cells:
                    continue
                if len(cells) != len(header):
                    error("DVI-ADAPTER-CSV", index, "row width differs from header")
                    continue
                consume(dict(zip(header, cells, strict=True)), index)
        else:
            raise ValueError("DVI-ADAPTER-UNSUPPORTED: adapter must be jsonl, csv, or suricata_eve")
    except (ValueError, UnicodeError, csv.Error) as exc:
        message = str(exc)
        code = (
            message.split(":", 1)[0] if message.startswith("DVI-ADAPTER-") else "DVI-ADAPTER-PARSE"
        )
        error(code, None, message)
    if not events and not errors:
        error("DVI-ADAPTER-EMPTY", None, "fixture contains no events")
    return NormalizationResult(
        adapter=adapter,
        input_digest=hashlib.sha256(content).hexdigest(),
        events=tuple(events),
        errors=tuple(errors),
    )


def load_input(root: Path, fixture: FixtureInput) -> NormalizationResult:
    return normalize(read_fixture(root, fixture.path), fixture.format)
