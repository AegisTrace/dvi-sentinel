"""Finite timestamp and severity conversions; no implicit source-format guessing."""

import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from pydantic import JsonValue

from dvi_sentinel.mapping_models import Codec
from dvi_sentinel.models import utc_timestamp

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
LEVELS = ("unknown", "informational", "low", "medium", "high", "critical")


def convert(value: JsonValue, codec: Codec, *, inverse: bool = False) -> tuple[JsonValue, bool]:
    """Return converted value and whether the conversion loses representable information."""
    if codec == "identity":
        return value, False
    if codec in {"eve_severity", "sigma_level"}:
        if inverse:
            if codec == "sigma_level" and isinstance(value, str) and value in LEVELS[1:]:
                return LEVELS.index(value), False
            if codec == "eve_severity" and type(value) is int and value in (1, 2, 3):
                return {1: 4, 2: 3, 3: 2}[value], False
        elif type(value) is int and 0 <= value <= 5:
            if codec == "sigma_level" and value != 0:
                return LEVELS[value], False
            if codec == "eve_severity" and value >= 2:
                return {2: 3, 3: 2, 4: 1, 5: 1}[value], value == 5
        raise ValueError("severity has no declared representation in this profile")
    if not inverse or codec == "rfc3339":
        timestamp = utc_timestamp(value)
        if codec == "rfc3339":
            return timestamp.isoformat(timespec="microseconds"), False
        delta = timestamp - EPOCH
        micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        if codec == "epoch_ms":
            return micros // 1000, micros % 1000 != 0
        if codec == "epoch_ns":
            if not 0 <= micros * 1000 <= 2**64 - 1:
                raise ValueError("nanosecond timestamp exceeds uint64")
            return micros * 1000, False
        return str(Decimal(micros) / Decimal(1_000_000)), False
    if codec == "epoch_seconds":
        if isinstance(value, bool) or not isinstance(value, str | int | float):
            raise ValueError("epoch seconds require a bounded decimal scalar")
        text = str(value)
        if len(text) > 40 or not re.fullmatch(r"-?\d{1,12}(?:\.\d{1,9})?", text):
            raise ValueError("epoch seconds require plain decimal notation")
        micro_value = Decimal(text) * Decimal(1_000_000)
        micros = int(micro_value)
        loss = micro_value != micros
    else:
        if type(value) is not int:
            raise ValueError("epoch milliseconds/nanoseconds require an integer")
        if codec == "epoch_ns" and not 0 <= value <= 2**64 - 1:
            raise ValueError("nanosecond timestamp exceeds uint64")
        micros = value * 1000 if codec == "epoch_ms" else value // 1000
        loss = codec == "epoch_ns" and value % 1000 != 0
    try:
        result = EPOCH + timedelta(microseconds=micros)
    except OverflowError as exc:
        raise ValueError("timestamp exceeds the canonical calendar range") from exc
    return result.isoformat(
        timespec="milliseconds" if codec == "epoch_ms" else "microseconds"
    ), loss
