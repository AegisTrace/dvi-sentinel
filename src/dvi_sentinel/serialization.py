"""Version-local deterministic JSON and SHA-256; no hidden I/O."""

import hashlib
import json

from pydantic import BaseModel, JsonValue


def canonical_json(value: JsonValue | BaseModel) -> str:
    """Sort object keys, retain array order, and reject non-finite numbers."""
    data = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def digest(value: JsonValue | BaseModel) -> str:
    """Hash the UTF-8 bytes of DVI canonical JSON (not RFC 8785)."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
