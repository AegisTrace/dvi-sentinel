"""Explicit bounded local reload of pinned regression memory (R)."""

from pathlib import Path

from pydantic import TypeAdapter

from dvi_sentinel.local_fixtures import local_file, read_fixture
from dvi_sentinel.models import Sha256
from dvi_sentinel.regression_memory import _checked_memory
from dvi_sentinel.regression_memory_models import DriftMemory, MemoryArtifact
from dvi_sentinel.serialization import parse_json


def load_regression_memory(root: Path, relative: str, *, expected_digest: str) -> DriftMemory:
    """The external pin identifies canonical memory, not a self-reported envelope hash."""
    pinned = TypeAdapter(Sha256).validate_python(expected_digest)
    if str(root).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (root, *root.parents)
    ):
        raise ValueError("DVI-MEMORY-PATH: require a plain local root")
    path = local_file(root, relative)
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError("DVI-MEMORY-PATH: linked paths are unsupported")
    artifact = MemoryArtifact.model_validate(
        parse_json(read_fixture(root, relative, limit=8 * 1024 * 1024))
    )
    if artifact.memory is None or artifact.state == "unsafe_rejected":
        raise ValueError("DVI-MEMORY-GATE: blocked artifact cannot supply history")
    return _checked_memory(artifact.memory, pinned)
