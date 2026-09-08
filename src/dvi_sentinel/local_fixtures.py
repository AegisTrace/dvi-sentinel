"""Bounded local file reads with portable path restrictions."""

from pathlib import Path, PurePosixPath

from dvi_sentinel.policy import reject

MAX_SCENARIO_BYTES = 131_072
MAX_FIXTURE_BYTES = 2_097_152


def local_file(root: Path, relative: str) -> Path:
    """Reject absolute, encoded, device, traversal, and symlink paths before reads."""
    if str(root).startswith(("\\\\", "//")):
        raise reject("DVI-POL-002", "root", "network filesystem roots are unsupported")
    parts = PurePosixPath(relative).parts
    reserved = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
    if (
        not parts
        or relative.startswith("/")
        or any(c in relative for c in "\\:%\x00")
        or any(
            p in (".", "..") or p.rstrip(" .") != p or p.split(".")[0].lower() in reserved
            for p in relative.split("/")
        )
        or "//" in relative
    ):
        raise reject("DVI-POL-002", relative, "use a plain relative local file path")
    base = root.resolve()
    candidate = base
    for part in parts:
        candidate /= part
        if candidate.is_symlink():
            raise reject("DVI-POL-002", relative, "symlink fixture paths are unsupported")
    if not candidate.resolve().is_relative_to(base):
        raise reject("DVI-POL-002", relative, "fixture escapes the scenario directory")
    if not candidate.is_file():
        raise reject("DVI-POL-009", relative, "local regular fixture file does not exist")
    return candidate


def read_fixture(root: Path, relative: str, *, limit: int = MAX_FIXTURE_BYTES) -> bytes:
    path = local_file(root, relative)
    try:
        with path.open("rb") as stream:
            contents = stream.read(limit + 1)
    except OSError as exc:
        raise reject("DVI-POL-009", relative, "fixture could not be read") from exc
    if len(contents) > limit:
        raise reject("DVI-POL-010", relative, f"file exceeds {limit} bytes")
    return contents
