"""Bounded artifact verification and staged local publication with explicit overwrite."""

import hashlib
import os
import shutil
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path

from dvi_sentinel.artifact_contract import validate_contract
from dvi_sentinel.artifact_models import (
    LINEAGE_FILES,
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACTS,
    MAX_BUNDLE_BYTES,
    ArtifactEntry,
    ArtifactIssue,
    ArtifactManifest,
    ArtifactVerification,
    RunRecord,
    portable_path,
)
from dvi_sentinel.local_fixtures import read_fixture
from dvi_sentinel.provenance_bundle import verify_bundle_lineage
from dvi_sentinel.serialization import canonical_json, parse_json


class ArtifactError(ValueError):
    pass


def _root(path: Path) -> Path:
    if str(path).startswith(("\\\\", "//")):
        raise ArtifactError("DVI-ARTIFACT-PATH: network destinations are unsupported")
    if any(part.is_symlink() or part.is_junction() for part in (path, *path.parents)):
        raise ArtifactError("DVI-ARTIFACT-PATH: symlink destinations are unsupported")
    return path.resolve()


def _inventory(root: Path) -> Iterator[Path]:
    """Yield lazily for the caller's count bound; never descend through a link/junction."""
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                yield path
                if not path.is_symlink() and not path.is_junction() and path.is_dir():
                    pending.append(path)


def verify_artifacts(
    directory: Path, *, expected_manifest_digest: str | None = None
) -> ArtifactVerification:
    issues: list[ArtifactIssue] = []
    manifest_digest = None
    run_id = None

    def issue(code: str, path: str, explanation: str) -> None:
        issues.append(ArtifactIssue(code=code, path=path, explanation=explanation))

    try:
        root = _root(directory)
        encoded = read_fixture(root, "manifest.json", limit=1024 * 1024)
        manifest_digest = hashlib.sha256(encoded).hexdigest()
        if expected_manifest_digest and manifest_digest != expected_manifest_digest:
            issue(
                "DVI-ARTIFACT-ANCHOR", "manifest.json", "Manifest differs from the trusted digest"
            )
        manifest = ArtifactManifest.model_validate(parse_json(encoded))
        run_id = manifest.run_id
        captured: dict[str, bytes] = {}
        captured_size = 0
        for entry in manifest.artifacts:
            try:
                contents = read_fixture(root, entry.path, limit=MAX_ARTIFACT_BYTES)
                captured_size += len(contents)
                if captured_size > MAX_BUNDLE_BYTES:
                    issue("DVI-ARTIFACT-SIZE", entry.path, "Actual bundle bytes exceed 128 MiB")
                    break
                captured[entry.path] = contents
                if len(contents) != entry.size_bytes:
                    issue("DVI-ARTIFACT-SIZE", entry.path, "Artifact length differs from manifest")
                if hashlib.sha256(contents).hexdigest() != entry.sha256:
                    issue("DVI-ARTIFACT-HASH", entry.path, "Artifact SHA-256 differs from manifest")
            except (ValueError, OSError):
                issue(
                    "DVI-ARTIFACT-MISSING",
                    entry.path,
                    "Artifact is absent or not a safe local file",
                )
        expected = {entry.path for entry in manifest.artifacts} | {"manifest.json"}
        directories = {
            parent.as_posix()
            for name in expected
            for parent in Path(name).parents
            if parent != Path(".")
        }
        for index, path in enumerate(_inventory(root)):
            if index > MAX_ARTIFACTS * 3:
                issue(
                    "DVI-ARTIFACT-EXTRA",
                    "manifest.json",
                    "Unexpected directory inventory exceeds bounds",
                )
                break
            relative = path.relative_to(root).as_posix()
            if (
                path.is_symlink()
                or path.is_junction()
                or not (
                    (path.is_file() and relative in expected)
                    or (path.is_dir() and relative in directories)
                )
            ):
                issue(
                    "DVI-ARTIFACT-EXTRA",
                    relative,
                    "Unlisted file, directory, or symlink is present",
                )
        if manifest.schema_version == "2":
            issues.extend(verify_bundle_lineage(captured))
        record = RunRecord.model_validate(
            parse_json(read_fixture(root, "run.json", limit=MAX_ARTIFACT_BYTES))
        )
        if record.run_id != manifest.run_id or record.tool_version != manifest.tool_version:
            issue("DVI-ARTIFACT-IDENTITY", "run.json", "Run identity/version differs from manifest")
        if not issues:
            try:
                validate_contract(root, record, manifest)
            except (ValueError, OSError, RecursionError):
                issue(
                    "DVI-ARTIFACT-CONTRACT",
                    "run.json",
                    "Typed evidence or cross-file derivations differ",
                )
    except (ValueError, OSError, RecursionError):
        issue(
            "DVI-ARTIFACT-MANIFEST",
            "manifest.json",
            "Manifest/run metadata is absent, unsafe, or invalid",
        )
    return ArtifactVerification(
        valid=not issues, manifest_digest=manifest_digest, run_id=run_id, issues=tuple(issues)
    )


def _cleanup_owned(path: Path, parent: Path) -> None:
    if (
        path.parent.resolve() != parent
        or not path.name.startswith((".dvi-stage-", ".dvi-backup-"))
        or path.is_symlink()
    ):
        raise ArtifactError("DVI-ARTIFACT-CLEANUP: refusing an unowned cleanup path")
    if path.exists():
        shutil.rmtree(path)


def write_artifacts(
    directory: Path, contents: Mapping[str, bytes], *, overwrite: bool = False
) -> ArtifactVerification:
    """New output publishes by rename; verified prior output is backed up on overwrite."""
    root = _root(directory)
    if root == root.parent:
        raise ArtifactError("DVI-ARTIFACT-PATH: filesystem roots are not output directories")
    if root.exists() and (not overwrite or not verify_artifacts(root).valid):
        raise ArtifactError(
            "DVI-ARTIFACT-EXISTS: overwrite requires a verified existing DVI artifact directory"
        )
    if "manifest.json" in contents or len(contents) > MAX_ARTIFACTS:
        raise ArtifactError(
            "DVI-ARTIFACT-BOUNDS: manifest is managed internally; at most 128 artifacts"
        )
    if sum(len(value) for value in contents.values()) > MAX_BUNDLE_BYTES:
        raise ArtifactError("DVI-ARTIFACT-BOUNDS: bundle exceeds 128 MiB")
    entries = tuple(
        ArtifactEntry(
            path=portable_path(name),
            sha256=hashlib.sha256(value).hexdigest(),
            size_bytes=len(value),
        )
        for name, value in sorted(contents.items())
    )
    record = RunRecord.model_validate(parse_json(contents.get("run.json", b"")))
    manifest = ArtifactManifest(
        schema_version="2" if contents.keys() & LINEAGE_FILES else "1",
        tool_version=record.tool_version,
        run_id=record.run_id,
        artifacts=entries,
    )
    root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".dvi-stage-", dir=root.parent))
    backup: Path | None = None
    published = False
    try:
        for name, value in (
            *sorted(contents.items()),
            ("manifest.json", (canonical_json(manifest) + "\n").encode("utf-8")),
        ):
            output = stage / name
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        verified = verify_artifacts(stage)
        if not verified.valid:
            raise ArtifactError("DVI-ARTIFACT-VERIFY: staged artifacts failed verification")
        if root.exists():
            if not overwrite or not verify_artifacts(root).valid:
                raise ArtifactError("DVI-ARTIFACT-EXISTS: destination changed before publication")
            backup = Path(tempfile.mkdtemp(prefix=".dvi-backup-", dir=root.parent))
            backup.rmdir()
            os.replace(root, backup)
        os.replace(stage, root)
        published = True
        return verified
    except BaseException:
        if backup is not None and backup.exists() and not root.exists():
            os.replace(backup, root)
        raise
    finally:
        _cleanup_owned(stage, root.parent)
        if published and backup is not None:
            _cleanup_owned(backup, root.parent)
