"""Evidence directory with a SHA-256 manifest.

A manifest detects accidental change and binds files to each other. It is not
authentication: anyone who can rewrite the directory can rewrite the manifest.
"""
import json
import shutil
import re
from pathlib import PurePosixPath
from pathlib import Path

from .errors import UntrustedInputError
from .safety import read_json, redact, redact_text, sha256_bytes, sha256_file, stable_id, write_json

MANIFEST = "manifest.json"
MANIFEST_SCHEMA = "cra.evidence-manifest/1"
SAFE_MAX_TEXT = 512 * 1024 * 1024


def reset_output(destination, kind, protected=()):
    """Only replace recognized output bundles, never unrelated customer files."""
    destination = Path(destination)
    resolved = destination.resolve()
    for path in protected:
        if path is not None and Path(path).resolve().is_relative_to(resolved):
            raise UntrustedInputError("output_overlaps_input", "output would overwrite an input or working directory")
    if destination.is_symlink():
        raise UntrustedInputError("output_unsafe", "output directory must not be a symlink")
    if destination.exists():
        if not destination.is_dir():
            raise UntrustedInputError("output_unsafe", "output path is not a directory")
        if any(destination.iterdir()):
            manifest = destination / MANIFEST
            if not manifest.is_file() or manifest.is_symlink():
                raise UntrustedInputError("output_unsafe", "refusing to replace a nonempty directory without a CRA output manifest")
            metadata = read_json(manifest)
            if not isinstance(metadata, dict) or metadata.get("kind") != kind:
                raise UntrustedInputError("output_unsafe", "existing output has a different bundle kind")
            if any(path.is_symlink() for path in destination.rglob("*")):
                raise UntrustedInputError("output_unsafe", "existing output contains symlinks")
            if any(problem.startswith("unlisted:") for problem in verify_manifest(destination)):
                raise UntrustedInputError("output_unsafe", "existing output contains unlisted files; use a new destination")
            shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


class EvidenceStore:
    """Copies raw tool and collector output into evidence/, redacting text content."""

    def __init__(self, root):
        self.root = Path(root)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.records = []

    def _record(self, role, source, stored_name, original_hash, redactions, adapter):
        path = self.evidence_dir / stored_name
        identity = stable_id("ev", stored_name)
        self.records.append({"id": identity, "role": role, "source": source, "path": f"evidence/{stored_name}",
                             "sha256": sha256_file(path), "bytes": path.stat().st_size,
                             "original_sha256": original_hash, "redactions": redactions, "adapter": adapter})
        return identity

    def add_json(self, role, source, value, stored_name, *, original_bytes=None, adapter=""):
        cleaned, count = redact(value)
        write_json(self.evidence_dir / stored_name, cleaned)
        original = sha256_bytes(original_bytes) if original_bytes is not None else ""
        return self._record(role, source, stored_name, original, count, adapter)

    def add_file_as_text(self, role, source, path, stored_name, *, adapter=""):
        path = Path(path)
        if path.stat().st_size > SAFE_MAX_TEXT:
            raise UntrustedInputError("file_too_large", f"{path}: too large to retain")
        original = path.read_bytes()
        cleaned, count = redact_text(original.decode("utf-8", "replace"))
        (self.evidence_dir / stored_name).write_text(cleaned, encoding="utf-8")
        return self._record(role, source, stored_name, sha256_bytes(original), count, adapter)

    def add_binary(self, role, source, path, stored_name, *, adapter=""):
        shutil.copyfile(path, self.evidence_dir / stored_name)
        return self._record(role, source, stored_name, sha256_file(path), 0, adapter)


def write_manifest(root, extra_files=(), **metadata):
    """Hash every regular file below root except the manifest itself."""
    root = Path(root)
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise UntrustedInputError("bundle_symlink", f"evidence bundle contains a symlink: {path}")
        if path.is_file() and path != root / MANIFEST:
            files.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
    manifest = {"schema_version": MANIFEST_SCHEMA, "authenticated": False, "files": files, **metadata}
    write_json(root / MANIFEST, manifest)
    return manifest


def bundle_file(root, relative):
    """Resolve only canonical relative regular files; every parent must stay inside the bundle."""
    root = Path(root)
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise UntrustedInputError("manifest_invalid", "bundle paths must be canonical relative paths")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or parts.as_posix() != relative or any(part in (".", "..") for part in parts.parts):
        raise UntrustedInputError("manifest_invalid", "bundle path is not canonical or escapes its root")
    current = root
    if root.is_symlink():
        raise UntrustedInputError("bundle_symlink", "bundle root must not be a symlink")
    for part in parts.parts:
        current = current / part
        if current.is_symlink():
            raise UntrustedInputError("bundle_symlink", "bundle paths must not traverse symlinks")
    if not current.resolve().is_relative_to(root.resolve()):
        raise UntrustedInputError("manifest_invalid", "bundle path escapes its root")
    return current


def verify_manifest(root):
    """Check paths, types, sizes, hashes and the complete file set before consuming a bundle."""
    root = Path(root)
    manifest_path = bundle_file(root, MANIFEST)
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA or not isinstance(manifest.get("files"), list):
        raise UntrustedInputError("manifest_invalid", "invalid evidence manifest")
    problems, listed = [], set()
    for record in manifest["files"]:
        if not isinstance(record, dict):
            raise UntrustedInputError("manifest_invalid", "manifest entries must be objects")
        name = record.get("path")
        target = bundle_file(root, name)
        size, digest = record.get("bytes"), record.get("sha256")
        if name == MANIFEST or name in listed:
            raise UntrustedInputError("manifest_invalid", "duplicate or self-referential manifest entry")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise UntrustedInputError("manifest_invalid", "manifest entries need nonnegative size and SHA-256")
        listed.add(name)
        if not target.is_file():
            problems.append(f"missing: {name}")
        elif target.stat().st_size != size or sha256_file(target) != digest:
            problems.append(f"changed: {name}")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise UntrustedInputError("bundle_symlink", "bundle contains a symlink")
        relative = path.relative_to(root).as_posix()
        if path.is_file() and path != root / MANIFEST and relative not in listed:
            problems.append(f"unlisted: {relative}")
        elif not path.is_file() and not path.is_dir():
            raise UntrustedInputError("manifest_invalid", "bundle contains a special file")
    return problems


def verify_evidence_references(root, collection):
    """A collection must not direct the scanner to files outside its verified manifest."""
    manifest = read_json(Path(root) / MANIFEST)
    listed = {row["path"]: row for row in manifest["files"]}
    identities = set()
    for record in collection["evidence"]:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str) or record["id"] in identities:
            raise UntrustedInputError("collection_evidence_invalid", "evidence identifiers must be unique strings")
        identities.add(record["id"])
        name = record.get("path")
        path = bundle_file(root, name)
        expected = listed.get(name)
        if not expected or not path.is_file() or any(record.get(key) != expected[key] for key in ("bytes", "sha256")):
            raise UntrustedInputError("collection_evidence_invalid", "evidence reference does not match the verified manifest")
    for record in collection["observations"] + collection["artifacts"]:
        evidence = record.get("evidence")
        if evidence and (not isinstance(evidence, str) or evidence not in identities):
            raise UntrustedInputError("collection_evidence_invalid", "observation/artifact names unknown evidence")
