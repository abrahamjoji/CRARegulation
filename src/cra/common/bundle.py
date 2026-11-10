"""Evidence directory with a SHA-256 manifest.

A manifest detects accidental change and binds files to each other. It is not
authentication: anyone who can rewrite the directory can rewrite the manifest.
"""
import json
import shutil
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
        if path.is_file() and path.name != MANIFEST:
            files.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
    manifest = {"schema_version": MANIFEST_SCHEMA, "authenticated": False, "files": files, **metadata}
    write_json(root / MANIFEST, manifest)
    return manifest


def verify_manifest(root):
    """Return problems: changed, missing or unlisted files. An empty list means hashes agree."""
    root = Path(root)
    manifest = read_json(root / MANIFEST)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA or not isinstance(manifest.get("files"), list):
        raise UntrustedInputError("manifest_invalid", f"{root / MANIFEST}: not a {MANIFEST_SCHEMA} manifest")
    problems, listed = [], set()
    resolved_root = root.resolve()
    for record in manifest["files"]:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise UntrustedInputError("manifest_invalid", "manifest entry needs a path")
        target = (root / record["path"])
        if not target.resolve().is_relative_to(resolved_root):
            raise UntrustedInputError("manifest_invalid", f"manifest path escapes the bundle: {record['path']}")
        listed.add(record["path"])
        if not target.is_file():
            problems.append(f"missing: {record['path']}")
        elif sha256_file(target) != record.get("sha256"):
            problems.append(f"changed: {record['path']}")
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_file() and path.name != MANIFEST and relative not in listed:
            problems.append(f"unlisted: {relative}")
    return problems
