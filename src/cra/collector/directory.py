"""Language-independent directory evidence via Syft over a bounded, symlink-free snapshot."""
import os
import json
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

from ..common.errors import UntrustedInputError
from ..common.safety import Limits, read_json, sha256_bytes, sha256_file, stable_id
from .container import MAX_SYFT_OUTPUT, SUPPORTED_SYFT, SUPPORTED_SYFT_SCHEMA_MAJOR, parse_syft, run_syft, tool_versions

MAX_FILES = 100000
MAX_BYTES = 1024 * 1024 * 1024


def _open_in_tree(root_fd, relative):
    """Open every path component relative to a held root; refuse symlink substitutions."""
    parent = os.dup(root_fd)
    try:
        for part in relative.parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_fd
        return os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def snapshot(root, destination, excluded=()):
    root, destination = Path(root).resolve(), Path(destination)
    excluded = [Path(path).resolve() for path in excluded]
    entries, total = [], 0
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def walk_error(error):
            raise error
        for current, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            current = Path(current)
            dirs.sort()
            for name in list(dirs):
                path = current / name
                if name == ".git" or any(path.resolve().is_relative_to(item) for item in excluded):
                    dirs.remove(name)
                elif path.is_symlink():
                    raise UntrustedInputError("directory_symlink", f"directory scan refuses symlinks: {path.relative_to(root)}")
            for name in sorted(files):
                if name == ".git":
                    continue
                source = current / name
                if any(source.resolve().is_relative_to(item) for item in excluded):
                    continue
                relative = source.relative_to(root)
                if source.is_symlink():
                    raise UntrustedInputError("directory_symlink", f"directory scan refuses symlinks: {relative}")
                fd = _open_in_tree(root_fd, relative)
                with os.fdopen(fd, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise UntrustedInputError("directory_special_file", f"not a regular file: {relative}")
                    if len(entries) >= MAX_FILES or info.st_size > MAX_BYTES - total:
                        raise UntrustedInputError("directory_too_large", "directory snapshot exceeds 100000 files or 1 GiB")
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    copied = 0
                    with target.open("wb") as output:
                        while block := handle.read(min(1024 * 1024, MAX_BYTES - total - copied + 1)):
                            copied += len(block)
                            if copied > MAX_BYTES - total:
                                raise UntrustedInputError("directory_too_large", "directory changed beyond snapshot size limit")
                            output.write(block)
                total += copied
                entries.append({"path": relative.as_posix(), "bytes": copied, "sha256": sha256_file(target)})
    finally:
        os.close(root_fd)
    entries.sort(key=lambda entry: entry["path"])
    return entries, total


def collect_directory(directory, tools, store, excluded=()):
    root = directory.path
    record = {"id": directory.id, "kind": "directory", "role": directory.role,
              "shipped": directory.role == "final", "path": str(root), "name": root.name,
              "format": "directory", "sha256": "", "bytes": 0, "evidence": "", "limitations": [
                  "Only detected package metadata is inventoried; undeclared/vendored dependencies may remain unidentified.",
                  ".git and configured CRA output directories are excluded. Symlinks and special files are refused."]}
    if not root.is_dir():
        return record, [], "missing", f"directory not found: {root}", None
    version = tool_versions(tools.syft, Limits(timeout_seconds=60))
    tool = {"name": "syft", "version": version, "output_schema": ""}
    if version not in SUPPORTED_SYFT and not tools.allow_unverified_versions:
        return record, [], "unsupported", f"Syft {version} is not a verified version", tool
    with tempfile.TemporaryDirectory(prefix="cra-directory-") as work:
        staged = Path(work) / "input"
        staged.mkdir()
        files, total = snapshot(root, staged, excluded)
        snapshot_evidence = store.add_json("collector-input", f"directory:{directory.id}", {"files": files},
                                           f"directory-{directory.id}.files.json", adapter="directory-snapshot")
        record["sha256"] = sha256_bytes(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())
        record["bytes"] = total
        record["snapshot_evidence"] = snapshot_evidence
        output = Path(work) / "syft.json"
        target = SimpleNamespace(reference=None, format="dir", archive=staged)
        result = run_syft(target, tools, output)
        if result.timed_out or result.returncode or not output.is_file():
            return record, [], "failed", f"Syft directory scan failed (exit {result.returncode}, timeout={result.timed_out}): {result.stderr[:400]}", tool
        document = read_json(output, MAX_SYFT_OUTPUT)
        evidence = store.add_json("scanner-output", f"directory:{directory.id}", document,
                                  f"directory-{directory.id}.syft.json", original_bytes=output.read_bytes(), adapter=f"syft {version}")
        parsed = parse_syft(document, directory, evidence)
    tool["output_schema"] = parsed["schema_version"]
    record["evidence"] = evidence
    if parsed["schema_version"].split(".")[0] != SUPPORTED_SYFT_SCHEMA_MAJOR and not tools.allow_unverified_versions:
        return record, [], "unsupported", f"Syft output schema {parsed['schema_version']} is not verified", tool
    for observation in parsed["observations"]:
        observation.update(id=stable_id("obs", "directory", directory.id, observation["id"]), source=f"directory:{directory.role}",
                           state="shipped" if directory.role == "final" else "declared" if directory.role == "source" else "observed")
        observation["scope"] = "build_stage" if directory.role == "build-stage" else "runtime"
    if not parsed["observations"]:
        return record, [], "partial", "Syft found no packages; this does not establish that the directory has no dependencies", tool
    return record, parsed["observations"], "complete", "", tool
