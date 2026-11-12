#!/usr/bin/env python3
"""Snapshot report inputs and linked evidence with a SHA-256 manifest.

Hashes establish integrity relative to this manifest, not signer authenticity.
"""
import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path


def snapshot(inputs, product_path, destination, revision="", firmware=None):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("evidence destination already exists; refusing to overwrite")
    product_path = Path(product_path).resolve()
    root = product_path.parent
    product = json.loads(product_path.read_text(encoding="utf-8"))
    files = [("input", Path(path).resolve()) for path in inputs]
    files.append(("product", product_path))
    if firmware:
        files.append(("firmware", Path(firmware).resolve()))
    for part in product["annex_i"].values():
        for item in part:
            for ref in item.get("evidence_refs", []):
                path = (root / ref).resolve()
                if not path.is_relative_to(root):
                    raise ValueError(f"evidence path escapes product root: {ref}")
                files.append(("linked-evidence", path))
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Build outside the destination so a failed copy never looks like a complete bundle.
    with tempfile.TemporaryDirectory(dir=destination.parent) as work:
        stage = Path(work) / "bundle"
        stage.mkdir()
        manifest = {"schema_version": 1, "source_revision": revision,
                    "authenticated": False, "files": []}
        seen = set()
        for role, source in files:
            if source in seen:
                continue
            seen.add(source)
            if not source.is_file() or source.stat().st_size == 0:
                raise ValueError(f"missing or empty evidence: {source}")
            name = f"{len(manifest['files']):03d}-{source.name}"
            target = stage / name
            shutil.copyfile(source, target)
            manifest["files"].append({"role": role, "path": name,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "bytes": target.stat().st_size})
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        stage.rename(destination)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--revision", default="")
    parser.add_argument("--firmware", help="Optional exact built firmware file to retain and hash")
    parser.add_argument("inputs", nargs="+")
    args = parser.parse_args()
    try:
        snapshot(args.inputs, args.product, args.out, args.revision, args.firmware)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Evidence snapshot failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
