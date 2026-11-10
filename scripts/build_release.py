#!/usr/bin/env python3
"""Build a release directory: wheel, release.json, and a cosign bundle over release.json.

Signing uses cosign with either a local key (for testing) or keyless identity in CI.
Trust and rotation are documented in docs/PROVENANCE.md. This script publishes nothing.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--wheel", type=Path, help="Existing wheel; built when absent")
    parser.add_argument("--version", help="Override the version in release.json (tests only)")
    parser.add_argument("--image-digest", action="append", default=[], metavar="NAME=sha256:...")
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--key", help="Cosign private key file. Omit for keyless signing in CI.")
    parser.add_argument("--no-sign", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    if args.wheel:
        wheel = args.out / args.wheel.name
        wheel.write_bytes(args.wheel.read_bytes())
    else:
        subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(args.out), str(REPO)], check=True)
        wheel = next(args.out.glob("*.whl"))
    sys.path.insert(0, str(REPO / "src"))
    from cra import __version__
    revision = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    document = {"schema_version": "cra.release/1", "version": args.version or __version__, "source_revision": revision,
                "files": [{"name": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}],
                "images": dict(item.split("=", 1) for item in args.image_digest),
                "scanners": {"syft": "1.57.0", "grype": "0.121.2"}}
    release = args.out / "release.json"
    release.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not args.no_sign:
        command = [args.cosign, "sign-blob", str(release), "--bundle", str(release) + ".sigstore.json", "--yes"]
        if args.key:
            command += ["--key", args.key, "--tlog-upload=false", "--use-signing-config=false"]
        subprocess.run(command, check=True)
    print(json.dumps(document, indent=2))


if __name__ == "__main__":
    main()
