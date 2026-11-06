#!/usr/bin/env python3
"""Merge CycloneDX SBOMs (scanner output + manual components) into one file.

Usage: python scripts/merge_sbom.py out/sbom.cdx.json sbom/manual-components.cdx.json -o out/sbom.full.cdx.json
"""
import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    boms = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.inputs]
    merged = boms[0]
    seen = {c.get("purl") or f'{c.get("name")}@{c.get("version")}' for c in merged.get("components", [])}
    for bom in boms[1:]:
        for c in bom.get("components", []):
            key = c.get("purl") or f'{c.get("name")}@{c.get("version")}'
            if key not in seen:
                merged.setdefault("components", []).append(c)
                seen.add(key)
    Path(args.out).write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(f"Merged {len(merged.get('components', []))} components into {args.out}")


if __name__ == "__main__":
    main()
