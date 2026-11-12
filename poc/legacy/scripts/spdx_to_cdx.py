#!/usr/bin/env python3
"""Convert SPDX 2.x SBOMs (JSON or tag-value) into one CycloneDX SBOM.

Yocto's create-spdx writes one JSON document per recipe and Zephyr's west spdx
writes several tag-value documents, so inputs can be files or directories.
Packages are merged across documents. Relationships are not converted.

Usage: python poc/legacy/scripts/spdx_to_cdx.py build/spdx --name my-image -o out/sbom.cdx.json
"""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import quote

# Everything else becomes "library": Syft and Grype do not scan components typed
# operating-system, so a kernel with that type would silently get no CVE matches.
PURPOSE_TO_TYPE = {"APPLICATION": "application", "FRAMEWORK": "framework"}
TAG_TO_FIELD = {
    "PackageVersion": "versionInfo",
    "PackageSupplier": "supplier",
    "PackageLicenseDeclared": "licenseDeclared",
    "PackageLicenseConcluded": "licenseConcluded",
    "PrimaryPackagePurpose": "primaryPackagePurpose",
}


def fail(message):
    sys.exit(f"ERROR: {message}")


def clean(value):
    value = (value or "").strip()
    return "" if value in ("NOASSERTION", "NONE") else value


def parse_tag_value(text):
    doc = {"packages": []}
    package = None
    in_text = False
    for line in text.splitlines():
        if in_text:
            in_text = "</text>" not in line
            continue
        tag, sep, value = line.partition(":")
        if not sep or line.startswith("#"):
            continue
        value = value.strip()
        if value.startswith("<text>") and "</text>" not in value:
            in_text = True
        elif tag == "SPDXVersion":
            doc["spdxVersion"] = value
        elif tag == "DocumentName":
            doc["name"] = value
        elif tag == "PackageName":
            package = {"name": value, "externalRefs": []}
            doc["packages"].append(package)
        elif tag == "FileName":
            package = None
        elif package is not None and tag in TAG_TO_FIELD:
            package[TAG_TO_FIELD[tag]] = value
        elif package is not None and tag == "ExternalRef":
            parts = value.split()
            if len(parts) == 3:
                package["externalRefs"].append({"referenceType": parts[1], "referenceLocator": parts[2]})
    return doc


def read_document(path):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"{path}: cannot read as text ({exc}). Extract archives such as .spdx.tar.zst first.")
    if text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError as exc:
            fail(f"{path}: invalid JSON ({exc})")
        if "@graph" in doc or "@context" in doc:
            fail(f'{path}: SPDX 3 is not supported. On Yocto, use INHERIT += "create-spdx-2.2".')
    else:
        doc = parse_tag_value(text)
    if not str(doc.get("spdxVersion", "")).startswith("SPDX-2."):
        fail(f"{path}: not an SPDX 2.x document")
    return doc


def find_documents(inputs):
    paths = []
    for name in inputs:
        path = Path(name)
        if path.is_dir():
            paths += sorted(p for p in path.rglob("*") if p.name.endswith((".spdx", ".spdx.json")))
        elif path.is_file():
            paths.append(path)
        else:
            fail(f"{path}: no such file or directory")
    if not paths:
        fail(f"no .spdx or .spdx.json files in {', '.join(inputs)}. Extract archives such as .spdx.tar.zst first.")
    return paths


def to_component(package):
    refs = {r.get("referenceType"): r.get("referenceLocator") for r in package.get("externalRefs", [])}
    component = {
        "type": PURPOSE_TO_TYPE.get(package.get("primaryPackagePurpose"), "library"),
        "name": package["name"].strip(),
    }
    version = clean(package.get("versionInfo"))
    supplier = clean(package.get("supplier")).partition(":")[2].strip()
    license_expr = clean(package.get("licenseDeclared")) or clean(package.get("licenseConcluded"))
    cpe = refs.get("cpe23Type") or refs.get("cpe22Type")
    if version:
        component["version"] = version
    if supplier:
        component["supplier"] = {"name": supplier}
    if license_expr:
        component["licenses"] = [{"expression": license_expr}]
    if refs.get("purl"):
        component["purl"] = refs["purl"]
    if cpe:
        component["cpe"] = cpe
    return component


def convert(paths, name=None):
    docs = [read_document(p) for p in paths]
    merged = {}
    for doc in docs:
        for package in doc.get("packages", []):
            if not clean(package.get("name")):
                continue
            component = to_component(package)
            key = f'{component["name"]}@{component.get("version", "")}'
            # A later document can hold identifiers the first one lacks, such as a CPE
            existing = merged.setdefault(key, component)
            for field, value in component.items():
                existing.setdefault(field, value)
    components = list(merged.values())
    if not components:
        fail(f"no packages found in {len(paths)} SPDX document(s)")

    unversioned = [c["name"] for c in components if "version" not in c]
    no_cpe = [c["name"] for c in components if "cpe" not in c]
    for c in components:
        if "purl" not in c:
            version = f'@{quote(c["version"], safe="")}' if "version" in c else ""
            c["purl"] = f'pkg:generic/{quote(c["name"], safe="")}{version}'

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "firmware", "name": name or docs[0].get("name", "firmware")}},
        "components": components,
    }
    return bom, unversioned, no_cpe


def warn(names, problem):
    if names:
        shown = ", ".join(names[:5]) + (", ..." if len(names) > 5 else "")
        print(f"WARNING: {len(names)} component(s) {problem}: {shown}")


def main():
    ap = argparse.ArgumentParser(description="Convert SPDX 2.x SBOMs into one CycloneDX SBOM")
    ap.add_argument("inputs", nargs="+", help="SPDX files, or directories to search for them")
    ap.add_argument("--name", help="Firmware name for the SBOM metadata (default: first document's name)")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    paths = find_documents(args.inputs)
    bom, unversioned, no_cpe = convert(paths, args.name)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(bom, indent=2), encoding="utf-8")
    print(f"Converted {len(paths)} SPDX document(s) into {len(bom['components'])} components in {args.out}")
    warn(unversioned, "have no version, so CVE matching cannot work")
    warn(no_cpe, "have no CPE; without Grype's --add-cpes-if-none they may get no CVE matches")


if __name__ == "__main__":
    main()
