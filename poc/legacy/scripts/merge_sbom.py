#!/usr/bin/env python3
"""Conservatively merge CycloneDX inventories and dependency references.

Conflicting metadata and unsupported nested inventories fail instead of being
silently discarded. This helper does not replace CycloneDX schema validation.
"""
import argparse
import copy
import json
import sys
from pathlib import Path


def merge(boms):
    if not boms:
        raise ValueError("no SBOM inputs")
    merged = copy.deepcopy(boms[0])
    merged["components"] = []
    identities, references, aliases, edges = {}, {}, {}, {}
    for bom in boms:
        if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
            raise ValueError("every input must be a CycloneDX object")
        if bom.get("specVersion") != merged.get("specVersion"):
            raise ValueError(
                f"SBOM specVersion mismatch: first input uses {merged.get('specVersion')!r}, "
                f"another input uses {bom.get('specVersion')!r}; "
                "regenerate the inputs with the same CycloneDX version"
            )
        if any(bom.get(field) for field in ("services", "vulnerabilities", "compositions")):
            raise ValueError("services/vulnerabilities/compositions require a full CycloneDX merger")
        components = bom.get("components")
        if not isinstance(components, list):
            raise ValueError("SBOM components must be a list")
        root = (bom.get("metadata") or {}).get("component")
        if isinstance(root, dict) and root.get("bom-ref"):
            if root.get("components"):
                raise ValueError("nested root components require flattening before merge")
            if bom is not boms[0]:
                components = components + [root]
            else:
                references[root["bom-ref"]] = ("root", root.get("name"))
                aliases[root["bom-ref"]] = root["bom-ref"]
        for component in components:
            if not isinstance(component, dict) or not isinstance(component.get("name"), str):
                raise ValueError("every component needs a string name")
            if component.get("components"):
                raise ValueError("nested components require flattening before merge")
            identity = component.get("purl") or (component["name"], component.get("version"))
            ref = component.get("bom-ref")
            if ref:
                if ref in references and references[ref] != identity:
                    raise ValueError(f"conflicting bom-ref: {ref}")
                references[ref] = identity
            if identity not in identities:
                identities[identity] = copy.deepcopy(component)
                merged["components"].append(identities[identity])
            else:
                current = identities[identity]
                for field, value in component.items():
                    if field == "bom-ref":
                        current.setdefault(field, value)
                    elif field not in current:
                        current[field] = copy.deepcopy(value)
                    elif isinstance(value, list) and isinstance(current[field], list):
                        for entry in value:
                            if entry not in current[field]:
                                current[field].append(copy.deepcopy(entry))
                    elif current[field] != value:
                        raise ValueError(f"conflicting {field} for component {component['name']}")
            if ref:
                aliases[ref] = identities[identity]["bom-ref"]
    for bom in boms:
        dependencies = bom.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise ValueError("dependencies must be a list")
        for dependency in dependencies:
            if not isinstance(dependency, dict) or set(dependency) - {"ref", "dependsOn"}:
                raise ValueError("unsupported dependency shape")
            ref, targets = dependency.get("ref"), dependency.get("dependsOn", [])
            if not isinstance(targets, list) or ref not in aliases or any(t not in aliases for t in targets):
                raise ValueError("dependency references an unknown component")
            edges.setdefault(aliases[ref], set()).update(aliases[t] for t in targets)
    if edges:
        merged["dependencies"] = [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(edges.items())]
    return merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("-o", "--out", required=True)
    args = parser.parse_args()
    try:
        merged = merge([json.loads(Path(p).read_text(encoding="utf-8")) for p in args.inputs])
        Path(args.out).write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f"SBOM merge failed: {error}", file=sys.stderr)
        return 2
    print(f"Merged {len(merged['components'])} components into {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
