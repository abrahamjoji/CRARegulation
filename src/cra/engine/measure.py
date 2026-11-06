"""Measure an inventory against a known expected one, to keep claims about accuracy honest."""
from urllib.parse import unquote

from ..common.safety import read_json


def _canonical(purl):
    return unquote(purl)


def compare(inventory, expected):
    """Return completeness, false components and per-attribute mismatches."""
    actual = {_canonical(item["identity"]["purl"]): item for item in inventory["components"]}
    wanted = {_canonical(item["purl"]): item for item in expected["components"]}
    missing = sorted(set(wanted) - set(actual))
    unexpected = sorted(set(actual) - set(wanted))
    mismatches = []
    for key in sorted(set(wanted) & set(actual)):
        want, have = wanted[key], actual[key]
        if want["shipped"] != have["presence"]["shipped"]:
            mismatches.append({"component": key, "attribute": "shipped", "expected": want["shipped"], "actual": have["presence"]["shipped"]})
        if want["scope"] != have["scope"]:
            mismatches.append({"component": key, "attribute": "scope", "expected": want["scope"], "actual": have["scope"]})
        linkage = {item for item in have["linkage"] if item != "static-or-embedded"}
        if set(want["linkage"]) != linkage:
            mismatches.append({"component": key, "attribute": "linkage", "expected": sorted(want["linkage"]), "actual": sorted(linkage)})
        resolved = sorted(config for config, row in have["configurations"].items() if "resolved" in row["states"])
        if sorted(want["resolved_in"]) != resolved:
            mismatches.append({"component": key, "attribute": "resolved_in", "expected": sorted(want["resolved_in"]), "actual": resolved})
    total = len(wanted)
    return {"expected_components": total, "found": total - len(missing), "missing": missing, "unexpected": unexpected,
            "attribute_mismatches": mismatches, "completeness": (total - len(missing)) / total if total else 0.0,
            "false_component_rate": len(unexpected) / len(actual) if actual else 0.0}


def compare_files(inventory_path, expected_path):
    return compare(read_json(inventory_path), read_json(expected_path))
