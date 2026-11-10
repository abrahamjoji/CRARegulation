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


def compare_findings(result, labels):
    """Score findings against hand-labelled matches. Labels: list of {vulnerability, purl, label}.

    Only labelled findings count. An unlabelled finding is reported, not assumed correct.
    """
    known = {(item["vulnerability"], _canonical(item["purl"])): item["label"] for item in labels["labels"]}
    seen, true_matches, false_matches, unlabelled = set(), [], [], []
    for finding in result["findings"]:
        key = (finding["vulnerability"]["id"], _canonical(finding["component"]["purl"]))
        label = known.get(key)
        seen.add(key)
        row = {"vulnerability": key[0], "component": key[1], "confidence": finding["matching"]["confidence"], "shipped": finding["presence"]["shipped"]}
        if label == "true":
            true_matches.append(row)
        elif label == "false":
            false_matches.append(row)
        else:
            unlabelled.append(row)
    missed = sorted(f"{key[0]} on {key[1]}" for key, label in known.items() if label == "true" and key not in seen)
    assessed = len(true_matches) + len(false_matches)
    return {"labelled_true_found": len(true_matches), "labelled_true_missed": missed, "labelled_false_reported": false_matches,
            "unlabelled": len(unlabelled), "false_match_rate_of_labelled": len(false_matches) / assessed if assessed else None,
            "note": "Rates describe labelled findings only and are not a general accuracy claim."}
