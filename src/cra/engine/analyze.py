"""cra analyze, local engine: inventory, scan, explain, evaluate, write a result bundle."""
import datetime as dt
import tempfile
from pathlib import Path

from .. import __version__
from ..common import purl as purls
from ..common.bundle import EvidenceStore, reset_output, verify_manifest, verify_evidence_references, write_manifest
from ..common.errors import UntrustedInputError, diagnostic
from ..common.safety import read_json, sha256_file, stable_id, write_json
from . import grype, kev, policy as policy_module, readiness as readiness_module, reconcile, report, vex

RESULT_SCHEMA = "cra.result/1"
ALWAYS_MISSING = "No reachability analysis was performed, so exploitability in this product is not established."


def _find_component(inventory, match):
    components = reconcile.component_lookup(inventory)
    key = purls.strip(match["purl"])
    if key in components:
        return components[key]
    if match["purl"]:
        return None  # An explicit identity must never be reassigned to another ecosystem.
    same = [item for item in inventory["components"] if item["identity"]["name"] == match["name"] and item["identity"]["version"] == match["version"]]
    return same[0] if len(same) == 1 else None


def _build_findings(inventory, matches, register_entries, kev_index, documents, trusted, now):
    groups = {}
    for match in matches:
        component = _find_component(inventory, match)
        key = (match["vulnerability"], component["id"] if component else match["purl"] or f"{match['name']}@{match['version']}")
        groups.setdefault(key, {"matches": [], "component": component})["matches"].append(match)

    known = {}
    for entry in register_entries:
        if entry.get("type") == "vulnerability" and entry.get("vulnerability"):
            known[(entry["vulnerability"], purls.strip(entry.get("purl")) if entry.get("purl") else None)] = entry
    # Register entries from any source count as findings, including ones no scanner sees.
    lookup = reconcile.component_lookup(inventory)
    for (vulnerability, purl), entry in known.items():
        component = lookup.get(purl)
        key = (vulnerability, component["id"] if component else purl or f"unscoped:{entry.get('id')}")
        if key not in groups:
            groups[key] = {"component": component, "matches": [], "register_only": entry}

    product = inventory["product"]
    product_purl = purls.build("generic", product.get("name", "product"), product.get("version"))
    findings = []
    for (vulnerability, _), group in sorted(groups.items(), key=lambda item: (item[0][0], str(item[0][1]))):
        finding = _finding(vulnerability, group, inventory, known, kev_index)
        finding["triage"] = _triage(finding, product_purl, documents, trusted, now)
        _finish_uncertainty(finding, group["component"])
        findings.append(finding)
    order = {name: index for index, name in enumerate(policy_module.SEVERITIES)}
    findings.sort(key=lambda item: (not item["kev"]["listed"], order.get(item["severity"], 9), item["vulnerability"]["id"], item["component"]["purl"]))
    return findings


def _finding(vulnerability, group, inventory, known, kev_index):
    matches, component = group["matches"], group["component"]
    first = matches[0] if matches else {}
    register_only = group.get("register_only") or {}
    identity = (component or {}).get("identity") or {}
    purl = identity.get("purl") or purls.strip(first.get("purl")) or purls.strip(register_only.get("purl")) or ""
    component_id = (component or {}).get("id")
    artifacts = (component or {}).get("artifacts", [])
    configurations = sorted((component or {}).get("configurations", {}))
    best = {"high": 2, "medium": 1, "low": 0}
    matching = max((item["matching"] for item in matches), key=lambda row: best.get(row["confidence"], 0), default=None) or {
        "scanner": "none", "matchers": [], "match_types": [], "confidence": "claim",
        "rationale": f"Recorded in the vulnerability register from source {register_only.get('source', 'other')}; not a scanner match."}
    entry = known.get((vulnerability, identity.get("purl") or purls.strip(first.get("purl")) or None)) or register_only or None
    listing = (kev_index or {}).get(vulnerability)
    for alias in first.get("aliases", []) if not listing else []:
        listing = listing or (kev_index or {}).get(alias)
    return {
        "id": stable_id("finding", vulnerability, component_id or purl),
        "origin": "product",
        "component": {"id": component_id, "name": identity.get("name") or first.get("name") or register_only.get("component") or "unknown",
                      "version": identity.get("version") or first.get("version") or register_only.get("version"),
                      "purl": purl, "ecosystem": identity.get("ecosystem") or "unknown", "evidence": (component or {}).get("observations", [])[:12],
                      "joined_to_inventory": component is not None},
        "vulnerability": {"id": vulnerability, "aliases": sorted({alias for item in matches for alias in item["aliases"]}),
                          "source": {"namespace": first.get("namespace") or "register", "url": first.get("url") or register_only.get("url") or ""},
                          "description": first.get("description") or register_only.get("description") or ""},
        "severity": first.get("severity") or str(register_only.get("severity") or "unknown").lower(),
        "cvss_base_score": max((item["score"] for item in matches if item["score"] is not None), default=None),
        "matching": {**matching, "targets": sorted({item["target"] for item in matches})},
        "presence": {key: (component or {"presence": {}})["presence"].get(key) for key in ("declared", "resolved", "observed")} | {
            "shipped": ((component or {}).get("presence") or {}).get("shipped", "unknown"),
            "shipped_rationale": ((component or {}).get("presence") or {}).get("shipped_rationale", ["This finding could not be joined to the inventory."]),
            "scope": (component or {}).get("scope", "unknown")},
        "artifacts": artifacts, "configurations": configurations,
        "locations": sorted({location for item in matches for location in item["locations"] if location})[:8],
        "dependency_paths": reconcile.dependency_paths(inventory, component_id) if component_id else [],
        "remediation": {"fix_state": first.get("fix_state") or "unknown", "fixed_in": sorted({value for item in matches for value in item["fixed_in"]}),
                        "note": _fix_note(matches)},
        "kev": {"listed": bool(listing), "meaning": kev.MEANING if listing else "", **(listing or {})},
        "exploitability": {"established": entry.get("actively_exploited_in_product") is True if entry else False,
                           "status": "recorded_exploited_in_product" if entry and entry.get("actively_exploited_in_product") is True else "unknown",
                           "basis": "Manufacturer's vulnerability register." if entry and isinstance(entry.get("actively_exploited_in_product"), bool) else "No evidence either way. A scanner match does not establish exploitability."},
        "register": {"id": entry.get("id"), "source": entry.get("source"), "upstream": entry.get("upstream"),
                     "release_decision": entry.get("release_decision")} if entry else None,
        "uncertainty": [], "missing_evidence": [ALWAYS_MISSING],
        "patch_claims": [item for item in (component or {}).get("patch_claims", []) if item.get("vulnerability") == vulnerability],
    }


def _fix_note(matches):
    if not matches:
        return "No scanner fix data."
    if any(item["fixed_in"] for item in matches):
        return "A fixed version is reported upstream. Updating the dependency and revalidating the product is the customer's change."
    return "The scanner reports no fixed version. Check for a vendor patch, mitigation or replacement."


def _triage(finding, product_purl, documents, trusted, now):
    decision = vex.decide(finding, product_purl, documents, trusted, now)
    decision["since"] = (decision.get("provenance") or {}).get("timestamp")
    return decision


def _finish_uncertainty(finding, component):
    uncertainty = finding["uncertainty"]
    if component is None:
        uncertainty.append("This finding could not be joined to the reconciled inventory. It is kept so nothing is lost.")
    else:
        uncertainty += component["uncertainty"]
    if finding["matching"]["confidence"] in ("low", "medium") and "cpe-match" in finding["matching"]["match_types"]:
        uncertainty.append("Matched by CPE, which can misidentify a package or miss a vendor patch.")
    shipped = finding["presence"]["shipped"]
    if shipped == "unknown":
        uncertainty.append("It is not established whether this component is in the shipped product.")
    elif shipped == "no":
        uncertainty.append("Evidence suggests this component is not shipped, so the finding concerns the build environment.")
    if finding["patch_claims"]:
        uncertainty.append("A customer record claims this vulnerability is patched. The claim is not verified and does not close the finding; record a VEX decision.")
    if finding["component"]["ecosystem"] not in ("deb", "rpm", "apk"):
        finding["missing_evidence"].append("Vendor or recipe patches applied to this build are not visible to the scanner.")
    if finding["kev"]["listed"]:
        finding["missing_evidence"].append("Whether the KEV-listed exploitation applies to this product has not been recorded.")
    if finding["triage"]["status"] == "needs_triage":
        finding["missing_evidence"].append("No applicable triage or VEX decision exists.")
    if finding["triage"]["status"] == "fixed":
        uncertainty.append("A VEX statement says fixed, and that claim is not verified against the shipped artifact.")


def run_analysis(collection_dir, analysis_settings, tools, destination, kev_path=None, now=None):
    """Analyze a collection bundle. Used by the CLI and by isolated hosted workers."""
    now = now or dt.datetime.now(dt.timezone.utc)
    collection_dir, destination = Path(collection_dir), Path(destination)
    problems = verify_manifest(collection_dir)
    if problems:
        raise UntrustedInputError("collection_integrity", "collection manifest does not match its files: " + "; ".join(problems[:5]))
    collection = reconcile.validate_collection(read_json(collection_dir / "collection.json"))
    verify_evidence_references(collection_dir, collection)
    reset_output(destination, "analysis", protected=[collection_dir, Path.cwd(), analysis_settings.policy,
                                                   analysis_settings.kev, analysis_settings.product_file, analysis_settings.risk_file,
                                                   analysis_settings.register_file] + analysis_settings.vex)
    store = EvidenceStore(destination)
    policy, policy_identity = policy_module.load_policy(analysis_settings.policy)
    inventory = reconcile.reconcile(collection)
    write_json(destination / "inventory.json", inventory)
    write_json(destination / "sbom.cdx.json", reconcile.export_cyclonedx(inventory))

    scanner_info, scanner_problems = grype.describe(tools)
    diagnostics = list(collection["diagnostics"]) + list(scanner_problems)
    if scanner_info["version"] and scanner_info["version"] not in grype.SUPPORTED_GRYPE and not tools.allow_unverified_versions:
        diagnostics.append(diagnostic("scanner_unverified_version", f"Grype {scanner_info['version']} is not a verified version (verified: {sorted(grype.SUPPORTED_GRYPE)})", subject="grype", origin="external"))
        scan = {"matches": [], "diagnostics": [], "targets": [], "scanner_ignored_matches": 0, "raw_evidence": [], "not_matchable": []}
    elif scanner_info["version"] is None:
        scan = {"matches": [], "diagnostics": [], "targets": [], "scanner_ignored_matches": 0, "raw_evidence": [], "not_matchable": []}
    else:
        with tempfile.TemporaryDirectory(prefix="cra-scan-") as work:
            scan = grype.scan_inventory(inventory, collection_dir, tools, work, store)
    scan["scanner"] = scanner_info
    scan["diagnostics"] = diagnostics + scan["diagnostics"]

    kev_index, kev_identity, kev_problem = kev.load(kev_path if kev_path is not None else analysis_settings.kev)
    documents, vex_problems = vex.load_documents(analysis_settings.vex)
    for item in documents:
        store.add_binary("customer-input", "vex", next(path for path in analysis_settings.vex if str(path).endswith(item["file"])), f"vex-{item['file']}", adapter="openvex")

    readiness, entries = None, []
    if analysis_settings.product_file:
        no_version = [item for item in inventory["components"] if not item["identity"]["version"] and item["presence"]["shipped"] != "no"]
        readiness, entries = readiness_module.assess(analysis_settings.product_file, analysis_settings.risk_file, analysis_settings.register_file,
                                                     bool(inventory["components"]) and not no_version, now)

    findings = _build_findings(inventory, scan["matches"], entries, kev_index, documents, policy["vex"]["trusted_authors"], now)
    incomplete = policy_module.incompleteness(inventory, scan, kev_identity, kev_problem, vex_problems, policy, now)
    evaluation = policy_module.evaluate(findings, inventory, policy, incomplete, readiness, now)

    counts = {"total": len(findings), "kev": sum(item["kev"]["listed"] for item in findings), "by_severity": {}, "by_status": {}, "by_shipped": {}}
    for finding in findings:
        for field, value in (("by_severity", finding["severity"]), ("by_status", finding["triage"]["status"]), ("by_shipped", finding["presence"]["shipped"])):
            counts[field][value] = counts[field].get(value, 0) + 1
    result = {
        "schema_version": RESULT_SCHEMA, "created_at": now.isoformat(timespec="seconds"),
        "scan_status": "incomplete" if incomplete else "complete",
        "product": collection["product"], "source": collection["source"], "collector": collection["collector"],
        "engine": {"name": "cra-engine", "version": __version__},
        "policy": policy_identity,
        "scanners": [scanner_info] + collection["adapters"],
        "vulnerability_data": {"grype": scanner_info.get("database"), "kev": kev_identity},
        "artifacts": [{key: item.get(key) for key in ("id", "kind", "role", "name", "sha256", "digest", "shipped", "configuration", "format")} for item in inventory["artifacts"]],
        "configurations": sorted(inventory["configurations"]),
        "coverage": {key: inventory["coverage"][key] for key in ("status", "incomplete_reasons", "limitations", "scope_note", "unresolved_count", "conflict_count")},
        "coverage_sources": inventory["coverage"]["sources"],
        "inventory_summary": {"components": len(inventory["components"]), "conflicts": len(inventory["conflicts"]),
                              "shipped": _count(inventory, "yes"), "not_shipped": _count(inventory, "no"), "shipped_unknown": _count(inventory, "unknown")},
        "conflicts": inventory["conflicts"],
        "summary": counts, "findings": findings, "evaluation": evaluation,
        "scan_targets": scan["targets"], "scanner_ignored_matches": scan["scanner_ignored_matches"],
        "not_matchable": scan["not_matchable"],
        "tool_diagnostics": scan["diagnostics"], "readiness": readiness,
        "collection_manifest_sha256": sha256_file(collection_dir / "manifest.json"),
        "notes": ["Findings are scanner matches and records, not verified root causes.", "No generated text or AI explanation is included in this result."],
    }
    write_json(destination / "result.json", result)
    report.write_reports(result, inventory, destination)
    write_manifest(destination, kind="analysis", engine_version=__version__, source_revision=collection["source"].get("revision"))
    return result


def _count(inventory, value):
    return sum(1 for item in inventory["components"] if item["presence"]["shipped"] == value)
