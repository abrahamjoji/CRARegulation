"""Vulnerability scanning through a narrow Grype adapter.

Scanner version and output handling are pinned together. A scanner failure is an
incomplete scan and goes to tool diagnostics; it never looks like zero findings.
"""
import os
import tempfile
from pathlib import Path

from ..common.errors import UntrustedInputError, diagnostic
from ..common.safety import Limits, read_json, run_tool, tool_environment, write_json
from ..common.safety import MIB

SUPPORTED_GRYPE = {"0.121.2"}
MAX_OUTPUT = 512 * MIB
# Curated product CPEs for packages whose ecosystem has no vulnerability feed of its own.
# A CPE match compares product names, so results carry medium confidence at best.
CPE_HINTS = {
    "zlib": "cpe:2.3:a:zlib:zlib:{version}:*:*:*:*:*:*:*",
    "openssl": "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",
    "lz4": "cpe:2.3:a:lz4_project:lz4:{version}:*:*:*:*:*:*:*",
    "fmt": "cpe:2.3:a:fmt:fmt:{version}:*:*:*:*:*:*:*",
    "nlohmann_json": "cpe:2.3:a:json-for-modern-cpp_project:json-for-modern-cpp:{version}:*:*:*:*:*:*:*",
    "libcurl": "cpe:2.3:a:haxx:libcurl:{version}:*:*:*:*:*:*:*",
    "curl": "cpe:2.3:a:haxx:curl:{version}:*:*:*:*:*:*:*",
    "expat": "cpe:2.3:a:libexpat_project:libexpat:{version}:*:*:*:*:*:*:*",
    "mosquitto": "cpe:2.3:a:eclipse:mosquitto:{version}:*:*:*:*:*:*:*",
    "protobuf-c": "cpe:2.3:a:protobuf-c_project:protobuf-c:{version}:*:*:*:*:*:*:*",
    "mbedtls": "cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*",
}


def apply_cpe_hints(sbom):
    """Add curated CPEs. Returns the bom-refs that received one."""
    hinted = set()
    for component in sbom["components"]:
        template = CPE_HINTS.get(component["name"].lower())
        if template and "cpe" not in component and component.get("version"):
            component["cpe"] = template.format(version=component["version"])
            hinted.add(component["bom-ref"])
    return hinted


def _environment(tools):
    env = {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    cache = os.environ.get("GRYPE_DB_CACHE_DIR") or str(Path.home() / ".cache" / "grype" / "db")
    env["GRYPE_DB_CACHE_DIR"] = cache
    return tool_environment(env, tools.env_passthrough)


def describe(tools):
    """Return scanner version and vulnerability-data identity, or diagnostics saying why not."""
    diagnostics, info = [], {"name": "grype", "version": None, "database": None}
    limits = Limits(timeout_seconds=min(tools.timeout_seconds, 120))
    with tempfile.TemporaryDirectory(prefix="cra-grype-") as work:
        version_file = Path(work) / "version.json"
        env = {**_environment(tools), "HOME": work}
        result = run_tool([tools.grype, "version", "-o", "json"], stdout_path=version_file, limits=limits, env=env)
        if result.missing:
            return info, [diagnostic("scanner_missing", f"Grype is not available: {result.stderr}", subject="grype", origin="external")]
        try:
            info["version"] = str(read_json(version_file, MIB).get("version", "")).lstrip("v") or None
        except (UntrustedInputError, AttributeError) as exc:
            diagnostics.append(diagnostic("scanner_version_unknown", f"cannot read the Grype version: {exc}", subject="grype", origin="external"))
        status_file = Path(work) / "status.json"
        result = run_tool([tools.grype, "db", "status", "-o", "json"], stdout_path=status_file, limits=limits, env=env)
        try:
            database = read_json(status_file, MIB)
            if not isinstance(database, dict):
                raise UntrustedInputError("db_status_invalid", "database status is not an object")
            info["database"] = {"schema": database.get("schemaVersion"), "built": database.get("built"),
                                "source": database.get("from"), "valid": database.get("valid")}
            if database.get("valid") is not True:
                diagnostics.append(diagnostic("vulnerability_db_invalid", "Grype reports its vulnerability database as invalid or missing", subject="grype", origin="external"))
        except UntrustedInputError as exc:
            diagnostics.append(diagnostic("vulnerability_db_unknown", f"cannot read vulnerability database status: {exc} ({result.stderr[:200]})", subject="grype", origin="external"))
    return info, diagnostics


def run_scan(target_path, tools, output_path, *, generated_cpes=False):
    """Scan one SBOM file. Raises nothing: returns (parsed output or None, diagnostics)."""
    argv = [tools.grype, f"sbom:{target_path}", "-o", "json", "--file", str(output_path), "-q"]
    if generated_cpes:
        argv.insert(2, "--add-cpes-if-none")
    with tempfile.TemporaryDirectory(prefix="cra-grype-home-") as home:
        result = run_tool(argv, limits=Limits(timeout_seconds=tools.timeout_seconds), env={**_environment(tools), "HOME": home})
    subject = Path(target_path).name
    if result.missing:
        return None, [diagnostic("scanner_missing", f"Grype is not available: {result.stderr}", subject=subject, origin="external")]
    if result.timed_out:
        return None, [diagnostic("scanner_timeout", f"Grype timed out after {tools.timeout_seconds} s", subject=subject, origin="external")]
    if result.returncode:
        return None, [diagnostic("scanner_failed", f"Grype exited with {result.returncode}: {result.stderr[:500]}", subject=subject, origin="external")]
    try:
        document = read_json(output_path, MAX_OUTPUT)
        validate_output(document)
    except UntrustedInputError as exc:
        return None, [diagnostic("scanner_output_invalid", str(exc), subject=subject, origin="external")]
    return document, []


def validate_output(document):
    """Reject output that could otherwise read as a clean scan."""
    if not isinstance(document, dict) or not isinstance(document.get("matches"), list):
        raise UntrustedInputError("scanner_output_invalid", "Grype output has no matches list")
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
        raise UntrustedInputError("scanner_output_invalid", "Grype output has no grype descriptor")
    for match in document["matches"]:
        vulnerability = match.get("vulnerability") if isinstance(match, dict) else None
        artifact = match.get("artifact") if isinstance(match, dict) else None
        if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str) or not vulnerability["id"]:
            raise UntrustedInputError("scanner_output_invalid", "a match has no vulnerability id")
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str) or not artifact["name"]:
            raise UntrustedInputError("scanner_output_invalid", "a match has no artifact name")


def _describe_search(searched):
    distro = searched.get("distro")
    if isinstance(distro, dict) and distro.get("type"):
        return f"the {distro.get('type')} {distro.get('version', '')} feed".replace("  ", " ")
    cpes = searched.get("cpes")
    if isinstance(cpes, list) and cpes:
        return f"by CPE {', '.join(str(item) for item in cpes[:2])}"
    language = searched.get("language")
    return f"the {language} package feed" if language else "by package name"


def normalize_match(match, target, hinted_purls):
    """Reduce one match to the fields the finding needs, and explain the match."""
    vulnerability, artifact = match["vulnerability"], match["artifact"]
    details = [item for item in match.get("matchDetails") or [] if isinstance(item, dict)]
    kinds = sorted({str(item.get("type")) for item in details}) or ["unknown"]
    matchers = sorted({str(item.get("matcher")) for item in details if item.get("matcher")})
    namespace = str(vulnerability.get("namespace") or "")
    cpe_only = kinds == ["cpe-match"]
    purl = artifact.get("purl") or ""
    if cpe_only:
        confidence = "medium" if purl.split("?")[0] in hinted_purls or artifact.get("cpes") else "low"
    elif kinds == ["unknown"]:
        confidence = "low"
    else:
        confidence = "high"
    pieces = []
    for item in details[:3]:
        searched = item.get("searchedBy") or {}
        found = item.get("found") or {}
        if not isinstance(searched, dict) or not isinstance(found, dict):
            continue
        pieces.append(f"{item.get('matcher')} ({item.get('type')}) searched {_describe_search(searched)}; affected range {found.get('versionConstraint', 'unknown')}.")
    if cpe_only:
        pieces.append("A CPE match compares vendor and product names only, so it may not describe this package build.")
    if namespace.startswith(("debian:", "ubuntu:", "rhel:", "alpine:", "amazon:", "wolfi:", "chainguard:", "sles:", "ol:", "mariner:")):
        pieces.append("The distribution's own feed was used, so its backported fixes are considered.")
    fix = vulnerability.get("fix") if isinstance(vulnerability.get("fix"), dict) else {}
    scores = [entry.get("metrics", {}).get("baseScore") for entry in vulnerability.get("cvss") or [] if isinstance(entry, dict) and isinstance(entry.get("metrics"), dict)]
    related = [item.get("id") for item in match.get("relatedVulnerabilities") or [] if isinstance(item, dict) and item.get("id")]
    return {"vulnerability": vulnerability["id"], "aliases": sorted(set(related) - {vulnerability["id"]}),
            "severity": str(vulnerability.get("severity") or "unknown").lower(),
            "score": max([score for score in scores if isinstance(score, (int, float))], default=None),
            "description": str(vulnerability.get("description") or "")[:2000], "namespace": namespace,
            "url": vulnerability.get("dataSource") or "", "fix_state": str(fix.get("state") or "unknown"),
            "fixed_in": [str(item) for item in fix.get("versions") or []][:16],
            "purl": purl, "name": artifact["name"], "version": artifact.get("version"), "package_type": artifact.get("type"),
            "locations": [item.get("path") for item in artifact.get("locations") or [] if isinstance(item, dict)][:8],
            "target": target,
            "matching": {"scanner": "grype", "matchers": matchers, "match_types": kinds, "confidence": confidence, "rationale": " ".join(pieces) or "Scanner gave no match details."}}


def scan_inventory(inventory, collection_root, tools, work_dir, store):
    """Scan build-derived components and each image's retained Syft document."""
    from .reconcile import export_cyclonedx
    work_dir = Path(work_dir)
    matches, diagnostics, targets, ignored, raw_records = [], [], [], 0, []
    plans = []
    sbom = export_cyclonedx(inventory, only_for_scan=True)
    hinted = apply_cpe_hints(sbom)
    hinted_purls = {item["purl"] for item in sbom["components"] if item["bom-ref"] in hinted or item.get("cpe")}
    # A package with no CPE in an ecosystem with no feed gets no matches. That must be said.
    not_matchable = [{"component": item["bom-ref"], "name": item["name"], "version": item.get("version"),
                      "message": "No vulnerability feed covers this package identity, so no matches are possible. The absence of findings says nothing about it."}
                     for item in sbom["components"] if not item.get("cpe") and not tools.add_generated_cpes
                     and (item["purl"].startswith(("pkg:conan/", "pkg:generic/")))]
    if sbom["components"]:
        path = work_dir / "scan-input-build.cdx.json"
        write_json(path, sbom)
        plans.append(("build-derived", path, tools.add_generated_cpes))
    for artifact in inventory["artifacts"]:
        if artifact.get("kind") == "image" and artifact.get("evidence"):
            record = next((item for item in inventory["evidence"] if item["id"] == artifact["evidence"]), None)
            if record:
                plans.append((f"image:{artifact['id']}", Path(collection_root) / record["path"], False))
    for label, path, generated in plans:
        output = work_dir / f"grype-{label.replace(':', '-')}.json"
        document, problems = run_scan(path, tools, output, generated_cpes=generated)
        target = {"target": label, "status": "failed" if problems else "complete", "generated_cpes": generated}
        diagnostics += problems
        targets.append(target)
        if output.is_file() and output.stat().st_size:
            raw_records.append(store.add_file_as_text("scanner-output", label, output, output.name, adapter="grype"))
        if document is None:
            continue
        matches += [normalize_match(match, label, hinted_purls) for match in document["matches"]]
        ignored += len(document.get("ignoredMatches") or [])
    if not plans:
        diagnostics.append(diagnostic("nothing_to_scan", "No versioned component or image inventory was available to scan.", subject="scanner", origin="input"))
    return {"matches": matches, "diagnostics": diagnostics, "targets": targets, "scanner_ignored_matches": ignored, "raw_evidence": raw_records, "not_matchable": not_matchable}
