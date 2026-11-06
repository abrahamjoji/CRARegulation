"""Container evidence through a narrow Syft adapter. No Docker daemon socket is used.

Syft reads an exported archive or pulls from a registry itself. The tool version
and its output schema are pinned together; anything else is reported, not guessed.
"""
import tempfile
from pathlib import Path

from ..common import purl as purls
from ..common.archive import ArchiveLimits, inspect_tar, read_member
from ..common.errors import UntrustedInputError
from ..common.safety import Limits, parse_json_bytes, read_json, run_tool, sha256_file, stable_id, tool_environment

SUPPORTED_SYFT = {"1.57.0"}
SUPPORTED_SYFT_SCHEMA_MAJOR = "16"
MAX_SYFT_OUTPUT = 512 * 1024 * 1024
OUTER_LIMITS = ArchiveLimits(max_members=20000, max_total_bytes=64 * 1024 * 1024 * 1024, max_member_bytes=32 * 1024 * 1024 * 1024)


def inspect_image_archive(path, declared_format):
    """Check the outer tar and read its index before any scanner touches it."""
    members = inspect_tar(path, OUTER_LIMITS)
    if declared_format == "oci-archive":
        if "index.json" not in members or "oci-layout" not in members:
            raise UntrustedInputError("image_archive_invalid", f"{path}: not an OCI layout (needs index.json and oci-layout)")
        index = parse_json_bytes(read_member(path, "index.json"), "index.json")
        manifests = index.get("manifests") if isinstance(index, dict) else None
        if not isinstance(manifests, list) or not manifests or not isinstance(manifests[0], dict):
            raise UntrustedInputError("image_archive_invalid", f"{path}: index.json lists no manifests")
        return {"digest": manifests[0].get("digest") or "", "manifests": len(manifests)}
    if "manifest.json" not in members:
        raise UntrustedInputError("image_archive_invalid", f"{path}: docker-archive needs manifest.json")
    manifest = parse_json_bytes(read_member(path, "manifest.json"), "manifest.json")
    if not isinstance(manifest, list) or not manifest or not isinstance(manifest[0], dict):
        raise UntrustedInputError("image_archive_invalid", f"{path}: manifest.json is empty")
    return {"digest": "", "manifests": len(manifest)}


def tool_versions(tool, limits):
    """Return the version string reported by a tool in JSON form."""
    with tempfile.NamedTemporaryFile(suffix=".json") as output:
        result = run_tool([tool, "version", "-o", "json"], stdout_path=output.name, limits=limits, env=tool_environment({"HOME": "/nonexistent"}))
        if result.missing:
            raise FileNotFoundError(result.stderr)
        if result.returncode or result.timed_out:
            raise UntrustedInputError("tool_version_failed", f"{tool} version failed: {result.stderr[:300]}")
        document = read_json(output.name, 1024 * 1024)
    version = document.get("version") if isinstance(document, dict) else None
    if not isinstance(version, str):
        raise UntrustedInputError("tool_version_failed", f"{tool} version output has no version")
    return version.lstrip("v")


def scheme_argument(image):
    if image.reference:
        return f"registry:{image.reference}"
    return f"{image.format}:{image.archive}"


def run_syft(image, tools, destination):
    limits = Limits(timeout_seconds=tools.timeout_seconds)
    with tempfile.TemporaryDirectory(prefix="cra-syft-") as home:
        env = tool_environment({"HOME": home, "XDG_CACHE_HOME": home, "SYFT_CHECK_FOR_APP_UPDATE": "false",
                                "SYFT_TMP_DIR": home}, tools.env_passthrough)
        return run_tool([tools.syft, "scan", scheme_argument(image), "-o", f"syft-json={destination}", "--scope", "squashed", "-q"],
                        limits=limits, env=env)


def parse_syft(document, image, evidence_id):
    """Validate Syft's output and convert packages into observations."""
    if not isinstance(document, dict) or not isinstance(document.get("artifacts"), list):
        raise UntrustedInputError("syft_output_invalid", "Syft output has no artifacts list")
    descriptor = document.get("descriptor") or {}
    schema = (document.get("schema") or {}).get("version", "")
    source = document.get("source") or {}
    metadata = source.get("metadata") or {} if isinstance(source, dict) else {}
    distro = document.get("distro") or {}
    observations = []
    for package in document["artifacts"]:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise UntrustedInputError("syft_output_invalid", "Syft package without a name")
        parsed = purls.parse(package.get("purl"))
        version = package.get("version") if isinstance(package.get("version"), str) and package.get("version") else None
        ecosystem = parsed["ecosystem"] if parsed else str(package.get("type") or "unknown")
        purl = package.get("purl") if parsed else purls.build(ecosystem, package["name"], version)
        licenses = [item.get("value") for item in package.get("licenses") or [] if isinstance(item, dict) and item.get("value")]
        locations = [item.get("path") for item in package.get("locations") or [] if isinstance(item, dict) and item.get("path")]
        observations.append({
            "id": stable_id("obs", "image", image.id, package.get("id"), package["name"], version),
            "source": f"image:{image.role}", "state": "shipped" if image.role == "final" else "observed", "configuration": None,
            "artifact": image.id, "image_role": image.role,
            "identity": {"ecosystem": ecosystem, "name": package["name"], "version": version, "purl": purl,
                         "supplier": "", "license": " AND ".join(sorted(set(licenses))), "cpes": [item.get("cpe") if isinstance(item, dict) else item for item in package.get("cpes") or []][:8]},
            "scope": "runtime" if image.role == "final" else "build_stage", "linkage": "unknown",
            "location": (locations or ["unknown location"])[0], "evidence": evidence_id, "confidence": "high",
            "attributes": {"found_by": package.get("foundBy"), "package_type": package.get("type"),
                           "distro": f"{distro.get('id')}-{distro.get('versionID')}" if distro.get("id") else None},
        })
    return {"tool_name": descriptor.get("name"), "tool_version": str(descriptor.get("version", "")).lstrip("v"), "schema_version": schema,
            "manifest_digest": metadata.get("manifestDigest") or "", "repo_digests": [str(item) for item in metadata.get("repoDigests") or []], "image_id": metadata.get("imageID") or "",
            "distro": {"id": distro.get("id"), "version": distro.get("versionID")} if distro.get("id") else None,
            "layers": len(metadata.get("layers") or []), "observations": observations}


def collect_image(image, tools, store):
    """Return artifact record, observations, status, reason, tool record."""
    record = {"id": image.id, "kind": "image", "role": image.role, "shipped": image.role == "final",
              "reference": image.reference or "", "path": str(image.archive or ""), "name": image.reference or Path(image.archive).name,
              "format": image.format if image.archive else "registry", "sha256": "", "bytes": 0, "limitations": [],
              "digest": "", "evidence": ""}
    if image.archive:
        if not Path(image.archive).is_file():
            return record, [], "failed", f"image archive not found: {image.archive}", None
        record["sha256"] = sha256_file(image.archive)
        record["bytes"] = Path(image.archive).stat().st_size
        record["digest"] = inspect_image_archive(image.archive, image.format)["digest"]
    try:
        version = tool_versions(tools.syft, Limits(timeout_seconds=60))
    except FileNotFoundError as exc:
        return record, [], "failed", f"Syft is not available: {exc}", None
    tool = {"name": "syft", "version": version, "output_schema": ""}
    if version not in SUPPORTED_SYFT and not tools.allow_unverified_versions:
        return record, [], "unsupported", f"Syft {version} is not a verified version (verified: {sorted(SUPPORTED_SYFT)})", tool
    with tempfile.TemporaryDirectory(prefix="cra-syft-out-") as work:
        output = Path(work) / "syft.json"
        result = run_syft(image, tools, output)
        if result.timed_out:
            return record, [], "failed", f"Syft timed out after {tools.timeout_seconds} s", tool
        if result.returncode or not output.is_file():
            return record, [], "failed", f"Syft exited with {result.returncode}: {result.stderr[:400]}", tool
        raw = output.read_bytes()
        document = read_json(output, MAX_SYFT_OUTPUT)
        evidence = store.add_json("scanner-output", f"image:{image.id}", document, f"image-{image.id}.syft.json", original_bytes=raw, adapter=f"syft {version}")
    parsed = parse_syft(document, image, evidence)
    tool["output_schema"] = parsed["schema_version"]
    record["evidence"] = evidence
    if parsed["schema_version"].split(".")[0] != SUPPORTED_SYFT_SCHEMA_MAJOR and not tools.allow_unverified_versions:
        return record, [], "unsupported", f"Syft output schema {parsed['schema_version']} is not verified", tool
    resolved = parsed["manifest_digest"] or record["digest"]
    record.update(digest=resolved, image_id=parsed["image_id"], distro=parsed["distro"], layers=parsed["layers"])
    if image.reference:
        # The pin may name a multi-platform index; Syft then reports the platform's manifest separately.
        pinned = image.reference.rsplit("@", 1)[1]
        record["requested_digest"] = pinned
        record["repo_digests"] = parsed["repo_digests"]
        if pinned != resolved and not any(item.endswith("@" + pinned) for item in parsed["repo_digests"]):
            return record, [], "failed", f"Syft resolved {resolved or 'unknown'}, which does not match the pinned reference {pinned}", tool
    if image.expected_digest and resolved != image.expected_digest:
        return record, [], "failed", f"resolved digest {resolved or 'unknown'} differs from expected {image.expected_digest}", tool
    if not resolved:
        record["limitations"].append("The image digest could not be resolved; only the archive hash identifies it.")
    if not parsed["observations"]:
        # An empty package list is a finding about detection, not evidence of no dependencies.
        return record, [], "partial", "Syft found no packages; this does not show the image has no dependencies", tool
    if not parsed["distro"]:
        record["limitations"].append("No operating-system identity found, so distribution vulnerability feeds and backport data cannot be applied.")
    return record, parsed["observations"], "complete", "", tool
