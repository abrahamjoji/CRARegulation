"""Read pip inspect v1 from the actual Python environment; never import customer code."""
import re

from ..common import purl as purls
from ..common.errors import UntrustedInputError
from ..common.safety import stable_id, text_field

NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")


def normalized_name(name):
    if not isinstance(name, str) or not NAME.fullmatch(name) or len(name) > 256:
        raise UntrustedInputError("pip_inspect_invalid", "invalid Python distribution name")
    return re.sub(r"[-_.]+", "-", name).lower()


def collect_inspect(document, configuration, evidence):
    if not isinstance(document, dict) or document.get("version") != "1":
        raise UntrustedInputError("pip_inspect_invalid", "expected pip inspect schema version '1'")
    packages = document.get("installed")
    if not isinstance(packages, list) or len(packages) > 100000:
        raise UntrustedInputError("pip_inspect_invalid", "installed must be a bounded list of distributions")
    environment = document.get("environment")
    if not isinstance(environment, dict) or any(not isinstance(value, str) for value in environment.values()):
        raise UntrustedInputError("pip_inspect_invalid", "environment must be an object with string values")
    observations, edges, identities, requirements = [], [], {}, {}
    for package in packages:
        metadata = package.get("metadata") if isinstance(package, dict) else None
        if not isinstance(metadata, dict):
            raise UntrustedInputError("pip_inspect_invalid", "every installed item needs metadata")
        name = normalized_name(metadata.get("name"))
        version = text_field(metadata.get("version"), f"{name}.version", max_length=256)
        if name in identities:
            raise UntrustedInputError("pip_inspect_invalid", f"duplicate installed distribution: {name}")
        purl = purls.build("pypi", name, version)
        identities[name] = purl
        requires = metadata.get("requires_dist", [])
        if not isinstance(requires, list) or len(requires) > 10000 or any(not isinstance(item, str) or len(item) > 4096 for item in requires):
            raise UntrustedInputError("pip_inspect_invalid", f"{name}.requires_dist must be a bounded list of strings")
        requirements[name] = requires
        location = package.get("metadata_location", "installed distribution metadata")
        if not isinstance(location, str):
            raise UntrustedInputError("pip_inspect_invalid", "metadata_location must be a string")
        requested = package.get("requested")
        if requested is not None and not isinstance(requested, bool):
            raise UntrustedInputError("pip_inspect_invalid", "requested must be a boolean when present")
        direct_url = package.get("direct_url")
        observations.append({
            "id": stable_id("obs", "python-inspect", configuration.id, purl),
            "source": "python-inspect", "state": "observed", "configuration": configuration.id,
            "identity": {"name": name, "version": version, "ecosystem": "pypi", "purl": purl,
                         "supplier": "", "license": str(metadata.get("license_expression") or metadata.get("license") or "")[:4096], "cpes": []},
            "scope": configuration.pip_inspect_scope, "linkage": "python-distribution",
            "location": location, "evidence": evidence, "confidence": "high",
            "shipped_claim": configuration.pip_inspect_shipped,
            "attributes": {"requires_dist": requires, "requested": requested, "installer": package.get("installer"),
                           "direct_url": direct_url, "environment": environment,
                           "identity_note": "Distribution metadata; upstream identity and vendor modifications are not independently verified."},
        })
        if requested:
            edges.append({"from": "product", "to": purl, "kind": "requires", "configuration": configuration.id,
                          "direct": True, "evidence": evidence})
    conditional, missing, direct = 0, [], 0
    for name, entries in requirements.items():
        for requirement in entries:
            match = REQUIREMENT_NAME.match(requirement)
            if not match:
                raise UntrustedInputError("pip_inspect_invalid", f"{name}: malformed requirement")
            target = normalized_name(match.group(1))
            suffix = match.group(2)
            # Extras and markers require resolution evidence. Preserve text; do not guess an edge.
            if ";" in suffix or "[" in suffix:
                conditional += 1
                continue
            if target not in identities:
                missing.append(f"{name} requires {target}, which is absent from the inspected environment")
                continue
            edges.append({"from": identities[name], "to": identities[target], "kind": "requires",
                          "configuration": configuration.id, "direct": False, "evidence": evidence,
                          "attributes": {"declared_requirement": requirement, "constraints_verified": False}})
    for row in observations:
        if row["attributes"]["direct_url"]:
            direct += 1
    limitations = []
    if conditional:
        limitations.append(f"{conditional} conditional/extra requirements are retained but not evaluated; dependency paths may be incomplete.")
    if direct:
        limitations.append(f"{direct} direct/editable installs use declared distribution identity; forks and local changes are not independently identified.")
    limitations.append("Dependency version constraints are retained but not verified; this is not a pip check or dependency resolver.")
    limitations.append("Installed distributions are not import reachability evidence; native dependencies of Python extensions need artifact or image evidence.")
    problems = missing or ([] if packages else ["pip inspect lists no distributions; dependency coverage is unknown"])
    return {"observations": observations, "edges": edges, "problems": problems, "limitations": limitations,
            "build": {"pip_version": document.get("pip_version"), "schema_version": "1", "environment": environment,
                      "shipped_claim": configuration.pip_inspect_shipped}}
