"""Customer-supplied records for components that tools cannot identify."""
from ..common import purl as purls
from ..common.errors import ConfigError, UntrustedInputError
from ..common.schema import validate
from ..common.safety import stable_id, text_field
from ..common.mappings import valid_cpe

SCHEMA = "cra.component-records/1"
ALLOWED = {"name", "version", "purl", "cpes", "supplier", "license", "scope", "linkage", "shipped", "configurations", "source_paths",
           "patched", "candidates", "note", "reviewed_by", "generated", "provenance", "patch_builds", "notes"}
SCOPES = ("runtime", "build_tool", "test", "unknown")


def parse_records(document, evidence_id):
    """Validate records. A record is a customer's claim and is labelled as one."""
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA or not isinstance(document.get("components"), list):
        raise UntrustedInputError("records_invalid", f"component records need schema_version {SCHEMA} and a components list")
    try:
        validate(document, "component-records.schema.json")
    except ConfigError as exc:
        raise UntrustedInputError("records_invalid", str(exc)) from exc
    observations, covered = [], {}
    for position, item in enumerate(document["components"]):
        where = f"components[{position}]"
        if not isinstance(item, dict):
            raise UntrustedInputError("records_invalid", f"{where} must be an object")
        unknown = set(item) - ALLOWED
        if unknown:
            raise UntrustedInputError("records_invalid", f"{where}: unknown keys {sorted(unknown)}")
        name = text_field(item.get("name"), f"{where}.name", max_length=256)
        scope = item.get("scope", "unknown")
        if scope not in SCOPES:
            raise UntrustedInputError("records_invalid", f"{where}.scope must be one of {SCOPES}")
        generated_unreviewed = item.get("generated") is True and not item.get("reviewed_by", "").strip()
        for path in ([] if generated_unreviewed else item.get("source_paths", [])):
            covered[str(path).rstrip("/")] = name
        patched = item.get("patched", [])
        if not isinstance(patched, list) or not all(isinstance(p, dict) and isinstance(p.get("vulnerability"), str) for p in patched):
            raise UntrustedInputError("records_invalid", f"{where}.patched must list objects with a vulnerability")
        candidates = item.get("candidates")
        variants = candidates if candidates else [item]
        if not isinstance(variants, list):
            raise UntrustedInputError("records_invalid", f"{where}.candidates must be a list")
        for variant in variants:
            if not isinstance(variant, dict):
                raise UntrustedInputError("records_invalid", f"{where}: every candidate must be an object")
            version = variant.get("version")
            version = text_field(version, f"{where}.version", max_length=256) if version not in (None, "") else None
            given = variant.get("purl")
            parsed = purls.parse(given) if given else None
            if given and not parsed:
                raise UntrustedInputError("records_invalid", f"{where}.purl is not a package URL: {given!r}")
            if parsed and version and parsed["version"] and parsed["version"] != version:
                raise UntrustedInputError("records_invalid", f"{where}.version disagrees with its purl")
            ecosystem = parsed["ecosystem"] if parsed else "generic"
            purl = purls.strip(given) if given else purls.build("generic", variant.get("name", name), version)
            cpes = variant.get("cpes", item.get("cpes", []))
            if not isinstance(cpes, list) or not all(isinstance(c, str) and valid_cpe(c) for c in cpes):
                raise UntrustedInputError("records_invalid", f"{where}.cpes must be CPE 2.3 strings")
            configurations = item.get("configurations") or [None]
            for configuration in configurations:
                observations.append({
                    "id": stable_id("obs", "record", name, purl, configuration), "source": "customer-record",
                    "state": "observed", "configuration": configuration,
                    "identity": {"ecosystem": ecosystem, "name": variant.get("name", name), "version": version, "purl": purl,
                                 "supplier": item.get("supplier", ""), "license": item.get("license", ""), "cpes": cpes},
                    "upstream_name": variant.get("name", name), "scope": "unknown" if generated_unreviewed and scope in ("test", "build_tool") else scope, "linkage": item.get("linkage", "unknown"),
                    "location": f"component record {name}", "evidence": evidence_id, "confidence": "claim",
                    "shipped_claim": None if generated_unreviewed else item.get("shipped"), "ambiguous_group": name if candidates else None,
                    "attributes": {"note": item.get("note", ""), "reviewed_by": item.get("reviewed_by", ""),
                                   "patched": patched, "source_paths": [] if generated_unreviewed else item.get("source_paths", []),
                                   "generated": item.get("generated", False), "provenance": item.get("provenance", {}),
                                   "patch_builds": item.get("patch_builds", []), "notes": item.get("notes", "")},
                })
    return observations, covered
