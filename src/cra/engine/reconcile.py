"""Reconcile observations into one inventory. Disagreement is kept, never merged away.

The states stay separate on purpose: declared by the project, resolved for a
build, observed in build outputs, and present in the shipped product.
"""
from ..common import purl as purls
from ..common.errors import UntrustedInputError
from ..common.safety import stable_id

INVENTORY_SCHEMA = "cra.inventory/1"
COLLECTION_SCHEMA = "cra.collection/1"
MAX_OBSERVATIONS = 500000
SCOPE_ORDER = ("runtime", "test", "build_tool", "build_stage", "unknown")
LIST_FIELDS = ("sources", "observations", "edges", "artifacts", "targets", "adapters", "vendored_candidates",
               "unresolved_links", "limitations", "diagnostics", "evidence")


def validate_collection(collection):
    """Structural check; collection.json is untrusted when it arrives at the hosted service."""
    if not isinstance(collection, dict) or collection.get("schema_version") != COLLECTION_SCHEMA:
        raise UntrustedInputError("collection_invalid", f"expected schema_version {COLLECTION_SCHEMA}")
    for field in LIST_FIELDS:
        if not isinstance(collection.get(field), list):
            raise UntrustedInputError("collection_invalid", f"collection.{field} must be a list")
    for field in ("product", "source", "collector", "configurations", "covered_vendor_paths"):
        if not isinstance(collection.get(field), dict):
            raise UntrustedInputError("collection_invalid", f"collection.{field} must be an object")
    if len(collection["observations"]) > MAX_OBSERVATIONS:
        raise UntrustedInputError("collection_too_large", "too many observations")
    for observation in collection["observations"]:
        if not isinstance(observation, dict) or not isinstance(observation.get("id"), str) or not isinstance(observation.get("source"), str):
            raise UntrustedInputError("collection_invalid", "every observation needs an id and source")
        identity = observation.get("identity")
        if identity is None:
            continue
        if not isinstance(identity, dict) or not isinstance(identity.get("name"), str) or not isinstance(identity.get("purl"), str):
            raise UntrustedInputError("collection_invalid", f"observation {observation['id']}: identity needs a name and purl")
    for artifact in collection["artifacts"]:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("id"), str):
            raise UntrustedInputError("collection_invalid", "every artifact needs an id")
    for edge in collection["edges"]:
        if not isinstance(edge, dict) or not isinstance(edge.get("from"), str) or not isinstance(edge.get("to"), str):
            raise UntrustedInputError("collection_invalid", "every edge needs from and to")
    return collection


def _new_component(identity):
    key = purls.strip(identity["purl"])
    return {"id": f"comp:{key}", "identity": {"name": identity["name"], "version": identity.get("version"),
                                              "ecosystem": identity.get("ecosystem") or "unknown", "purl": key,
                                              "licenses": [], "suppliers": [], "cpes": []},
            "presence": {"declared": False, "resolved": False, "observed": False, "shipped": "unknown", "shipped_rationale": []},
            "scope": "unknown", "linkage": [], "configurations": {}, "artifacts": [], "observations": [],
            "attributes": {}, "uncertainty": [], "patch_claims": []}


def _apply(component, observation):
    identity = observation["identity"]
    data = component["identity"]
    for field, target in (("license", "licenses"), ("supplier", "suppliers")):
        value = identity.get(field)
        if value and value not in data[target]:
            data[target].append(value)
    for cpe in identity.get("cpes") or []:
        if cpe and cpe not in data["cpes"]:
            data["cpes"].append(cpe)
    state = observation.get("state")
    presence = component["presence"]
    if state == "declared":
        presence["declared"] = True
    elif state == "resolved":
        presence["resolved"] = True
    elif state in ("observed", "shipped"):
        presence["observed"] = True
    if observation["id"] not in component["observations"]:
        component["observations"].append(observation["id"])
    linkage = observation.get("linkage")
    if linkage and linkage != "unknown" and linkage not in component["linkage"]:
        component["linkage"].append(linkage)
    artifact = observation.get("artifact")
    if artifact and artifact not in component["artifacts"]:
        component["artifacts"].append(artifact)
    configuration = observation.get("configuration")
    if configuration:
        row = component["configurations"].setdefault(configuration, {"states": [], "scopes": [], "attributes": {}})
        if state not in row["states"]:
            row["states"].append(state)
        if observation.get("scope") and observation["scope"] not in row["scopes"]:
            row["scopes"].append(observation["scope"])
        attributes = observation.get("attributes") or {}
        if observation.get("source") == "conan" and state == "resolved":
            row["attributes"] = {key: attributes.get(key) for key in ("context", "package_type", "binary", "recipe_revision", "package_id", "package_revision", "options", "settings")}
            component["attributes"].setdefault("libraries", [])
            for library in attributes.get("libraries") or []:
                if library not in component["attributes"]["libraries"]:
                    component["attributes"]["libraries"].append(library)
    patched = (observation.get("attributes") or {}).get("patched") or []
    component["patch_claims"] += [item for item in patched if item not in component["patch_claims"]]
    current = component["scope"]
    new = observation.get("scope") or "unknown"
    if new in SCOPE_ORDER and SCOPE_ORDER.index(new) < SCOPE_ORDER.index(current):
        component["scope"] = new


def _candidates(components, name, configuration):
    """Non-generic components with this upstream name, preferring the same configuration."""
    lowered = name.lower()
    found = [item for item in components.values() if item["identity"]["name"].lower() == lowered and item["identity"]["ecosystem"] != "generic"]
    if configuration:
        same = [item for item in found if configuration in item["configurations"]]
        return same or found
    return found


def reconcile(collection):
    """Build the inventory from a validated collection."""
    validate_collection(collection)
    components, conflicts, unresolved = {}, [], []
    observations = collection["observations"]
    deferred = []
    for observation in observations:
        identity = observation.get("identity")
        if identity is None:
            continue
        version_less_declaration = observation.get("source") == "manifest" and not identity.get("version")
        if observation.get("upstream_name") or version_less_declaration:
            deferred.append(observation)
            continue
        component = components.setdefault(purls.strip(identity["purl"]), _new_component(identity))
        _apply(component, observation)

    # Generic evidence (version strings, customer records, ranges) attaches only when it agrees.
    for observation in deferred:
        identity = observation["identity"]
        name = observation.get("upstream_name") or identity["name"]
        candidates = _candidates(components, name, observation.get("configuration"))
        same_version = [item for item in candidates if identity.get("version") and item["identity"]["version"] == identity["version"]]
        if observation.get("ambiguous_group"):
            component = components.setdefault(purls.strip(identity["purl"]), _new_component(identity))
            _apply(component, observation)
        elif same_version:
            _apply(same_version[0], observation)
        elif candidates and not identity.get("version"):
            if len(candidates) == 1:
                _apply(candidates[0], observation)
            else:
                conflicts.append({"kind": "ambiguous_attachment", "subject": name, "values": sorted(item["id"] for item in candidates),
                                  "observations": [observation["id"]], "detail": f"{observation['source']} names {name} without a version, and several components match."})
        else:
            component = components.setdefault(purls.strip(identity["purl"]), _new_component(identity))
            _apply(component, observation)
            if candidates:
                conflicts.append({"kind": "version_disagreement", "subject": name,
                                  "values": sorted({str(identity.get("version"))} | {str(item["identity"]["version"]) for item in candidates}),
                                  "observations": [observation["id"]] + [oid for item in candidates for oid in item["observations"][:3]],
                                  "detail": f"{observation['source']} ({observation.get('location')}) disagrees with {', '.join(item['id'] for item in candidates)}. Both are kept."})

    # Ambiguous identities stay visible as separate components.
    groups = {}
    for observation in observations:
        if observation.get("ambiguous_group") and observation.get("identity"):
            groups.setdefault(observation["ambiguous_group"], set()).add(purls.strip(observation["identity"]["purl"]))
    for group, keys in sorted(groups.items()):
        conflicts.append({"kind": "ambiguous_identity", "subject": group, "values": sorted(keys), "observations": [],
                          "detail": "The customer record lists several candidate identities. All are scanned until one is confirmed."})
        for key in keys:
            components[key]["uncertainty"].append(f"Identity is ambiguous between {', '.join(sorted(keys))}.")

    # Same package with different versions: a conflict within a build, a variant across builds.
    by_name = {}
    for component in components.values():
        if component["identity"]["ecosystem"] != "generic" or component["presence"]["resolved"]:
            by_name.setdefault((component["identity"]["ecosystem"], component["identity"]["name"]), []).append(component)
    for (ecosystem, name), group in sorted(by_name.items()):
        versions = {str(item["identity"]["version"]) for item in group}
        if len(versions) < 2:
            continue
        shared = set.intersection(*[set(item["configurations"]) for item in group]) if all(item["configurations"] for item in group) else set()
        if shared:
            states = {state for item in group for cfg in shared for state in item["configurations"][cfg]["states"]}
            kind = "declared_resolved_mismatch" if states <= {"declared", "resolved"} else "multiple_versions_in_configuration"
            conflicts.append({"kind": kind, "subject": f"{ecosystem}/{name}", "values": sorted(versions),
                              "observations": [oid for item in group for oid in item["observations"][:3]],
                              "detail": f"Several versions were seen in configuration {', '.join(sorted(shared))}."})
        else:
            conflicts.append({"kind": "version_varies", "subject": f"{ecosystem}/{name}", "values": sorted(versions),
                              "observations": [], "detail": "Versions differ between configurations or images. This can be expected."})

    # Metadata disagreements on a single component.
    for component in components.values():
        for field, label in (("licenses", "license"), ("suppliers", "supplier")):
            values = component["identity"][field]
            if len(values) > 1:
                conflicts.append({"kind": f"{label}_disagreement", "subject": component["id"], "values": sorted(values),
                                  "observations": component["observations"][:6], "detail": f"Sources report different {label} values. All are kept."})

    _link_needed(observations, components, unresolved)
    _shipping(collection, components)
    for conflict in conflicts:
        if conflict["kind"] in ("version_disagreement", "multiple_versions_in_configuration"):
            for value in components.values():
                if value["identity"]["name"].lower() == conflict["subject"].split("/")[-1].lower():
                    value["uncertainty"].append(f"Sources disagree on the version: {', '.join(conflict['values'])}.")

    relationships = _relationships(collection, components)
    coverage = _coverage(collection, components, unresolved, conflicts)
    ordered = sorted(components.values(), key=lambda item: item["id"])
    return {
        "schema_version": INVENTORY_SCHEMA,
        "product": collection["product"], "source": collection["source"], "collector": collection["collector"],
        "configurations": collection["configurations"], "adapters": collection["adapters"],
        "artifacts": collection["artifacts"], "components": ordered, "relationships": relationships,
        "targets": collection["targets"], "conflicts": conflicts, "unresolved_observations": unresolved,
        "coverage": coverage, "evidence": collection["evidence"],
        "observation_index": {item["id"]: {key: item.get(key) for key in ("source", "state", "configuration", "location", "evidence", "confidence", "artifact")}
                              for item in observations},
    }


def _link_needed(observations, components, unresolved):
    """Resolve DT_NEEDED sonames through the library names Conan reports for the same build."""
    for observation in observations:
        if observation.get("source") != "artifact-needed":
            continue
        soname = observation.get("soname") or ""
        base = soname.split(".so")[0]
        matched = []
        for component in components.values():
            libraries = component["attributes"].get("libraries") or []
            if observation.get("configuration") in component["configurations"] and any(f"lib{library}" == base for library in libraries):
                matched.append(component)
        if len(matched) == 1:
            matched[0]["observations"].append(observation["id"])
            matched[0]["presence"]["observed"] = True
            if observation.get("artifact") and observation["artifact"] not in matched[0]["artifacts"]:
                matched[0]["artifacts"].append(observation["artifact"])
            if "shared" not in matched[0]["linkage"]:
                matched[0]["linkage"].append("shared")
        else:
            unresolved.append({"kind": "native_dependency_without_identity", "value": soname, "artifact": observation.get("artifact"),
                               "configuration": observation.get("configuration"), "observation": observation["id"],
                               "detail": "A shared library was needed, but no package in this build's evidence provides it." if not matched
                               else "Several packages could provide this shared library."})


def _shipping(collection, components):
    """Decide shipped yes, no or unknown, and say why. Absence of evidence stays unknown."""
    artifacts = {item["id"]: item for item in collection["artifacts"]}
    observation_by_id = {item["id"]: item for item in collection["observations"]}
    shipped_outputs = {item["path"]: item for item in collection["artifacts"] if item.get("kind") == "file" and item.get("shipped")}
    final_complete = any(row.get("role") == "final" and row.get("status") == "complete" for row in collection["sources"] if row.get("source") in ("image", "directory"))
    vendored = _vendored_shipping(collection, shipped_outputs)
    for component in components.values():
        reasons_yes, reasons_no = [], []
        for observation_id in component["observations"]:
            observation = observation_by_id.get(observation_id)
            if observation is None:
                continue
            source = observation.get("source")
            artifact = artifacts.get(observation.get("artifact")) or {}
            if observation.get("state") == "shipped":
                reasons_yes.append(f"Detected in final deployment inventory {observation.get('artifact')} at {observation.get('location')}.")
            elif source == "python-inspect" and observation.get("shipped_claim") is True:
                reasons_yes.append("Customer identifies this inspected Python environment as shipped; installed distribution metadata was observed.")
            elif source == "artifact-signature" and artifact.get("shipped"):
                reasons_yes.append(f"Version string found in shipped artifact {artifact['id']}.")
            elif source == "artifact-needed" and artifact.get("shipped"):
                reasons_yes.append(f"Shipped artifact {artifact['id']} needs {observation.get('soname')} at run time.")
            elif source == "cmake":
                hits = [shipped_outputs[path]["id"] for path in (observation.get("attributes") or {}).get("outputs", []) if path in shipped_outputs]
                via = (observation.get("attributes") or {}).get("via")
                if hits:
                    if hits[0] not in component["artifacts"]:
                        component["artifacts"].append(hits[0])
                    word = "linked into" if via == "link_path" else "compiled against by"
                    reasons_yes.append(f"CMake shows it {word} target {(observation.get('attributes') or {}).get('target')}, which produces shipped artifact {hits[0]}.")
            elif source == "customer-record":
                claim = observation.get("shipped_claim")
                if claim is True:
                    reasons_yes.append("Customer record states it ships (a claim, not verified).")
                elif claim is False:
                    reasons_no.append("Customer record states it does not ship (a claim, not verified).")
            if source == "customer-record":
                for path in (observation.get("attributes") or {}).get("source_paths") or []:
                    for artifact_id, target in vendored.get(str(path).rstrip("/"), []):
                        reasons_yes.append(f"CMake builds its source path {path} into target {target}, which contributes to shipped artifact {artifact_id}.")
                        if artifact_id not in component["artifacts"]:
                            component["artifacts"].append(artifact_id)
        scopes = {scope for row in component["configurations"].values() for scope in row["scopes"]} | {component["scope"]}
        presence = component["presence"]
        if reasons_yes:
            presence["shipped"], presence["shipped_rationale"] = "yes", sorted(set(reasons_yes))
        elif reasons_no:
            presence["shipped"], presence["shipped_rationale"] = "no", reasons_no
        elif scopes <= {"build_tool", "test", "unknown"} and scopes & {"build_tool", "test"}:
            presence["shipped"] = "no"
            presence["shipped_rationale"] = ["Conan classifies it as a build tool or test requirement, and no shipped evidence contradicts that."]
        elif component["scope"] == "build_stage":
            presence["shipped"] = "no" if final_complete else "unknown"
            presence["shipped_rationale"] = ["Seen only in a build-stage image, and the final image inventory does not contain it." if final_complete
                                             else "Seen only in a build-stage image, and no complete final image inventory exists."]
        else:
            presence["shipped"] = "unknown"
            presence["shipped_rationale"] = ["Resolved or declared, but no evidence shows it in a shipped output. Runtime loading or an unselected artifact could still include it."]


def _vendored_shipping(collection, shipped_outputs):
    """Map vendored source paths to shipped artifacts through in-tree target dependencies."""
    mapping = {}
    for candidate in collection["vendored_candidates"]:
        if not isinstance(candidate, dict):
            continue
        for target in collection["targets"]:
            if not isinstance(target, dict) or target.get("configuration") != candidate.get("configuration"):
                continue
            names = set(candidate.get("targets") or [])
            if target.get("name") in names or names & set(target.get("in_tree_dependencies") or []):
                for output in target.get("outputs") or []:
                    if output in shipped_outputs:
                        mapping.setdefault(str(candidate.get("path")), []).append((shipped_outputs[output]["id"], target.get("name")))
    return mapping


def _relationships(collection, components):
    seen, relationships = set(), []
    for edge in collection["edges"]:
        key = (edge["from"], edge["to"], edge.get("kind"), edge.get("configuration"))
        if key in seen:
            continue
        seen.add(key)
        relationships.append({"from": "product" if edge["from"] == "product" else f"comp:{purls.strip(edge['from'])}",
                              "to": f"comp:{purls.strip(edge['to'])}", "kind": edge.get("kind", "requires"),
                              "direct": bool(edge.get("direct")), "configuration": edge.get("configuration"),
                              "evidence": edge.get("evidence", ""), "attributes": edge.get("attributes") or {}})
    for component in components.values():
        for artifact in component["artifacts"]:
            relationships.append({"from": f"artifact:{artifact}", "to": component["id"], "kind": "contains", "direct": True,
                                  "configuration": None, "evidence": "", "attributes": {}})
    return relationships


def _coverage(collection, components, unresolved, conflicts):
    """Decide completeness from facts. Silence from a detector is never counted as clean."""
    reasons, limitations = [], list(collection["limitations"])
    for row in collection["sources"]:
        if row.get("status") == "complete" or row.get("status") == "not_configured":
            continue
        if row.get("required", True):
            reasons.append({"code": f"source_{row.get('status')}", "subject": f"{row.get('source')}:{row.get('subject')}", "message": row.get("reason") or "source did not complete"})
        else:
            limitations.append({"subject": f"{row.get('source')}:{row.get('subject')}", "source": row.get("source"), "message": row.get("reason", "")})
    if not components:
        reasons.append({"code": "inventory_empty", "subject": "inventory", "message": "No components were identified. This is a detection result, not evidence of no dependencies."})
    for component in components.values():
        if not component["identity"]["version"] and component["presence"]["shipped"] != "no":
            reasons.append({"code": "unknown_version", "subject": component["id"], "message": f"{component['identity']['name']} has no version, so vulnerability matching cannot work for it."})
    for observation in collection["observations"]:
        attributes = observation.get("attributes") or {}
        if attributes.get("generated") is True and not attributes.get("reviewed_by"):
            reasons.append({"code": "generated_record_unreviewed", "subject": observation["id"],
                            "message": "Generated component identity/scope needs human review in the records file."})
    covered = collection["covered_vendor_paths"]
    for candidate in collection["vendored_candidates"]:
        if isinstance(candidate, dict) and not any(str(candidate.get("path", "")).endswith(path) or path.endswith(str(candidate.get("path", ""))) for path in covered):
            reasons.append({"code": "vendored_source_unidentified", "subject": str(candidate.get("path")), "message": f"Source under {candidate.get('path')} looks vendored and no component record names it."})
    for artifact in collection["artifacts"]:
        limitations += [{"subject": artifact["id"], "source": "artifact", "message": message} for message in artifact.get("limitations") or []]
    if unresolved:
        limitations.append({"subject": "inventory", "source": "reconcile",
                            "message": f"{len(unresolved)} native dependencies or link items have no package identity. See unresolved_observations."})
    return {"status": "incomplete" if reasons else "complete", "incomplete_reasons": reasons, "sources": collection["sources"],
            "limitations": limitations, "unresolved_count": len(unresolved), "conflict_count": len(conflicts),
            "scope_note": "Complete means every configured source finished. It does not mean every dependency in the product was discovered."}


def component_lookup(inventory):
    return {item["identity"]["purl"]: item for item in inventory["components"]}


def dependency_paths(inventory, component_id, limit=3):
    """Shortest requirement paths from the product, per configuration."""
    edges = {}
    for relation in inventory["relationships"]:
        if relation["kind"] != "contains":
            edges.setdefault((relation.get("configuration"), relation["from"]), []).append(relation["to"])
    paths = []
    for configuration in sorted(inventory["configurations"]):
        queue, seen = [("product", ["product"])], {"product"}
        while queue:
            node, path = queue.pop(0)
            if node == component_id:
                paths.append({"configuration": configuration, "path": path})
                break
            for target in sorted(edges.get((configuration, node), [])):
                if target not in seen:
                    seen.add(target)
                    queue.append((target, path + [target]))
    for relation in inventory["relationships"]:
        if relation["kind"] == "contains" and relation["to"] == component_id:
            paths.append({"configuration": None, "path": [relation["from"], component_id]})
    return paths[:limit + 2]


def export_cyclonedx(inventory, *, only_for_scan=False):
    """CycloneDX 1.5 export. only_for_scan leaves out unversioned and image-only components."""
    observations = inventory["observation_index"]
    components = []
    for component in inventory["components"]:
        identity = component["identity"]
        sources = {observations[oid]["source"] for oid in component["observations"] if oid in observations}
        if only_for_scan and (not identity["version"] or all(source.startswith(("image:", "directory:")) for source in sources)):
            continue
        record = {"type": "library", "bom-ref": component["id"], "name": identity["name"], "purl": identity["purl"],
                  "properties": [{"name": "cra:shipped", "value": component["presence"]["shipped"]}, {"name": "cra:scope", "value": component["scope"]}]}
        if identity["version"]:
            record["version"] = identity["version"]
        cpe = identity["cpes"][0] if identity["cpes"] else None
        if cpe:
            record["cpe"] = cpe
        if identity["licenses"]:
            record["licenses"] = [{"license": {"name": value}} for value in identity["licenses"]]
        if identity["suppliers"]:
            record["supplier"] = {"name": identity["suppliers"][0]}
        components.append(record)
    known = {item["bom-ref"] for item in components}
    dependencies = {}
    for relation in inventory["relationships"]:
        if relation["from"] in known and relation["to"] in known and relation["kind"] != "contains":
            dependencies.setdefault(relation["from"], set()).add(relation["to"])
    product = inventory["product"]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": f"urn:uuid:{_uuid_like(stable_id('sbom', inventory['source'].get('revision'), product.get('name'), product.get('version')))}",
            "metadata": {"component": {"type": "application", "name": product.get("name", ""), "version": product.get("version", "")}},
            "components": components,
            "dependencies": [{"ref": key, "dependsOn": sorted(value)} for key, value in sorted(dependencies.items())]}


def _uuid_like(value):
    digest = value.split("-", 1)[1].ljust(32, "0")
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-a{digest[17:20]}-{digest[20:32]}"
