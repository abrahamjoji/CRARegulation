"""CMake File API evidence.

Target names and link flags are evidence of what the build used. They are not an
upstream package identity. A link path only becomes an identity when it falls
inside a package folder that the Conan graph for the same configuration names.
"""
import re
from pathlib import Path, PurePosixPath

from ..common.errors import UntrustedInputError
from ..common.safety import read_json, stable_id

SUPPORTED_CODEMODEL_MAJOR = 2
MAX_REPLY_FILE = 32 * 1024 * 1024
MAX_TARGETS = 5000
_VENDOR_DIRS = {"third_party", "thirdparty", "3rdparty", "vendor", "vendored", "external", "extern", "deps"}
# Cache values can hold credentials and are not needed beyond these names.
KEPT_CACHE = re.compile(r"^(CMAKE_BUILD_TYPE|CMAKE_TOOLCHAIN_FILE|CMAKE_C(XX)?_COMPILER|CMAKE_SYSTEM_NAME|CMAKE_GENERATOR|[A-Za-z0-9_]+_DIR)$")
FLAG_LIBRARY = re.compile(r"^-l(?P<name>[A-Za-z0-9_.+-]+)$")


def _reply_dir(build_dir):
    return Path(build_dir) / ".cmake" / "api" / "v1" / "reply"


def _safe_reply(reply, name):
    """A reply file is named by the reply index, which is customer-controlled input."""
    if not isinstance(name, str) or "/" in name or "\\" in name or name in (".", ".."):
        raise UntrustedInputError("cmake_reply_invalid", f"unsafe reply file name: {name!r}")
    return read_json(reply / name, MAX_REPLY_FILE)


def find_index(build_dir):
    """Return the newest index file, or None. CMake writes names that sort by time."""
    reply = _reply_dir(build_dir)
    if not reply.is_dir():
        return None
    candidates = sorted(reply.glob("index-*.json"))
    return candidates[-1] if candidates else None


def missed_prepare_message(build_dir):
    build_dir = Path(build_dir)
    query = build_dir / ".cmake" / "api" / "v1" / "query" / "client-cra" / "query.json"
    if not build_dir.exists():
        return f"build directory {build_dir} does not exist; run the build before cra collect"
    if not query.exists():
        return ("no CMake File API query was registered: run `cra prepare` before CMake configures this "
                "build tree, then configure again")
    return "the query is registered but CMake has not answered it: run CMake configure again after `cra prepare`"


def _inside(path, folders):
    """Longest package folder containing path, compared lexically on absolute paths."""
    if not path.startswith("/"):
        return None
    candidate = PurePosixPath(path)
    best = None
    for folder in folders:
        try:
            candidate.relative_to(folder)
        except ValueError:
            continue
        if best is None or len(folder) > len(best):
            best = folder
    return best


def _fragment_paths(fragment):
    value = fragment.get("fragment") if isinstance(fragment, dict) else None
    if not isinstance(value, str):
        return []
    return [part for part in value.strip().split() if part]


def read_reply(index_path):
    """Load the reply tree into plain structures, validating shape and bounds."""
    reply = index_path.parent
    index = read_json(index_path, MAX_REPLY_FILE)
    objects = index.get("objects") if isinstance(index, dict) else None
    if not isinstance(objects, list):
        raise UntrustedInputError("cmake_reply_invalid", "reply index has no objects list")
    codemodel_entry, cache_entry, toolchains_entry = None, None, None
    for entry in objects:
        if not isinstance(entry, dict):
            continue
        version = entry.get("version") or {}
        if entry.get("kind") == "codemodel" and version.get("major") == SUPPORTED_CODEMODEL_MAJOR:
            codemodel_entry = entry
        elif entry.get("kind") == "cache":
            cache_entry = entry
        elif entry.get("kind") == "toolchains":
            toolchains_entry = entry
    if codemodel_entry is None:
        raise UntrustedInputError("cmake_reply_unsupported", f"reply has no codemodel v{SUPPORTED_CODEMODEL_MAJOR}")
    codemodel = _safe_reply(reply, codemodel_entry.get("jsonFile"))
    files = {"index": index, "codemodel": codemodel, "targets": {}}
    if cache_entry:
        files["cache"] = _safe_reply(reply, cache_entry.get("jsonFile"))
    if toolchains_entry:
        files["toolchains"] = _safe_reply(reply, toolchains_entry.get("jsonFile"))
    count = 0
    for configuration in codemodel.get("configurations") or []:
        for target in configuration.get("targets") or []:
            count += 1
            if count > MAX_TARGETS:
                raise UntrustedInputError("cmake_reply_too_large", f"more than {MAX_TARGETS} targets in the reply")
            files["targets"][target.get("jsonFile")] = _safe_reply(reply, target.get("jsonFile"))
    return files


def _select_configuration(codemodel, wanted):
    configurations = codemodel.get("configurations")
    if not isinstance(configurations, list) or not configurations:
        raise UntrustedInputError("cmake_reply_invalid", "codemodel lists no configurations")
    if wanted:
        for configuration in configurations:
            if configuration.get("name") == wanted:
                return configuration
        names = [item.get("name") for item in configurations]
        raise UntrustedInputError("cmake_config_missing", f"CMake configuration {wanted!r} not in the reply (found {names})")
    if len(configurations) > 1:
        raise UntrustedInputError("cmake_config_ambiguous", "this multi-config reply needs cmake_config set in cra.toml")
    return configurations[0]


def analyze_reply(files, configuration_id, wanted_config, folders, evidence_id, build_dir):
    """Build target facts plus observations linking Conan packages to targets."""
    selected = _select_configuration(files["codemodel"], wanted_config)
    by_id, targets = {}, []
    for entry in selected.get("targets") or []:
        data = files["targets"].get(entry.get("jsonFile"))
        if isinstance(data, dict):
            by_id[entry.get("id")] = data

    observations, unresolved, vendored = [], [], {}
    target_links = {}
    for identifier, data in by_id.items():
        name = data.get("name", "")
        links = {}
        for fragment in ((data.get("link") or {}).get("commandFragments") or []) + ((data.get("archive") or {}).get("commandFragments") or []):
            if not isinstance(fragment, dict) or fragment.get("role") != "libraries":
                continue
            for part in _fragment_paths(fragment):
                if part.startswith("-Wl,"):
                    continue
                folder = _inside(part, folders)
                if folder:
                    linkage = "static" if part.endswith(".a") else "shared" if ".so" in PurePosixPath(part).name else "unknown"
                    links[folders[folder]["purl"]] = {"identity": folders[folder], "via": "link_path", "linkage": linkage, "path": part}
                elif FLAG_LIBRARY.match(part) or part.startswith("/"):
                    unresolved.append({"target": name, "fragment": part})
        for group in data.get("compileGroups") or []:
            for include in (group.get("includes") or []) if isinstance(group, dict) else []:
                folder = _inside(include.get("path", "") if isinstance(include, dict) else "", folders)
                if folder and folders[folder]["purl"] not in links:
                    links[folders[folder]["purl"]] = {"identity": folders[folder], "via": "include_path", "linkage": "header", "path": include["path"]}
        target_links[identifier] = links
        for source in data.get("sources") or []:
            path = source.get("path", "") if isinstance(source, dict) else ""
            parts = PurePosixPath(path).parts if isinstance(path, str) else ()
            for position, part in enumerate(parts[:-1]):
                if part.lower() in _VENDOR_DIRS and position + 1 < len(parts) - 1:
                    vendored.setdefault("/".join(parts[:position + 2]), set()).add(name)
                    break

    def closure(identifier, seen):
        """Static in-tree libraries are part of the consumer; shared ones ship separately."""
        result = dict(target_links.get(identifier, {}))
        for dependency in by_id.get(identifier, {}).get("dependencies") or []:
            child = dependency.get("id") if isinstance(dependency, dict) else None
            if child in by_id and child not in seen and by_id[child].get("type") in ("STATIC_LIBRARY", "OBJECT_LIBRARY", "INTERFACE_LIBRARY"):
                seen.add(child)
                for key, value in closure(child, seen).items():
                    result.setdefault(key, value)
        return result

    for identifier, data in by_id.items():
        kind = data.get("type")
        if kind in ("UTILITY", None):
            continue
        outputs = [str(Path(build_dir) / item["path"]) for item in data.get("artifacts") or []
                   if isinstance(item, dict) and isinstance(item.get("path"), str)]
        links = closure(identifier, {identifier})
        in_tree = [by_id[d["id"]].get("name") for d in data.get("dependencies") or []
                   if isinstance(d, dict) and d.get("id") in by_id and by_id[d["id"]].get("type") != "UTILITY"]
        targets.append({"configuration": configuration_id, "name": data.get("name"), "type": kind,
                        "outputs": outputs, "components": sorted(links), "in_tree_dependencies": sorted(n for n in in_tree if n),
                        "sources": sorted(s.get("path") for s in data.get("sources") or [] if isinstance(s, dict) and isinstance(s.get("path"), str))[:500]})
        for key, link in links.items():
            observations.append({
                "id": stable_id("obs", "cmake", configuration_id, data.get("name"), key, link["via"]),
                "source": "cmake", "state": "observed", "configuration": configuration_id, "identity": link["identity"],
                "scope": "runtime", "linkage": link["linkage"],
                "location": f"target {data.get('name')}: {link['via']} {link['path']}",
                "evidence": evidence_id, "confidence": "high" if link["via"] == "link_path" else "medium",
                "attributes": {"target": data.get("name"), "via": link["via"], "outputs": outputs},
            })
    cache = {}
    for entry in (files.get("cache") or {}).get("entries") or []:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and KEPT_CACHE.match(entry["name"]):
            cache[entry["name"]] = entry.get("value")
    toolchains = []
    for item in (files.get("toolchains") or {}).get("toolchains") or []:
        compiler = item.get("compiler") or {} if isinstance(item, dict) else {}
        toolchains.append({"language": item.get("language"), "compiler_id": compiler.get("id"), "compiler_version": compiler.get("version"),
                           "target": compiler.get("target")})
    version = (files["index"].get("cmake") or {}).get("version") or {}
    return {"observations": observations, "targets": targets, "unresolved": unresolved,
            "vendored": {key: sorted(value) for key, value in sorted(vendored.items())},
            "build": {"cmake_version": version.get("string"), "cmake_config": selected.get("name"), "cache": cache, "toolchains": toolchains}}
