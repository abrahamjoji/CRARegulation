"""Conan 2 evidence: graph JSON captured from the customer's own install or create.

This module reads what Conan already resolved. It never runs Conan or a recipe,
because guessed defaults would produce a graph that is not the actual build.
"""
import ast
import re

from ..common import purl as purls
from ..common.errors import UntrustedInputError
from ..common.safety import stable_id

LINKAGE = {"shared-library": "shared", "static-library": "static", "header-library": "header", "application": "application"}
BAD_BINARY = {"Missing": "binary is missing", "Invalid": "configuration is invalid for this package", "Skip": None, "Editable": None}
_REF = re.compile(r"^(?P<name>[^/@#\s]+)(?:/(?P<version>[^@#\s]+))?(?:@(?P<user>[^/#\s]+)/(?P<channel>[^#\s]+))?(?:#(?P<rrev>[^\s]+))?$")


def parse_ref(reference):
    match = _REF.match(reference) if isinstance(reference, str) else None
    if not match:
        raise UntrustedInputError("conan_ref_invalid", f"cannot parse Conan reference: {reference!r}")
    return match.groupdict()


def _identity(ref, node):
    return {"ecosystem": "conan", "name": ref["name"], "version": ref["version"],
            "purl": purls.build("conan", ref["name"], ref["version"], ref["user"]),
            "supplier": "", "license": _license(node), "cpes": []}


def _license(node):
    value = node.get("license")
    if isinstance(value, (list, tuple)):
        return " AND ".join(str(item) for item in value)
    return value if isinstance(value, str) else ""


def _libraries(node):
    libs = set()
    info = node.get("cpp_info")
    for component in (info.values() if isinstance(info, dict) else []):
        if isinstance(component, dict):
            libs.update(item for item in (component.get("libs") or []) if isinstance(item, str))
    return sorted(libs)


def _reachable(nodes, root):
    """Scopes from root: runtime follows ordinary requires; test and build edges stay separate."""
    scope, stack = {root: "root"}, [(root, "runtime")]
    order = {"runtime": 0, "test": 1, "build_tool": 2}
    while stack:
        current, current_scope = stack.pop()
        for target, edge in (nodes[current].get("dependencies") or {}).items():
            if target not in nodes or not isinstance(edge, dict):
                continue
            next_scope = current_scope
            if edge.get("build"):
                next_scope = "build_tool"
            elif edge.get("test"):
                next_scope = "test" if current_scope == "runtime" else current_scope
            if target not in scope or order[next_scope] < order.get(scope[target], 99):
                scope[target] = next_scope
                stack.append((target, next_scope))
    return scope


def collect_graph(document, configuration, evidence_id):
    """Convert a graph into observations and edges. Raises on a document that is not a graph."""
    graph = document.get("graph") if isinstance(document, dict) else None
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict) or not nodes:
        raise UntrustedInputError("conan_graph_invalid", "no graph.nodes: capture it with `conan install ... --format=json`")
    if not all(isinstance(node, dict) for node in nodes.values()):
        raise UntrustedInputError("conan_graph_invalid", "every graph node must be an object")
    root = next(iter(graph.get("root") or {}), None)
    if root not in nodes:
        root = "0" if "0" in nodes else None
    if root is None:
        raise UntrustedInputError("conan_graph_invalid", "the graph names no root node")

    problems = []
    if graph.get("error"):
        problems.append(f"Conan reported a graph error: {str(graph['error'])[:500]}")
    scopes = _reachable(nodes, root)
    observations, edges, folders = [], [], {}
    keys = {}
    for key, node in nodes.items():
        if key == root:
            continue
        ref = parse_ref(node.get("ref"))
        keys[key] = ref
        identity = _identity(ref, node)
        context = node.get("context")
        scope = scopes.get(key, "unknown")
        if context == "build":
            scope = "build_tool"
        binary = node.get("binary")
        if binary in BAD_BINARY and BAD_BINARY[binary]:
            problems.append(f"{node.get('ref')}: {BAD_BINARY[binary]} (binary state {binary})")
        if not ref["version"]:
            problems.append(f"{node.get('ref')}: no version in the Conan reference")
        attributes = {
            "context": context, "package_type": node.get("package_type"), "binary": binary,
            "recipe_revision": node.get("rrev") or ref["rrev"], "package_id": node.get("package_id"),
            "package_revision": node.get("prev"), "remote": node.get("remote"),
            "settings": node.get("settings"), "options": node.get("options"),
            "libraries": _libraries(node), "homepage": node.get("homepage"),
        }
        observations.append({
            "id": stable_id("obs", "conan", configuration, key, node.get("ref")), "source": "conan", "state": "resolved",
            "configuration": configuration, "identity": identity, "scope": scope,
            "linkage": LINKAGE.get(node.get("package_type"), "unknown"), "location": f"conan graph node {key}",
            "evidence": evidence_id, "confidence": "high", "attributes": attributes,
        })
        for field in ("package_folder", "immutable_package_folder"):
            if isinstance(node.get(field), str) and node[field]:
                folders[node[field].rstrip("/")] = identity

    for key, node in nodes.items():
        parent = None if key == root else keys[key]
        for target, edge in (node.get("dependencies") or {}).items():
            if target not in keys or not isinstance(edge, dict):
                if target not in keys and target != root:
                    problems.append(f"dangling graph edge {key} -> {target}")
                continue
            child = keys[target]
            edges.append({"from": "product" if parent is None else purls.build("conan", parent["name"], parent["version"], parent["user"]),
                          "to": purls.build("conan", child["name"], child["version"], child["user"]),
                          "kind": "build_requires" if edge.get("build") else "test_requires" if edge.get("test") else "requires",
                          "direct": bool(edge.get("direct")), "configuration": configuration, "evidence": evidence_id,
                          "attributes": {flag: bool(edge.get(flag)) for flag in ("libs", "headers", "run", "visible")}})
            if parent is None and edge.get("direct"):
                identity = _identity(child, nodes[target])
                observations.append({
                    "id": stable_id("obs", "conan-declared", configuration, target), "source": "conan", "state": "declared",
                    "configuration": configuration, "identity": identity,
                    "scope": "build_tool" if edge.get("build") else "test" if edge.get("test") else "runtime",
                    "linkage": "unknown", "location": "direct requirement of the root node in the Conan graph",
                    "evidence": evidence_id, "confidence": "high", "attributes": {"requirement": edge.get("require")},
                })
    root_node = nodes[root]
    build = {"root_reference": root_node.get("ref") or "", "settings": root_node.get("settings") or {},
             "options": root_node.get("options") or {},
             "overrides": graph.get("overrides") or {}, "resolved_ranges": graph.get("resolved_ranges") or {},
             "replaced_requires": graph.get("replaced_requires") or {}}
    return {"observations": observations, "edges": edges, "problems": problems, "folders": folders, "build": build}


class _RecipeVisitor(ast.NodeVisitor):
    """Static reading of literal requirements. Conditionals are noted, never evaluated."""

    def __init__(self):
        self.requires, self.conditional = [], []

    def _literal(self, node):
        try:
            value = ast.literal_eval(node)
        except (ValueError, SyntaxError):
            return []
        if isinstance(value, str):
            return [value]
        return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else []

    def visit_ClassDef(self, node):
        for statement in node.body:
            if isinstance(statement, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("requires", "tool_requires", "build_requires", "test_requires") for t in statement.targets):
                kind = statement.targets[0].id
                self.requires += [(item, kind) for item in self._literal(statement.value)]
        self.generic_visit(node)

    def visit_If(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in ("requires", "tool_requires", "test_requires") and child.args:
                self.conditional += [(item, child.func.attr) for item in self._literal(child.args[0])]
        self.generic_visit(node)


def parse_manifest(text, name, configuration, evidence_id):
    """Declared requirements from conanfile.txt or conanfile.py, parsed and never executed."""
    declared, notes = [], []
    if name.endswith(".py"):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError) as exc:
            return [], [f"{name}: cannot parse statically ({exc})"]
        visitor = _RecipeVisitor()
        visitor.visit(tree)
        declared = [(item, kind, False) for item, kind in visitor.requires] + [(item, kind, True) for item, kind in visitor.conditional]
        notes.append(f"{name}: read statically; requirements computed at run time are not seen")
    else:
        section = ""
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
            elif line and section in ("requires", "tool_requires", "test_requires"):
                declared.append((line, section, False))
    observations = []
    for requirement, kind, conditional in declared:
        try:
            ref = parse_ref(requirement)
        except UntrustedInputError as exc:
            notes.append(str(exc))
            continue
        version = ref["version"] if ref["version"] and not re.search(r"[\[\]<>*~^]", ref["version"]) else None
        observations.append({
            "id": stable_id("obs", "manifest", configuration, requirement, kind), "source": "manifest", "state": "declared",
            "configuration": configuration,
            "identity": {"ecosystem": "conan", "name": ref["name"], "version": version,
                         "purl": purls.build("conan", ref["name"], version, ref["user"]), "supplier": "", "license": "", "cpes": []},
            "scope": {"tool_requires": "build_tool", "build_requires": "build_tool", "test_requires": "test"}.get(kind, "runtime"),
            "linkage": "unknown", "location": name, "evidence": evidence_id, "confidence": "medium",
            "attributes": {"requirement": requirement, "conditional": conditional},
        })
    return observations, notes
