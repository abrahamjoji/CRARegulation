"""cra collect: read explicitly configured metadata and artifacts into an evidence bundle."""
import datetime as dt
import shutil
import tempfile
from pathlib import Path

from .. import __version__
from ..common.bundle import EvidenceStore, reset_output, write_manifest
from ..common.errors import ConfigError, UntrustedInputError, diagnostic
from ..common.safety import Limits, read_json, run_tool, sha256_bytes, tool_environment, write_json
from . import artifact as artifact_module
from . import cmake, conan, container, directory as directory_module, python_env, records as records_module

COLLECTION_SCHEMA = "cra.collection/1"


def source_status(kind, subject, status, reason="", required=True, **details):
    return {"source": kind, "subject": subject, "status": status, "reason": reason, "required": required, **details}


def git_revision(root):
    """Read the checkout revision without letting repository config run anything."""
    git = shutil.which("git")
    if not git:
        return None, None
    env = tool_environment({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": "/nonexistent"})
    with tempfile.NamedTemporaryFile() as output:
        result = run_tool([git, "-c", "core.fsmonitor=false", "-c", f"safe.directory={root}", "-C", str(root), "rev-parse", "HEAD"],
                          stdout_path=output.name, limits=Limits(timeout_seconds=30), env=env)
        revision = Path(output.name).read_text(encoding="utf-8", errors="replace").strip()
        if result.returncode or not revision:
            return None, None
    with tempfile.NamedTemporaryFile() as output:
        result = run_tool([git, "-c", "core.fsmonitor=false", "-c", f"safe.directory={root}", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
                          stdout_path=output.name, limits=Limits(timeout_seconds=60), env=env)
        dirty = bool(Path(output.name).read_bytes().strip()) if not result.returncode else None
    return revision, dirty


def _collect_conan(configuration, config, store, out):
    if configuration.conan_graph is None:
        out["sources"].append(source_status("conan", configuration.id, "not_configured", "no conan_graph configured", required=False))
        return {}
    if not configuration.conan_graph.is_file():
        out["sources"].append(source_status(
            "conan", configuration.id, "missing",
            f"{configuration.conan_graph} not found; capture it with `conan install ... --format=json --out-file <file>` during the real build",
            configuration.required))
        return {}
    config.scope.require(configuration.conan_graph, "conan_graph")
    try:
        document = read_json(configuration.conan_graph)
        raw = configuration.conan_graph.read_bytes()
        evidence = store.add_json("collector-input", f"conan:{configuration.id}", document, f"conan-{configuration.id}.graph.json", original_bytes=raw, adapter="conan-graph-json")
        parsed = conan.collect_graph(document, configuration.id, evidence)
    except UntrustedInputError as exc:
        out["sources"].append(source_status("conan", configuration.id, "failed", str(exc), configuration.required, code=exc.code))
        return {}
    out["observations"] += parsed["observations"]
    out["edges"] += parsed["edges"]
    out["configurations"][configuration.id]["conan"] = parsed["build"]
    if parsed["problems"]:
        out["sources"].append(source_status("conan", configuration.id, "partial", "; ".join(parsed["problems"])[:2000], configuration.required, evidence=evidence))
    else:
        out["sources"].append(source_status("conan", configuration.id, "complete", "", configuration.required, evidence=evidence))
    if configuration.conan_lockfile:
        if configuration.conan_lockfile.is_file():
            config.scope.require(configuration.conan_lockfile, "conan_lockfile")
            store.add_file_as_text("collector-input", f"conan-lock:{configuration.id}", configuration.conan_lockfile, f"conan-{configuration.id}.lock")
        else:
            out["diagnostics"].append(diagnostic("conan_lockfile_missing", f"{configuration.conan_lockfile} not found", subject=configuration.id, origin="input", severity="warning"))
    if configuration.conan_manifest:
        _collect_manifest(configuration, config, store, out)
    return parsed["folders"]


def _collect_manifest(configuration, config, store, out):
    path = configuration.conan_manifest
    if not path.is_file():
        out["diagnostics"].append(diagnostic("conan_manifest_missing", f"{path} not found", subject=configuration.id, origin="input", severity="warning"))
        return
    config.scope.require(path, "conan_manifest")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise UntrustedInputError("file_too_large", f"{path}: recipe is larger than 4 MiB")
    # Declared requirements only: the recipe itself is not retained as uploadable evidence.
    text = path.read_text(encoding="utf-8", errors="replace")
    evidence = store.add_json("collector-input", f"conan-manifest:{configuration.id}",
                              {"file": path.name, "sha256": sha256_bytes(text.encode("utf-8")), "note": "Recipe parsed statically, never executed; source not retained."},
                              f"conan-{configuration.id}.manifest-ref.json", adapter="conan-manifest-static")
    observations, notes = conan.parse_manifest(text, path.name, configuration.id, evidence)
    out["observations"] += observations
    out["limitations"] += [{"subject": configuration.id, "source": "conan-manifest", "message": note} for note in notes]


def _collect_cmake(configuration, config, store, out, folders):
    build_dir = configuration.cmake_build_dir
    if build_dir is None:
        out["sources"].append(source_status("cmake", configuration.id, "not_configured", "no cmake_build_dir configured", required=False))
        return
    config.scope.require(build_dir, "cmake_build_dir")
    index = cmake.find_index(build_dir)
    if index is None:
        out["sources"].append(source_status("cmake", configuration.id, "missing", cmake.missed_prepare_message(build_dir), configuration.required, code="cmake_prepare_missed"))
        return
    try:
        files = cmake.read_reply(index)
        evidence = store.add_json("collector-input", f"cmake:{configuration.id}", _retained_reply(files), f"cmake-{configuration.id}.reply.json", adapter="cmake-file-api")
        parsed = cmake.analyze_reply(files, configuration.id, configuration.cmake_config, folders, evidence, build_dir, config.tools.test_frameworks, config.tools.test_targets)
    except UntrustedInputError as exc:
        out["sources"].append(source_status("cmake", configuration.id, "failed", str(exc), configuration.required, code=exc.code))
        return
    out["observations"] += parsed["observations"]
    out["targets"] += parsed["targets"]
    out["configurations"][configuration.id]["cmake"] = parsed["build"]
    out["vendored_candidates"] += [{"configuration": configuration.id, "path": path, "targets": targets} for path, targets in parsed["vendored"].items()]
    out["unresolved_links"] += [{"configuration": configuration.id, "evidence": evidence, **item} for item in parsed["unresolved"]]
    status = "complete" if parsed["targets"] else "partial"
    if not folders and configuration.conan_graph:
        status, reason = "partial", "no Conan package folders to compare link paths with, so linked packages cannot be identified"
    else:
        reason = "" if parsed["targets"] else "the reply lists no build targets"
    out["sources"].append(source_status("cmake", configuration.id, status, reason, configuration.required, evidence=evidence))


def _retained_reply(files):
    """Keep the code model and only safe cache names; cache values are often sensitive."""
    retained = {"index": files["index"], "codemodel": files["codemodel"], "targets": files["targets"]}
    if "toolchains" in files:
        retained["toolchains"] = files["toolchains"]
    entries = (files.get("cache") or {}).get("entries") or []
    retained["cache_entries"] = [{"name": item["name"], "value": item.get("value")} for item in entries
                                 if isinstance(item, dict) and isinstance(item.get("name"), str) and cmake.KEPT_CACHE.match(item["name"])]
    retained["cache_note"] = "Only allow-listed cache names are retained."
    return retained


def _collect_artifacts(config, store, out):
    for artifact in config.artifacts:
        path = Path(artifact.path)
        if not path.is_file():
            out["sources"].append(source_status("artifact", artifact.id, "missing", f"{path} not found", artifact.required))
            continue
        config.scope.require(path, f"artifact {artifact.id}")
        evidence = store.add_json("collector-output", f"artifact:{artifact.id}", {"path": str(path), "sha256": artifact_module.sha256_file(path)},
                                  f"artifact-{artifact.id}.json", adapter="artifact-inspector")
        try:
            record, observations, status, reason = artifact_module.collect_artifact(artifact, evidence)
        except UntrustedInputError as exc:
            out["sources"].append(source_status("artifact", artifact.id, "failed", str(exc), artifact.required, code=exc.code))
            continue
        out["artifacts"].append(record)
        out["observations"] += observations
        out["sources"].append(source_status("artifact", artifact.id, status, reason, artifact.required, evidence=evidence))


def _collect_images(config, store, out):
    for image in config.images:
        if image.archive:
            config.scope.require(image.archive, f"image {image.id}")
        try:
            record, observations, status, reason, tool = container.collect_image(image, config.tools, store)
        except UntrustedInputError as exc:
            out["sources"].append(source_status("image", image.id, "failed", str(exc), image.required, code=exc.code))
            continue
        out["artifacts"].append(record)
        out["observations"] += observations
        if tool and tool not in out["adapters"]:
            out["adapters"].append(tool)
        out["sources"].append(source_status("image", image.id, status, reason, image.required, evidence=record.get("evidence", ""), role=image.role))


def _collect_records(config, store, out):
    for path in config.records:
        if not path.is_file():
            out["sources"].append(source_status("customer-record", path.name, "missing", f"{path} not found"))
            continue
        config.scope.require(path, "component records")
        try:
            document = read_json(path, 16 * 1024 * 1024)
            raw = path.read_bytes()
            evidence = store.add_json("customer-input", f"records:{path.name}", document, f"records-{path.name}", original_bytes=raw, adapter="component-records")
            observations, covered = records_module.parse_records(document, evidence)
        except UntrustedInputError as exc:
            out["sources"].append(source_status("customer-record", path.name, "failed", str(exc), code=exc.code))
            continue
        out["observations"] += observations
        out["covered_vendor_paths"].update(covered)
        out["sources"].append(source_status("customer-record", path.name, "complete", evidence=evidence))


def _collect_python(configuration, config, store, out):
    path = configuration.pip_inspect
    if path is None:
        return
    try:
        config.scope.require(path, "pip_inspect")
        document = read_json(path)
        evidence = store.add_json("collector-input", f"python:{configuration.id}", document,
                                  f"python-{configuration.id}.inspect.json", original_bytes=path.read_bytes(), adapter="pip-inspect-v1")
        parsed = python_env.collect_inspect(document, configuration, evidence)
        artifact_id = f"python-env:{configuration.id}"
        out["artifacts"].append({"id": artifact_id, "kind": "python-environment", "path": str(path),
                                 "name": configuration.id, "sha256": sha256_bytes(path.read_bytes()), "bytes": path.stat().st_size,
                                 "configuration": configuration.id, "shipped": configuration.pip_inspect_shipped,
                                 "format": "pip-inspect/1", "evidence": evidence,
                                 "limitations": ["Hash identifies the captured metadata, not an attestation of the deployed environment."]})
        for observation in parsed["observations"]:
            observation["artifact"] = artifact_id
        out["observations"] += parsed["observations"]
        out["edges"] += parsed["edges"]
        out["configurations"][configuration.id]["python"] = parsed["build"]
        out["limitations"] += [{"subject": configuration.id, "source": "python-inspect", "message": note} for note in parsed["limitations"]]
        out["sources"].append(source_status("python-inspect", configuration.id, "partial" if parsed["problems"] else "complete",
                                            "; ".join(parsed["problems"])[:2000], configuration.required, evidence=evidence))
    except UntrustedInputError as exc:
        out["sources"].append(source_status("python-inspect", configuration.id, "failed", str(exc), configuration.required, code=exc.code))


def _collect_directories(config, store, out, destination):
    for directory in config.directories:
        try:
            config.scope.require(directory.path, "directory")
            if directory.path.is_relative_to(config.output_dir) or directory.path.is_relative_to(destination.resolve()):
                raise UntrustedInputError("directory_is_output", "directory input must not be a CRA output directory")
            record, observations, status, reason, tool = directory_module.collect_directory(
                directory, config.tools, store, excluded=(config.output_dir, destination.resolve()))
            out["artifacts"].append(record)
            out["observations"] += observations
            if tool and tool not in out["adapters"]:
                out["adapters"].append(tool)
            out["sources"].append(source_status("directory", directory.id, status, reason, directory.required, role=directory.role))
        except (UntrustedInputError, OSError) as exc:
            out["sources"].append(source_status("directory", directory.id, "failed", str(exc), directory.required,
                                                code=getattr(exc, "code", "directory_unreadable")))


def collect(config, destination=None):
    """Write a collection bundle. Returns the collection document."""
    destination = Path(destination or config.output_dir / "collection")
    inputs = [config.root, config.path] + config.records
    inputs += [item.path for item in config.artifacts] + [item.archive for item in config.images if item.archive]
    inputs += [item.path for item in config.directories]
    inputs += [path for item in config.configurations for path in
               (item.conan_graph, item.conan_manifest, item.conan_lockfile, item.cmake_build_dir, item.pip_inspect) if path]
    reset_output(destination, "collection", protected=inputs)
    if not config.scope.roots:
        raise ConfigError("config_missing", "scope.roots is empty")
    revision = config.revision
    dirty = None
    if revision is None:
        revision, dirty = git_revision(config.root)
    store = EvidenceStore(destination)
    out = {
        "schema_version": COLLECTION_SCHEMA,
        "collector": {"name": "cra", "version": __version__},
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "product": {"name": config.product_name, "version": config.product_version, "supplier": config.product_supplier},
        "source": {"revision": revision, "dirty": dirty},
        "configurations": {item.id: {"id": item.id} for item in config.configurations},
        "sources": [], "observations": [], "edges": [], "artifacts": [], "targets": [], "adapters": [],
        "vendored_candidates": [], "covered_vendor_paths": {}, "unresolved_links": [], "limitations": [], "diagnostics": [],
    }
    if not (config.configurations or config.images or config.artifacts or config.records or config.directories):
        raise ConfigError("config_empty", "nothing to collect: configure configurations, directories, images, artifacts or components.records")
    for configuration in config.configurations:
        _collect_python(configuration, config, store, out)
        folders = _collect_conan(configuration, config, store, out)
        _collect_cmake(configuration, config, store, out, folders)
    _collect_artifacts(config, store, out)
    _collect_images(config, store, out)
    _collect_directories(config, store, out, destination)
    _collect_records(config, store, out)
    out["evidence"] = store.records
    write_json(destination / "collection.json", out)
    write_manifest(destination, kind="collection", collector_version=__version__, source_revision=revision)
    return out, destination
