"""Versioned customer configuration (cra.toml). Unknown keys are errors, not ignored."""
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError
from .safety import PathScope

SCHEMA = "cra.config/1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
TOP_KEYS = {"schema_version", "product", "source", "scope", "output", "configurations", "images", "artifacts",
            "components", "tools", "analysis", "hosted", "directories"}


def _keys(table, allowed, where):
    if not isinstance(table, dict):
        raise ConfigError("config_invalid", f"{where} must be a table")
    unknown = set(table) - set(allowed)
    if unknown:
        raise ConfigError("config_unknown_key", f"{where}: unknown keys {sorted(unknown)}")


def _string(table, key, where, default=None, required=False):
    value = table.get(key, default)
    if value is None and required:
        raise ConfigError("config_missing", f"{where}.{key} is required")
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ConfigError("config_invalid", f"{where}.{key} must be a non-empty string")
    return value


def _identifier(value, where):
    if not isinstance(value, str) or not _ID.match(value):
        raise ConfigError("config_invalid", f"{where}: identifier must match {_ID.pattern}")
    return value


def _boolean(table, key, where, default=False):
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError("config_invalid", f"{where}.{key} must be a boolean")
    return value


@dataclass
class Configuration:
    id: str
    conan_graph: Path | None = None
    conan_manifest: Path | None = None
    conan_lockfile: Path | None = None
    cmake_build_dir: Path | None = None
    cmake_config: str | None = None
    required: bool = True
    pip_inspect: Path | None = None
    pip_inspect_shipped: bool = False
    pip_inspect_scope: str = "runtime"


@dataclass
class Directory:
    id: str
    path: Path
    role: str = "source"
    required: bool = True


@dataclass
class Image:
    id: str
    role: str
    archive: Path | None = None
    format: str = "oci-archive"
    reference: str | None = None
    expected_digest: str | None = None
    required: bool = True


@dataclass
class Artifact:
    id: str
    path: Path
    configuration: str | None = None
    shipped: bool = True
    required: bool = True


@dataclass
class Tools:
    syft: str = "syft"
    grype: str = "grype"
    timeout_seconds: int = 600
    allow_unverified_versions: bool = False
    add_generated_cpes: bool = False
    env_passthrough: list = field(default_factory=list)
    cpe_mappings: Path | None = None
    test_frameworks: list | None = None
    test_targets: list = field(default_factory=list)


@dataclass
class Analysis:
    policy: Path | None = None
    vex: list = field(default_factory=list)
    kev: Path | None = None
    product_file: Path | None = None
    risk_file: Path | None = None
    register_file: Path | None = None


@dataclass
class Hosted:
    url: str | None = None
    token_env: str = "CRA_TOKEN"
    poll_seconds: int = 5
    timeout_seconds: int = 900


@dataclass
class Config:
    path: Path
    root: Path
    product_name: str
    product_version: str
    product_supplier: str
    revision: str | None
    scope: PathScope
    output_dir: Path
    configurations: list
    images: list
    artifacts: list
    records: list
    tools: Tools
    analysis: Analysis
    hosted: Hosted
    directories: list = field(default_factory=list)


def _path(root, value):
    return (root / value).resolve() if value else None


def load_config(path):
    """Parse and validate. Every relative path resolves against the config file's folder."""
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError("config_unreadable", f"cannot read {path}: {exc.strerror or exc}") from exc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError("config_invalid", f"{path}: {exc}") from exc
    return parse_config(raw, path)


def parse_config(raw, path):
    """Validate parsed config without creating a temporary file (used by init)."""
    path = Path(path)
    _keys(raw, TOP_KEYS, "config")
    if raw.get("schema_version") != SCHEMA:
        raise ConfigError("config_schema", f"schema_version must be {SCHEMA!r}, found {raw.get('schema_version')!r}")
    root = path.resolve().parent
    for key in ("configurations", "images", "directories", "artifacts"):
        if key in raw and not isinstance(raw[key], list):
            raise ConfigError("config_invalid", f"{key} must be an array of tables")

    product = raw.get("product", {})
    _keys(product, {"name", "version", "supplier"}, "product")
    source = raw.get("source", {})
    _keys(source, {"revision"}, "source")
    scope_table = raw.get("scope", {})
    _keys(scope_table, {"roots"}, "scope")
    roots = scope_table.get("roots")
    if not isinstance(roots, list) or not roots or not all(isinstance(item, str) and item.strip() for item in roots):
        raise ConfigError("config_missing", "scope.roots must list the directories the collector may read")
    output = raw.get("output", {})
    _keys(output, {"dir"}, "output")

    configurations, seen = [], set()
    for index, table in enumerate(raw.get("configurations", [])):
        where = f"configurations[{index}]"
        _keys(table, {"id", "conan_graph", "conan_manifest", "conan_lockfile", "cmake_build_dir", "cmake_config", "required",
                      "pip_inspect", "pip_inspect_shipped", "pip_inspect_scope"}, where)
        identity = _identifier(table.get("id"), f"{where}.id")
        if identity in seen:
            raise ConfigError("config_invalid", f"{where}: duplicate id {identity}")
        seen.add(identity)
        python_scope = table.get("pip_inspect_scope", "runtime")
        if python_scope not in ("runtime", "build_tool", "test"):
            raise ConfigError("config_invalid", f"{where}.pip_inspect_scope must be runtime, build_tool or test")
        python_shipped = _boolean(table, "pip_inspect_shipped", where)
        if python_shipped and python_scope != "runtime":
            raise ConfigError("config_invalid", f"{where}: a shipped Python environment must have runtime scope")
        configurations.append(Configuration(
            id=identity, conan_graph=_path(root, _string(table, "conan_graph", where)),
            conan_manifest=_path(root, _string(table, "conan_manifest", where)),
            conan_lockfile=_path(root, _string(table, "conan_lockfile", where)),
            cmake_build_dir=_path(root, _string(table, "cmake_build_dir", where)),
            cmake_config=_string(table, "cmake_config", where), required=_boolean(table, "required", where, True),
            pip_inspect=_path(root, _string(table, "pip_inspect", where)),
            pip_inspect_shipped=python_shipped, pip_inspect_scope=python_scope))

    directories = []
    for index, table in enumerate(raw.get("directories", [])):
        where = f"directories[{index}]"
        _keys(table, {"id", "path", "role", "required"}, where)
        role = table.get("role", "source")
        if role not in ("source", "final", "build-stage"):
            raise ConfigError("config_invalid", f"{where}.role must be source, final or build-stage")
        directories.append(Directory(id=_identifier(table.get("id"), f"{where}.id"),
                                     path=_path(root, _string(table, "path", where, required=True)), role=role,
                                     required=_boolean(table, "required", where, True)))

    images = []
    for index, table in enumerate(raw.get("images", [])):
        where = f"images[{index}]"
        _keys(table, {"id", "role", "archive", "format", "reference", "expected_digest", "required"}, where)
        role = table.get("role")
        if role not in ("final", "build-stage"):
            raise ConfigError("config_invalid", f"{where}.role must be final or build-stage")
        archive, reference = _string(table, "archive", where), _string(table, "reference", where)
        if bool(archive) == bool(reference):
            raise ConfigError("config_invalid", f"{where}: set exactly one of archive or reference")
        if reference and not _DIGEST.search(reference):
            raise ConfigError("image_reference_mutable", f"{where}.reference must be pinned with @sha256:<digest>")
        image_format = table.get("format", "oci-archive")
        if image_format not in ("oci-archive", "docker-archive"):
            raise ConfigError("config_invalid", f"{where}.format must be oci-archive or docker-archive")
        images.append(Image(id=_identifier(table.get("id"), f"{where}.id"), role=role, archive=_path(root, archive),
                            format=image_format, reference=reference,
                            expected_digest=_string(table, "expected_digest", where),
                            required=_boolean(table, "required", where, True)))

    artifacts = []
    for index, table in enumerate(raw.get("artifacts", [])):
        where = f"artifacts[{index}]"
        _keys(table, {"id", "path", "configuration", "shipped", "required"}, where)
        configuration = _string(table, "configuration", where)
        if configuration and configuration not in seen:
            raise ConfigError("config_invalid", f"{where}.configuration names unknown configuration {configuration}")
        artifacts.append(Artifact(id=_identifier(table.get("id"), f"{where}.id"),
                                  path=_path(root, _string(table, "path", where, required=True)),
                                  configuration=configuration, shipped=_boolean(table, "shipped", where, True),
                                  required=_boolean(table, "required", where, True)))

    artifact_ids = [item.id for item in images + directories + artifacts]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ConfigError("config_invalid", "images, directories and artifacts must have unique ids")

    components = raw.get("components", {})
    _keys(components, {"records"}, "components")
    record_paths = components.get("records", [])
    if not isinstance(record_paths, list) or not all(isinstance(item, str) and item.strip() for item in record_paths):
        raise ConfigError("config_invalid", "components.records must be a list of paths")
    tools_table = raw.get("tools", {})
    _keys(tools_table, {"syft", "grype", "timeout_seconds", "allow_unverified_versions", "add_generated_cpes", "env_passthrough", "cpe_mappings", "test_frameworks", "test_targets"}, "tools")
    def _tool(name):
        value = _string(tools_table, name, "tools", default=name)
        return str(_path(root, value)) if "/" in value else value
    timeout = tools_table.get("timeout_seconds", 600)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 86400:
        raise ConfigError("config_invalid", "tools.timeout_seconds must be between 1 and 86400")
    passthrough = tools_table.get("env_passthrough", [])
    if not isinstance(passthrough, list) or not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) for item in passthrough):
        raise ConfigError("config_invalid", "tools.env_passthrough must be a list of environment variable names")
    tools = Tools(syft=_tool("syft"), grype=_tool("grype"), timeout_seconds=timeout,
                  allow_unverified_versions=_boolean(tools_table, "allow_unverified_versions", "tools"),
                  add_generated_cpes=_boolean(tools_table, "add_generated_cpes", "tools"),
                  env_passthrough=passthrough,
                  cpe_mappings=_path(root, _string(tools_table, "cpe_mappings", "tools")),
                  test_frameworks=tools_table.get("test_frameworks"), test_targets=tools_table.get("test_targets", []))
    if tools.test_frameworks is not None and (not isinstance(tools.test_frameworks, list) or any(not isinstance(x, str) or not x for x in tools.test_frameworks)):
        raise ConfigError("config_invalid", "tools.test_frameworks must list package names")

    analysis_table = raw.get("analysis", {})
    _keys(analysis_table, {"policy", "vex", "kev", "product_file", "risk_file", "register_file"}, "analysis")
    vex = analysis_table.get("vex", [])
    if not isinstance(vex, list) or not all(isinstance(item, str) for item in vex):
        raise ConfigError("config_invalid", "analysis.vex must be a list of paths")
    analysis = Analysis(policy=_path(root, _string(analysis_table, "policy", "analysis")),
                        vex=[_path(root, item) for item in vex], kev=_path(root, _string(analysis_table, "kev", "analysis")),
                        product_file=_path(root, _string(analysis_table, "product_file", "analysis")),
                        risk_file=_path(root, _string(analysis_table, "risk_file", "analysis")),
                        register_file=_path(root, _string(analysis_table, "register_file", "analysis")))

    if not isinstance(tools.test_targets, list) or any(not isinstance(x, str) or not x for x in tools.test_targets):
        raise ConfigError("config_invalid", "tools.test_targets must list target names")

    hosted_table = raw.get("hosted", {})
    _keys(hosted_table, {"url", "token_env", "poll_seconds", "timeout_seconds"}, "hosted")
    for key, default in (("poll_seconds", 5), ("timeout_seconds", 900)):
        value = hosted_table.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86400:
            raise ConfigError("config_invalid", f"hosted.{key} must be an integer between 1 and 86400")
    hosted = Hosted(url=_string(hosted_table, "url", "hosted"), token_env=_string(hosted_table, "token_env", "hosted", default="CRA_TOKEN"),
                    poll_seconds=int(hosted_table.get("poll_seconds", 5)), timeout_seconds=int(hosted_table.get("timeout_seconds", 900)))

    revision = _string(source, "revision", "source")
    if revision and revision.startswith("env:"):
        revision = os.environ.get(revision[4:]) or None

    return Config(path=path.resolve(), root=root,
                  product_name=_string(product, "name", "product", required=True),
                  product_version=_string(product, "version", "product", required=True),
                  product_supplier=_string(product, "supplier", "product") or "",
                  revision=revision, scope=PathScope([_path(root, item) for item in roots]),
                  output_dir=_path(root, _string(output, "dir", "output", default=".cra")),
                  configurations=configurations, images=images, artifacts=artifacts,
                  records=[_path(root, item) for item in components.get("records", [])], directories=directories,
                  tools=tools, analysis=analysis, hosted=hosted)
