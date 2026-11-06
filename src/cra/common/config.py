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
            "components", "tools", "analysis", "hosted"}


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


@dataclass
class Configuration:
    id: str
    conan_graph: Path | None = None
    conan_manifest: Path | None = None
    conan_lockfile: Path | None = None
    cmake_build_dir: Path | None = None
    cmake_config: str | None = None
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
    _keys(raw, TOP_KEYS, "config")
    if raw.get("schema_version") != SCHEMA:
        raise ConfigError("config_schema", f"schema_version must be {SCHEMA!r}, found {raw.get('schema_version')!r}")
    root = path.resolve().parent

    product = raw.get("product", {})
    _keys(product, {"name", "version", "supplier"}, "product")
    source = raw.get("source", {})
    _keys(source, {"revision"}, "source")
    scope_table = raw.get("scope", {})
    _keys(scope_table, {"roots"}, "scope")
    roots = scope_table.get("roots")
    if not isinstance(roots, list) or not roots or not all(isinstance(item, str) for item in roots):
        raise ConfigError("config_missing", "scope.roots must list the directories the collector may read")
    output = raw.get("output", {})
    _keys(output, {"dir"}, "output")

    configurations, seen = [], set()
    for index, table in enumerate(raw.get("configurations", [])):
        where = f"configurations[{index}]"
        _keys(table, {"id", "conan_graph", "conan_manifest", "conan_lockfile", "cmake_build_dir", "cmake_config", "required"}, where)
        identity = _identifier(table.get("id"), f"{where}.id")
        if identity in seen:
            raise ConfigError("config_invalid", f"{where}: duplicate id {identity}")
        seen.add(identity)
        configurations.append(Configuration(
            id=identity, conan_graph=_path(root, _string(table, "conan_graph", where)),
            conan_manifest=_path(root, _string(table, "conan_manifest", where)),
            conan_lockfile=_path(root, _string(table, "conan_lockfile", where)),
            cmake_build_dir=_path(root, _string(table, "cmake_build_dir", where)),
            cmake_config=_string(table, "cmake_config", where), required=bool(table.get("required", True))))

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
                            required=bool(table.get("required", True))))

    artifacts = []
    for index, table in enumerate(raw.get("artifacts", [])):
        where = f"artifacts[{index}]"
        _keys(table, {"id", "path", "configuration", "shipped", "required"}, where)
        configuration = _string(table, "configuration", where)
        if configuration and configuration not in seen:
            raise ConfigError("config_invalid", f"{where}.configuration names unknown configuration {configuration}")
        artifacts.append(Artifact(id=_identifier(table.get("id"), f"{where}.id"),
                                  path=_path(root, _string(table, "path", where, required=True)),
                                  configuration=configuration, shipped=bool(table.get("shipped", True)),
                                  required=bool(table.get("required", True))))

    components = raw.get("components", {})
    _keys(components, {"records"}, "components")
    tools_table = raw.get("tools", {})
    _keys(tools_table, {"syft", "grype", "timeout_seconds", "allow_unverified_versions", "add_generated_cpes", "env_passthrough"}, "tools")
    def _tool(name):
        value = _string(tools_table, name, "tools", default=name)
        return str(_path(root, value)) if "/" in value else value
    timeout = tools_table.get("timeout_seconds", 600)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 86400:
        raise ConfigError("config_invalid", "tools.timeout_seconds must be between 1 and 86400")
    tools = Tools(syft=_tool("syft"), grype=_tool("grype"), timeout_seconds=timeout,
                  allow_unverified_versions=bool(tools_table.get("allow_unverified_versions", False)),
                  add_generated_cpes=bool(tools_table.get("add_generated_cpes", False)),
                  env_passthrough=list(tools_table.get("env_passthrough", [])))

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

    hosted_table = raw.get("hosted", {})
    _keys(hosted_table, {"url", "token_env", "poll_seconds", "timeout_seconds"}, "hosted")
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
                  records=[_path(root, item) for item in components.get("records", [])],
                  tools=tools, analysis=analysis, hosted=hosted)
