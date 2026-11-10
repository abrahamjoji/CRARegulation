"""cra prepare: register CMake File API queries before CMake configures the build tree."""
import json

from ..common.errors import ConfigError

CLIENT = "cra"
# Requested at documented major versions; CMake answers with the newest minor it has.
QUERY = {"requests": [{"kind": "codemodel", "version": 2}, {"kind": "cache", "version": 2},
                      {"kind": "toolchains", "version": 1}, {"kind": "cmakeFiles", "version": 1}]}


def query_dir(build_dir):
    return build_dir / ".cmake" / "api" / "v1" / "query" / f"client-{CLIENT}"


def prepare(config):
    """Write stateful queries. CMake reads them at configure time, so order matters."""
    results = []
    for configuration in config.configurations:
        build_dir = configuration.cmake_build_dir
        if build_dir is None:
            results.append({"configuration": configuration.id, "status": "skipped", "reason": "no cmake_build_dir configured"})
            continue
        if not config.scope.contains(build_dir):
            raise ConfigError("path_out_of_scope", f"{build_dir} is outside scope.roots", subject=configuration.id)
        reply = build_dir / ".cmake" / "api" / "v1" / "reply"
        already_configured = (build_dir / "CMakeCache.txt").exists()
        target = query_dir(build_dir)
        target.mkdir(parents=True, exist_ok=True)
        (target / "query.json").write_text(json.dumps(QUERY, indent=2) + "\n", encoding="utf-8")
        results.append({
            "configuration": configuration.id, "status": "prepared", "query": str(target / "query.json"),
            "note": ("This build tree was already configured. Run CMake again so it answers the query."
                     if already_configured and not reply.exists() else ""),
        })
    return results
