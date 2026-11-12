"""Deterministic workspace for platform tests. Scanners here are fakes, and are labelled as such.

Conan graphs, CMake replies and Syft documents come from a real reference build,
with machine paths rewritten. Fake syft and grype replay that output; they exist
so routine tests need no network, tool downloads or vulnerability database.
Real tools are exercised only in tests/integration.
"""
import datetime as dt
import importlib.util
import json
import shutil
import stat
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
FIXTURES = REPO / "tests" / "fixtures" / "reference"
EXPECTED = REPO / "poc" / "reference" / "expected" / "inventory.json"

FAKE_SYFT = r'''#!/usr/bin/env python3
import json, sys, time
from pathlib import Path
here = Path(__file__).resolve().parent
behaviour = json.loads((here / "behaviour.json").read_text()).get("syft", "ok")
args = sys.argv[1:]
if args[0] == "version":
    print(json.dumps({"version": "9.9.9" if behaviour == "bad-version" else "1.57.0"}))
    sys.exit(0)
if behaviour == "timeout":
    time.sleep(60)
if behaviour == "fail":
    print("token=supersecretvalue boom", file=sys.stderr)
    sys.exit(3)
output = next(a for a in args if a.startswith("syft-json=")).split("=", 1)[1]
name = "builder" if "builder" in args[1] else "final"
if behaviour == "malformed":
    Path(output).write_text("{not json")
elif behaviour == "empty":
    document = json.loads((here / f"{name}.syft.json").read_text())
    document["artifacts"] = []
    Path(output).write_text(json.dumps(document))
else:
    Path(output).write_text((here / f"{name}.syft.json").read_text())
'''

FAKE_GRYPE = r'''#!/usr/bin/env python3
import datetime, json, sys, time
from pathlib import Path
here = Path(__file__).resolve().parent
settings = json.loads((here / "behaviour.json").read_text())
behaviour = settings.get("grype", "ok")
args = sys.argv[1:]
if args[0] == "version":
    print(json.dumps({"version": "9.9.9" if behaviour == "bad-version" else "0.121.2"}))
    sys.exit(0)
if args[:2] == ["db", "status"]:
    built = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30 if behaviour == "stale-db" else 0)
    print(json.dumps({"schemaVersion": "v6.fixture", "from": "fixture", "built": built.strftime("%Y-%m-%dT%H:%M:%SZ"), "valid": behaviour != "invalid-db"}))
    sys.exit(0)
if behaviour == "timeout":
    time.sleep(60)
if behaviour == "fail":
    print("grype failed", file=sys.stderr)
    sys.exit(2)
target = args[0]
output = args[args.index("--file") + 1]
if behaviour == "malformed-null":
    Path(output).write_text(json.dumps({"matches": None, "descriptor": {"name": "grype"}}))
    sys.exit(0)
if behaviour == "malformed-entry":
    Path(output).write_text(json.dumps({"matches": [{"vulnerability": {}}], "descriptor": {"name": "grype"}}))
    sys.exit(0)
key = "build" if "scan-input-build" in target else "builder" if "builder" in target else "final"
matches = settings.get("matches", {}).get(key)
if matches is None:
    matches = json.loads((here / f"{key}.grype.json").read_text())["matches"] if key != "build" else []
Path(output).write_text(json.dumps({"matches": matches, "ignoredMatches": [], "descriptor": {"name": "grype", "version": "0.121.2", "db": {"status": {"built": "x"}}}}))
'''


def cpe_match(vulnerability, name, version, purl, severity="high", fixed=("9.9.9",), kind="cpe-match"):
    """A scanner match in Grype's JSON shape, for scenarios a real database cannot pin down."""
    return {"vulnerability": {"id": vulnerability, "dataSource": f"https://nvd.nist.gov/vuln/detail/{vulnerability}", "namespace": "nvd:cpe",
                              "severity": severity.capitalize(), "description": "Fixture vulnerability.", "cvss": [{"metrics": {"baseScore": 7.5}}],
                              "fix": {"state": "fixed" if fixed else "unknown", "versions": list(fixed)}},
            "relatedVulnerabilities": [],
            "matchDetails": [{"type": kind, "matcher": "stock-matcher", "searchedBy": {"cpes": [f"cpe:2.3:a:x:{name}:{version}:*:*:*:*:*:*:*"]}, "found": {"versionConstraint": "< 9.9.9 (unknown)"}}],
            "artifact": {"name": name, "version": version, "type": "conan", "purl": purl, "cpes": [f"cpe:2.3:a:x:{name}:{version}:*:*:*:*:*:*:*"], "locations": []}}


def make_elf(needed=(), extra=b"", symtab=True, soname=""):
    """A minimal valid ELF64 with one LOAD segment, a dynamic section and optional strings."""
    strtab = b"\x00"
    offsets = []
    for name in list(needed) + ([soname] if soname else []):
        offsets.append(len(strtab))
        strtab += name.encode() + b"\x00"
    header_size, program_size, section_size = 64, 56, 64
    program_count = 2 if needed or soname else 1
    data_start = header_size + program_size * program_count
    strtab_offset = data_start
    dynamic_offset = strtab_offset + len(strtab)
    entries = [(1, offset) for offset in offsets[:len(needed)]]
    if soname:
        entries.append((14, offsets[-1]))
    entries += [(5, strtab_offset), (0, 0)]
    dynamic = b"".join(struct.pack("<qQ", tag, value) for tag, value in entries) if program_count == 2 else b""
    extra_offset = dynamic_offset + len(dynamic)
    section_offset = extra_offset + len(extra)
    sections = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    section_count = 1
    if symtab:
        sections += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, 0, 0, 0, 0, 0, 24)
        section_count = 2
    total = section_offset + len(sections)
    head = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, header_size, section_offset, 0, header_size, program_size, program_count, section_size, section_count, 0)
    programs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 4096)
    if program_count == 2:
        programs += struct.pack("<IIQQQQQQ", 2, 6, dynamic_offset, dynamic_offset, dynamic_offset, len(dynamic), len(dynamic), 8)
    return head + programs + strtab + dynamic + extra + sections


def load_image_builder():
    spec = importlib.util.spec_from_file_location("build_fixture_images", REPO / "poc" / "reference" / "tools" / "build_fixture_images.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONFIG = """
schema_version = "cra.config/1"
[product]
name = "reference-gateway"
version = "1.0.0"
[source]
revision = "abc123"
[scope]
roots = ["."]
[output]
dir = "out"
[[configurations]]
id = "release-static"
conan_graph = "release-static.graph.json"
conan_manifest = "app/conanfile.py"
cmake_build_dir = "app/build-release-static/build/Release"
cmake_config = "Release"
[[configurations]]
id = "debug-shared-lz4"
conan_graph = "debug-shared-lz4.graph.json"
conan_manifest = "app/conanfile.py"
cmake_build_dir = "app/build-debug-shared-lz4/build/Debug"
cmake_config = "Debug"
[[artifacts]]
id = "gateway-release"
path = "app/build-release-static/build/Release/gateway"
configuration = "release-static"
shipped = true
[[artifacts]]
id = "gateway-debug"
path = "app/build-debug-shared-lz4/build/Debug/gateway"
configuration = "debug-shared-lz4"
shipped = false
[[images]]
id = "final"
role = "final"
archive = "reference-final.oci.tar"
[[images]]
id = "builder"
role = "build-stage"
archive = "reference-builder.oci.tar"
[components]
records = ["vendor-components.json"]
[tools]
syft = "tools/syft"
grype = "tools/grype"
timeout_seconds = 30
[analysis]
policy = "policy.toml"
vex = ["vex.json"]
kev = "kev.json"
"""

POLICY = """
schema_version = "cra.policy/1"
version = "test-1"
[vex]
trusted_authors = ["Trusted Team"]
[freshness]
max_vulnerability_data_age_hours = 168
max_kev_age_hours = 720
kev_required = true
[build]
block_severities = ["critical", "high"]
minimum_confidence = "medium"
[release]
block_severities = ["critical", "high", "medium"]
"""


class Workspace:
    """A temporary customer checkout built from captured real tool output."""

    def __init__(self, behaviour=None, graph_paths=True):
        self._temp = tempfile.TemporaryDirectory(prefix="cra-test-")
        self.root = Path(self._temp.name).resolve()
        self.behaviour = behaviour or {}
        self._build()

    def cleanup(self):
        self._temp.cleanup()

    def _rewrite(self, text):
        return text.replace("/build/app", str(self.root / "app"))

    def _build(self):
        root = self.root
        (root / "app").mkdir()
        shutil.copy(REPO / "poc" / "reference" / "app" / "conanfile.py", root / "app" / "conanfile.py")
        for name, cmake_type in (("release-static", "Release"), ("debug-shared-lz4", "Debug")):
            (root / f"{name}.graph.json").write_text(self._rewrite((FIXTURES / f"{name}.graph.json").read_text()))
            tree = root / "app" / f"build-{name}" / "build" / cmake_type
            reply = tree / ".cmake" / "api" / "v1" / "reply"
            reply.mkdir(parents=True)
            for path in (FIXTURES / f"{name}.reply").iterdir():
                (reply / path.name).write_text(self._rewrite(path.read_text()))
        release = root / "app" / "build-release-static" / "build" / "Release" / "gateway"
        release.write_bytes(make_elf(needed=("libstdc++.so.6", "libc.so.6"), extra=b"deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly\x00"))
        debug = root / "app" / "build-debug-shared-lz4" / "build" / "Debug" / "gateway"
        debug.write_bytes(make_elf(needed=("libz.so.1", "libfmtd.so.12", "libc.so.6")))
        builder = load_image_builder()
        builder.build(root / "reference-final.oci.tar", {"etc/os-release": b"ID=debian\n"}, "final")
        builder.build(root / "reference-builder.oci.tar", {"etc/os-release": b"ID=debian\n"}, "builder")
        shutil.copy(REPO / "poc" / "reference" / "records" / "vendor-components.json", root / "vendor-components.json")
        tools = root / "tools"
        tools.mkdir()
        for name, body in (("syft", FAKE_SYFT), ("grype", FAKE_GRYPE)):
            (tools / name).write_text(body)
            (tools / name).chmod(stat.S_IRWXU)
        for name in ("final", "builder"):
            shutil.copy(FIXTURES / f"{name}.syft.json", tools / f"{name}.syft.json")
            shutil.copy(FIXTURES / f"{name}.grype.json", tools / f"{name}.grype.json")
        self.set_behaviour(self.behaviour)
        (root / "cra.toml").write_text(CONFIG)
        (root / "policy.toml").write_text(POLICY)
        self.write_vex([])
        self.write_kev([{"cveID": "CVE-1999-0001"}])

    def set_behaviour(self, behaviour):
        self.behaviour = behaviour
        (self.root / "tools" / "behaviour.json").write_text(json.dumps(behaviour))

    def write_kev(self, entries, released=None):
        released = released or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        (self.root / "kev.json").write_text(json.dumps({"title": "fixture", "catalogVersion": "fixture", "dateReleased": released, "vulnerabilities": entries}))

    def write_vex(self, statements, author="Trusted Team", **document):
        (self.root / "vex.json").write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex", "author": author,
                                                        "timestamp": "2026-01-01T00:00:00Z", "version": 1, "statements": statements, **document}))

    def edit_config(self, old, new):
        path = self.root / "cra.toml"
        text = path.read_text()
        assert old in text, old
        path.write_text(text.replace(old, new))

    def config(self):
        from cra.common.config import load_config
        return load_config(self.root / "cra.toml")

    def collect(self):
        from cra.collector.collect import collect
        return collect(self.config())

    def analyze(self):
        from cra.engine.analyze import run_analysis
        config = self.config()
        self.collect()
        return run_analysis(config.output_dir / "collection", config.analysis, config.tools, config.output_dir / "analysis")

    @property
    def analysis_dir(self):
        return self.root / "out" / "analysis"

    @property
    def collection_dir(self):
        return self.root / "out" / "collection"

    def not_affected(self, vulnerability, purl, **extra):
        return {"vulnerability": {"name": vulnerability}, "products": [{"@id": purl}], "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "The affected function is never called.",
                "timestamp": "2026-01-02T00:00:00Z", **extra}

    def triage_all_blockers(self, result):
        """Scoped decisions for every blocking finding, leaving nothing silently removed."""
        statements = [self.not_affected(f["vulnerability"]["id"], f["component"]["purl"]) for f in result["findings"]
                      if f["presence"]["shipped"] != "no" and f["severity"] in ("critical", "high")]
        self.write_vex(statements)
