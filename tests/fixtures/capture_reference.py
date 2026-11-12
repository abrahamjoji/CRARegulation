#!/usr/bin/env python3
"""Refresh deterministic fixtures from a real reference build (run poc/reference/build_reference.sh first).

Machine paths are rewritten to /build and /conan. Scanner output is trimmed, and a
tiny labelled false match is added by the tests, not here. Nothing else is edited.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "reference"
REF = REPO / "poc" / "reference"
CONAN = REPO / ".cra" / "conan-home"


def clean(text):
    return (text.replace(str(CONAN), "/conan").replace(str(REF / "app"), "/build/app").replace(str(REF), "/build")
            .replace(str(REPO), "/build").replace(str(Path.home()), "/home/ci"))


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    for name, cmake_type in (("release-static", "Release"), ("debug-shared-lz4", "Debug")):
        (OUT / f"{name}.graph.json").write_text(clean((REF / "out" / f"{name}.graph.json").read_text()))
        reply = REF / "app" / f"build-{name}" / "build" / cmake_type / ".cmake" / "api" / "v1" / "reply"
        target = OUT / f"{name}.reply"
        target.mkdir()
        for path in reply.iterdir():
            (target / path.name).write_text(clean(path.read_text()))
    syft, grype = str(REPO / ".tools" / "syft"), str(REPO / ".tools" / "grype")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "GRYPE_DB_AUTO_UPDATE": "false", "SYFT_CHECK_FOR_APP_UPDATE": "false"}
    for name in ("final", "builder"):
        document = json.loads(subprocess.run([syft, "scan", f"oci-archive:{REF}/out/reference-{name}.oci.tar", "-o", "syft-json", "--scope", "squashed", "-q"],
                                             check=True, capture_output=True, env=env, text=True).stdout)
        document.pop("files", None)
        document.pop("artifactRelationships", None)
        (document.get("descriptor") or {}).pop("configuration", None)
        (OUT / f"{name}.syft.json").write_text(clean(json.dumps(document, indent=1, sort_keys=True)))
    keep = {"final": {"CVE-2024-2961": 1, "CVE-2026-5450": 1}, "builder": {"CVE-2024-5535": 1}}
    for name, wanted in keep.items():
        raw = json.loads(subprocess.run([grype, f"sbom:{OUT}/{name}.syft.json", "-o", "json", "-q"], check=True, capture_output=True, env=env, text=True).stdout)
        matches = [item for item in raw["matches"] if item["vulnerability"]["id"] in wanted]
        (OUT / f"{name}.grype.json").write_text(clean(json.dumps({"matches": matches, "ignoredMatches": [], "descriptor": {"name": "grype", "version": raw["descriptor"]["version"]}}, indent=1, sort_keys=True)))
    print(f"Captured fixtures into {OUT}; review with git diff before committing.", file=sys.stderr)


if __name__ == "__main__":
    main()
