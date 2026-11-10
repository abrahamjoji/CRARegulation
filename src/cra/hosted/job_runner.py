"""One analysis in a credential-free process. Started by the worker; never reached from the API.

It sees a copy of one customer's bundle and nothing else it needs. It parses JSON
and runs a pinned scanner over an SBOM. It runs no customer CMake files or recipes.
"""
import json
import sys
from pathlib import Path

from ..common.archive import safe_extract
from ..common.config import Analysis, Tools
from ..common.errors import CraError, UntrustedInputError
from ..engine.analyze import run_analysis
from .api import UPLOAD_LIMITS


def main():
    job = json.loads(sys.stdin.read())
    work = Path(job["work_dir"])
    extracted = safe_extract(job["bundle"], work / "bundle", UPLOAD_LIMITS)
    vex = sorted((extracted / "vex").glob("*.json")) if (extracted / "vex").is_dir() else []
    analysis = Analysis(policy=Path(job["policy"]) if job.get("policy") else None, vex=vex, kev=Path(job["kev"]) if job.get("kev") else None)
    tools = Tools(grype=job["grype"], timeout_seconds=job["scanner_timeout"])
    result = run_analysis(extracted / "collection", analysis, tools, work / "analysis")
    print(json.dumps({"scan_status": result["scan_status"]}))


def entry():
    try:
        main()
    except (UntrustedInputError, CraError) as exc:
        print(json.dumps({"error_code": getattr(exc, "code", "analysis_failed"), "error_message": str(exc)[:800]}))
        sys.exit(3)


if __name__ == "__main__":
    entry()
