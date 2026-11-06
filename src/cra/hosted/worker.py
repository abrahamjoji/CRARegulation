"""Worker: claim, run isolated analysis, store the result, purge what has expired.

A failure in the analysis process is our failure, recorded on the job. It is never
turned into a clean result. See docs/PRODUCTION.md for the OS isolation production needs.
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from ..common.archive import create_tar_gz
from ..common.errors import UntrustedInputError
from ..common.safety import Limits, redact_text, run_tool, tool_environment
from .db import Database, Principal
from .settings import from_environment
from .storage import Storage

RUNNER_LIMITS_OUTPUT = 4096 * 1024 * 1024
CODES = {"worker_timeout": "Analysis exceeded the job time limit."}


def _runner_environment(work):
    # An allow-list: database paths, tokens and storage roots are deliberately absent.
    package_parent = str(Path(__file__).resolve().parents[2])
    extra = {"HOME": str(work), "TMPDIR": str(work), "PYTHONPATH": package_parent, "PYTHONDONTWRITEBYTECODE": "1"}
    return tool_environment(extra, passthrough=("GRYPE_DB_CACHE_DIR",))


def process_job(job, database, storage, settings):
    tenant, project = job["tenant_id"], job["project_id"]
    bundle = storage.bundle(tenant, project, job["id"])
    if not bundle.is_file():
        database.finish_job(job, "failed", error_code="bundle_missing", error_message="The stored evidence bundle is missing.")
        return "failed"
    with tempfile.TemporaryDirectory(prefix="cra-job-") as scratch:
        work = Path(scratch)
        os.chmod(work, 0o700)
        copy = work / "input.tar.gz"
        shutil.copyfile(bundle, copy)
        policy_path = None
        if job.get("policy_toml"):
            policy_path = work / "policy.toml"
            policy_path.write_text(job["policy_toml"], encoding="utf-8")
        request = {"work_dir": str(work), "bundle": str(copy), "policy": str(policy_path) if policy_path else None,
                   "kev": str(settings.kev_path) if settings.kev_path else None, "grype": settings.grype,
                   "scanner_timeout": max(60, settings.job_timeout_seconds - 60)}
        request_file = work / "request.json"
        request_file.write_text(json.dumps(request), encoding="utf-8")
        output = work / "runner.json"
        launcher = ("import sys, runpy; sys.stdin = open(sys.argv[1]); sys.argv = sys.argv[:1]; "
                    "runpy.run_module('cra.hosted.job_runner', run_name='__main__')")
        result = run_tool([sys.executable, "-c", launcher, str(request_file)], stdout_path=output,
                          limits=Limits(timeout_seconds=settings.job_timeout_seconds, output_bytes=RUNNER_LIMITS_OUTPUT),
                          env=_runner_environment(work), cwd=str(work))
        if result.timed_out:
            database.finish_job(job, "failed", error_code="worker_timeout", error_message=CODES["worker_timeout"])
            return "failed"
        try:
            answer = json.loads(output.read_text(encoding="utf-8") or "{}")
        except (OSError, ValueError):
            answer = {}
        if result.returncode == 3:
            database.finish_job(job, "failed", error_code=str(answer.get("error_code", "analysis_failed"))[:64],
                                error_message=redact_text(str(answer.get("error_message", "")))[0])
            return "failed"
        analysis = work / "analysis"
        if result.returncode or not (analysis / "result.json").is_file() or answer.get("scan_status") not in ("complete", "incomplete"):
            # Crash of our own process. Leave it for retry; repeated crashes end in a failed job.
            print(f"job {job['id']}: analysis process failed with {result.returncode}: {redact_text(result.stderr[:500])[0]}", file=sys.stderr)
            database.requeue(job)
            return "retry"
        storage_path = storage.result(tenant, project, job["id"])
        temporary = storage_path.with_suffix(".tmp")
        create_tar_gz(analysis, temporary)
        os.replace(temporary, storage_path)
        storage_path.chmod(0o600)
        if not database.finish_job(job, "completed", scan_status=answer["scan_status"]):
            # Deleted while running: the deletion wins.
            storage.delete_job(tenant, project, job["id"])
            return "deleted"
    return "completed"


def purge_expired(database, storage, now=None):
    """Apply retention. The audit record of the deletion stays."""
    count = 0
    for row in database.expired_jobs(now):
        storage.delete_job(row["tenant_id"], row["project_id"], row["id"])
        database.mark_deleted(Principal(row["tenant_id"], row["project_id"], "retention", frozenset()), row["id"], action="job.retention_delete")
        count += 1
    return count


def run_once(database, storage, settings):
    purge_expired(database, storage)
    job = database.claim_job(settings.lease_seconds, settings.max_attempts)
    if job is None or job.get("exhausted"):
        return None if job is None else "failed"
    try:
        return process_job(job, database, storage, settings)
    except (OSError, UntrustedInputError) as exc:
        print(f"job {job['id']}: worker error {type(exc).__name__}: {redact_text(str(exc))[0]}", file=sys.stderr)
        database.requeue(job)
        return "retry"


def main():
    settings = from_environment()
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = Database(settings.database)
    database.initialize()
    storage = Storage(settings.storage)
    while True:
        if run_once(database, storage, settings) is None:
            time.sleep(2)


if __name__ == "__main__":
    main()
