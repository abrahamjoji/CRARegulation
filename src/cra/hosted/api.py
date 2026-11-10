"""Hosted API. Authorization comes from the token, and never from anything a client states.

Run with: uvicorn --factory cra.hosted.api:create_app
"""
import hashlib
import re
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .. import __version__
from ..common.archive import ArchiveLimits, inspect_tar
from ..common.errors import UntrustedInputError
from .db import Database, Principal
from .settings import Settings, from_environment
from .storage import Storage

_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_JOB = re.compile(r"^[0-9a-f]{32}$")
UPLOAD_LIMITS = ArchiveLimits(max_members=5000, max_total_bytes=2048 * 1024 * 1024, max_member_bytes=1024 * 1024 * 1024)


def _public_job(job):
    return {"job_id": job["id"], "status": job["status"], "attempts": job["attempts"], "created_at": job["created_at"], "updated_at": job["updated_at"],
            "scan_status": job["scan_status"], "bundle_sha256": job["bundle_sha256"],
            "error": {"code": job["error_code"], "message": job["error_message"]} if job["error_code"] else None}


def create_app(settings: Settings | None = None):
    settings = settings or from_environment()
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = Database(settings.database)
    database.initialize()
    storage = Storage(settings.storage)
    app = FastAPI(title="CRA evidence service", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    bearer = HTTPBearer(auto_error=False)

    def principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
        found = database.authenticate(credentials.credentials) if credentials else None
        if found is None:
            database.audit("auth.denied", "api")
            raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "A valid project token is required."}, headers={"WWW-Authenticate": "Bearer"})
        return found

    def require(scope):
        def check(found: Principal = Depends(principal)) -> Principal:
            if scope not in found.scopes:
                database.audit("auth.forbidden", scope, tenant_id=found.tenant_id, project_id=found.project_id, actor=found.token_id)
                raise HTTPException(status_code=403, detail={"code": "forbidden", "message": f"This token lacks the {scope} scope."})
            return found
        return check

    def lookup(found, job_id):
        job = database.get_job(found, job_id) if _JOB.match(job_id) else None
        if job is None:
            # A job in another project gets the same answer as a job that does not exist.
            raise HTTPException(status_code=404, detail={"code": "job_not_found", "message": "No such job."})
        return job

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.post("/v1/submissions", status_code=202)
    async def submit(request: Request, found: Principal = Depends(require("submit"))):
        key = request.headers.get("idempotency-key", "")
        declared = request.headers.get("x-content-sha256", "").lower()
        if not _KEY.match(key):
            raise HTTPException(status_code=400, detail={"code": "idempotency_key_invalid", "message": "Idempotency-Key must be 8 to 128 safe characters."})
        if not _SHA.match(declared):
            raise HTTPException(status_code=400, detail={"code": "content_hash_invalid", "message": "X-Content-SHA256 must be a lowercase SHA-256 hex digest."})
        if request.headers.get("content-type") != "application/gzip":
            raise HTTPException(status_code=415, detail={"code": "media_type", "message": "Upload an application/gzip evidence bundle."})
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail={"code": "upload_too_large", "message": f"The limit is {settings.max_upload_bytes} bytes."})
        temporary = storage.incoming_path(found.tenant_id, found.project_id, uuid.uuid4().hex)
        digest, received = hashlib.sha256(), 0
        try:
            with temporary.open("wb") as output:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > settings.max_upload_bytes:
                        raise HTTPException(status_code=413, detail={"code": "upload_too_large", "message": f"The limit is {settings.max_upload_bytes} bytes."})
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != declared:
                raise HTTPException(status_code=400, detail={"code": "content_hash_mismatch", "message": "The upload does not match X-Content-SHA256."})
            try:
                # Decompression is slow on purpose-built input, so it stays off the event loop.
                members = await run_in_threadpool(inspect_tar, temporary, UPLOAD_LIMITS)
            except UntrustedInputError as exc:
                database.audit("job.rejected", exc.code, tenant_id=found.tenant_id, project_id=found.project_id, actor=found.token_id)
                raise HTTPException(status_code=422, detail={"code": exc.code, "message": "The evidence bundle failed validation."}) from exc
            if "collection/collection.json" not in members or "collection/manifest.json" not in members:
                raise HTTPException(status_code=422, detail={"code": "bundle_incomplete", "message": "The bundle needs collection/collection.json and collection/manifest.json."})
            try:
                job, created = await run_in_threadpool(database.create_job, found, key, declared, received, settings.max_active_jobs_per_project)
            except OverflowError as exc:
                raise HTTPException(status_code=429, detail={"code": "too_many_active_jobs", "message": "Wait for active jobs to finish."}, headers={"Retry-After": "30"}) from exc
            if job is None:
                raise HTTPException(status_code=409, detail={"code": "idempotency_conflict", "message": "This key was already used with different content."})
            if created:
                storage.adopt_upload(temporary, found.tenant_id, found.project_id, job["id"])
            return JSONResponse(status_code=202, content={**_public_job(job), "idempotent_replay": not created})
        finally:
            temporary.unlink(missing_ok=True)

    @app.get("/v1/jobs/{job_id}")
    def job_status(job_id: str, found: Principal = Depends(require("read"))):
        return _public_job(lookup(found, job_id))

    @app.get("/v1/jobs/{job_id}/result")
    def job_result(job_id: str, found: Principal = Depends(require("read"))):
        job = lookup(found, job_id)
        if job["status"] != "completed":
            raise HTTPException(status_code=409, detail={"code": "result_not_ready", "message": f"The job is {job['status']}.", "status": job["status"]})
        path = storage.result(found.tenant_id, found.project_id, job["id"])
        if not path.is_file():
            raise HTTPException(status_code=410, detail={"code": "result_gone", "message": "The result is no longer stored."})
        database.audit("result.read", job["id"], tenant_id=found.tenant_id, project_id=found.project_id, actor=found.token_id)
        return FileResponse(path, media_type="application/gzip", filename="result.tar.gz")

    @app.delete("/v1/jobs/{job_id}")
    def job_delete(job_id: str, found: Principal = Depends(require("delete"))):
        job = lookup(found, job_id)
        storage.delete_job(found.tenant_id, found.project_id, job["id"])
        database.mark_deleted(found, job["id"])
        return {"job_id": job["id"], "status": "deleted"}

    @app.get("/v1/audit")
    def audit(found: Principal = Depends(require("read"))):
        return {"records": database.audit_records(found)}

    @app.exception_handler(HTTPException)
    async def structured(_, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)

    return app
