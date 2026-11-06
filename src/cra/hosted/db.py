"""Control-plane records. SQLite for this version; see docs/PRODUCTION.md for what must change.

Every read that returns customer data takes the project from the authenticated
principal. There is no function that accepts a tenant identifier from a client.
"""
import datetime as dt
import hashlib
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, retention_days INTEGER NOT NULL,
  policy_toml TEXT, created_at TEXT NOT NULL, UNIQUE (tenant_id, name));
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL,
  label TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), idempotency_key TEXT NOT NULL, bundle_sha256 TEXT NOT NULL,
  bundle_bytes INTEGER NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, lease_until TEXT, created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, error_code TEXT, error_message TEXT, scan_status TEXT, deleted_at TEXT, UNIQUE (project_id, idempotency_key));
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs (status, created_at);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, tenant_id TEXT, project_id TEXT, actor TEXT NOT NULL, action TEXT NOT NULL,
  subject TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
"""
ACTIVE = ("queued", "running")
TERMINAL = ("completed", "failed", "deleted")
SCOPES = {"submit", "read", "delete"}
TOKEN_PREFIX = "cra_"


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def iso(moment=None):
    return (moment or utcnow()).isoformat(timespec="seconds")


def hash_token(token):
    # Tokens are 256-bit random values, so a fast hash is the right tool here. Passwords would need more.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    project_id: str
    token_id: str
    scopes: frozenset


class Database:
    def __init__(self, path):
        self.path = str(path)

    @contextmanager
    def connect(self, immediate=False):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def initialize(self):
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(SCHEMA)
        finally:
            connection.close()

    def audit(self, action, subject, *, tenant_id=None, project_id=None, actor="system", detail="", connection=None):
        statement = "INSERT INTO audit (at, tenant_id, project_id, actor, action, subject, detail) VALUES (?,?,?,?,?,?,?)"
        values = (iso(), tenant_id, project_id, actor, action, subject, detail[:1000])
        if connection is not None:
            connection.execute(statement, values)
            return
        with self.connect(immediate=True) as own:
            own.execute(statement, values)

    # Administration: reached from the operator CLI only, never from the API.
    def create_tenant(self, name):
        identifier = uuid.uuid4().hex
        with self.connect(immediate=True) as connection:
            connection.execute("INSERT INTO tenants VALUES (?,?,?)", (identifier, name, iso()))
            self.audit("tenant.create", identifier, tenant_id=identifier, actor="operator", connection=connection)
        return identifier

    def create_project(self, tenant_id, name, retention_days=90, policy_toml=None):
        identifier = uuid.uuid4().hex
        with self.connect(immediate=True) as connection:
            connection.execute("INSERT INTO projects VALUES (?,?,?,?,?,?)", (identifier, tenant_id, name, retention_days, policy_toml, iso()))
            self.audit("project.create", identifier, tenant_id=tenant_id, project_id=identifier, actor="operator", connection=connection)
        return identifier

    def create_token(self, project_id, scopes, label="", expires_at=None):
        """Return the secret once. Only its hash is stored."""
        if not scopes or not set(scopes) <= SCOPES:
            raise ValueError(f"scopes must come from {sorted(SCOPES)}")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        identifier = uuid.uuid4().hex
        with self.connect(immediate=True) as connection:
            project = connection.execute("SELECT tenant_id FROM projects WHERE id=?", (project_id,)).fetchone()
            if project is None:
                raise ValueError("unknown project")
            connection.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,NULL,?)", (identifier, project_id, hash_token(token), " ".join(sorted(scopes)), label, iso(expires_at) if expires_at else None, iso()))
            self.audit("token.create", identifier, tenant_id=project["tenant_id"], project_id=project_id, actor="operator", detail=label, connection=connection)
        return token, identifier

    def revoke_token(self, token_id):
        with self.connect(immediate=True) as connection:
            row = connection.execute("SELECT t.project_id, p.tenant_id FROM tokens t JOIN projects p ON p.id=t.project_id WHERE t.id=?", (token_id,)).fetchone()
            if row is None:
                raise ValueError("unknown token")
            connection.execute("UPDATE tokens SET revoked_at=? WHERE id=?", (iso(), token_id))
            self.audit("token.revoke", token_id, tenant_id=row["tenant_id"], project_id=row["project_id"], actor="operator", connection=connection)

    def authenticate(self, token):
        """Return the principal for a token. The tenant comes only from this server-side lookup."""
        if not token or not token.startswith(TOKEN_PREFIX) or len(token) > 256:
            return None
        with self.connect() as connection:
            row = connection.execute(
                "SELECT t.id, t.project_id, t.scopes, t.expires_at, t.revoked_at, p.tenant_id FROM tokens t JOIN projects p ON p.id=t.project_id WHERE t.token_hash=?",
                (hash_token(token),)).fetchone()
        if row is None or row["revoked_at"]:
            return None
        if row["expires_at"] and dt.datetime.fromisoformat(row["expires_at"]) <= utcnow():
            return None
        return Principal(row["tenant_id"], row["project_id"], row["id"], frozenset(row["scopes"].split()))

    # Jobs. Every customer-facing function scopes by the principal's project.
    def create_job(self, principal, idempotency_key, bundle_sha256, bundle_bytes, limit):
        """Return (job, created). The same key with different content is a conflict (None, False)."""
        with self.connect(immediate=True) as connection:
            existing = connection.execute("SELECT * FROM jobs WHERE project_id=? AND idempotency_key=?", (principal.project_id, idempotency_key)).fetchone()
            if existing is not None:
                if existing["bundle_sha256"] != bundle_sha256:
                    return None, False
                if existing["status"] == "failed":
                    # A retry of a failed job runs it again instead of replaying the failure forever.
                    connection.execute("UPDATE jobs SET status='queued', attempts=0, error_code=NULL, error_message=NULL, lease_until=NULL, updated_at=? WHERE id=?", (iso(), existing["id"]))
                    self.audit("job.retry", existing["id"], tenant_id=principal.tenant_id, project_id=principal.project_id, actor=principal.token_id, connection=connection)
                    return dict(connection.execute("SELECT * FROM jobs WHERE id=?", (existing["id"],)).fetchone()), False
                return dict(existing), False
            active = connection.execute(f"SELECT COUNT(*) FROM jobs WHERE project_id=? AND status IN ({','.join('?' * len(ACTIVE))})", (principal.project_id, *ACTIVE)).fetchone()[0]
            if active >= limit:
                raise OverflowError("too many active jobs")
            identifier = uuid.uuid4().hex
            connection.execute("INSERT INTO jobs (id, project_id, idempotency_key, bundle_sha256, bundle_bytes, status, created_at, updated_at) VALUES (?,?,?,?,?,'queued',?,?)",
                               (identifier, principal.project_id, idempotency_key, bundle_sha256, bundle_bytes, iso(), iso()))
            self.audit("job.submit", identifier, tenant_id=principal.tenant_id, project_id=principal.project_id, actor=principal.token_id, detail=bundle_sha256, connection=connection)
            job = connection.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()
        return dict(job), True

    def get_job(self, principal, job_id):
        """Another project's job does not exist as far as this caller can tell."""
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=? AND project_id=?", (job_id, principal.project_id)).fetchone()
        return dict(row) if row else None

    def mark_deleted(self, principal, job_id, *, action="job.delete"):
        with self.connect(immediate=True) as connection:
            # The key is released, so resubmitting deleted evidence creates a new job.
            connection.execute("UPDATE jobs SET status='deleted', deleted_at=?, updated_at=?, lease_until=NULL, idempotency_key='deleted:' || id WHERE id=? AND project_id=?", (iso(), iso(), job_id, principal.project_id))
            self.audit(action, job_id, tenant_id=principal.tenant_id, project_id=principal.project_id, actor=principal.token_id, connection=connection)

    def audit_records(self, principal, limit=200):
        with self.connect() as connection:
            rows = connection.execute("SELECT at, actor, action, subject, detail FROM audit WHERE project_id=? ORDER BY id DESC LIMIT ?", (principal.project_id, min(limit, 1000))).fetchall()
        return [dict(row) for row in rows]

    # Worker: internal, reached only from the worker process.
    def claim_job(self, lease_seconds, max_attempts):
        """Atomically claim the oldest job, including ones whose worker died mid-lease."""
        now = utcnow()
        with self.connect(immediate=True) as connection:
            row = connection.execute("""SELECT j.*, p.tenant_id, p.policy_toml FROM jobs j JOIN projects p ON p.id=j.project_id
                WHERE j.status='queued' OR (j.status='running' AND j.lease_until < ?) ORDER BY j.created_at LIMIT 1""", (iso(now),)).fetchone()
            if row is None:
                return None
            job = dict(row)
            if job["attempts"] >= max_attempts:
                connection.execute("UPDATE jobs SET status='failed', error_code='worker_retries_exhausted', error_message=?, updated_at=? WHERE id=?",
                                   ("Analysis stopped after repeated worker failures.", iso(), job["id"]))
                self.audit("job.failed", job["id"], tenant_id=job["tenant_id"], project_id=job["project_id"], detail="retries exhausted", connection=connection)
                return {"exhausted": True, **job}
            lease = iso(now + dt.timedelta(seconds=lease_seconds))
            connection.execute("UPDATE jobs SET status='running', attempts=attempts+1, lease_until=?, updated_at=? WHERE id=?", (lease, iso(), job["id"]))
            job.update(status="running", attempts=job["attempts"] + 1)
        return job

    def finish_job(self, job, status, *, scan_status=None, error_code=None, error_message=None):
        with self.connect(immediate=True) as connection:
            current = connection.execute("SELECT status FROM jobs WHERE id=?", (job["id"],)).fetchone()
            if current is None or current["status"] == "deleted":
                return False
            connection.execute("UPDATE jobs SET status=?, scan_status=?, error_code=?, error_message=?, lease_until=NULL, updated_at=? WHERE id=?",
                               (status, scan_status, error_code, (error_message or "")[:1000] or None, iso(), job["id"]))
            self.audit(f"job.{status}", job["id"], tenant_id=job["tenant_id"], project_id=job["project_id"], detail=error_code or scan_status or "", connection=connection)
        return True

    def requeue(self, job):
        with self.connect(immediate=True) as connection:
            connection.execute("UPDATE jobs SET status='queued', lease_until=NULL, updated_at=? WHERE id=? AND status='running'", (iso(), job["id"]))

    def expired_jobs(self, now=None):
        """Terminal jobs past their project's retention period."""
        now = now or utcnow()
        with self.connect() as connection:
            rows = connection.execute("""SELECT j.id, j.project_id, j.created_at, j.status, p.tenant_id, p.retention_days FROM jobs j JOIN projects p ON p.id=j.project_id
                WHERE j.status IN ('completed','failed')""").fetchall()
        return [dict(row) for row in rows if dt.datetime.fromisoformat(row["created_at"]) + dt.timedelta(days=row["retention_days"]) <= now]
