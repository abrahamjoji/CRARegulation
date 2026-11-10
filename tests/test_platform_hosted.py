"""Hosted API and worker. Uses Starlette's in-process client, a real worker subprocess, and fake scanners."""
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path

import helpers
from helpers import Workspace

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    from fastapi.testclient import TestClient
    HAVE_HOSTED = True
except ImportError:
    HAVE_HOSTED = False

# TestClient's thread bridge requires socketpair wakeups. Some restricted execution
# environments allow creating sockets but deny send(), otherwise hanging the suite.
HOSTED_SKIP_REASON = "hosted extras are not installed"
if HAVE_HOSTED:
    try:
        left, right = socket.socketpair()
        try:
            left.settimeout(0.2)
            right.settimeout(0.2)
            left.send(b"x")
            if right.recv(1) != b"x":
                raise OSError("socketpair wakeup failed")
        finally:
            left.close()
            right.close()
    except OSError as exc:
        HAVE_HOSTED = False
        HOSTED_SKIP_REASON = f"hosted tests require socketpair wakeups; environment denied them: {exc}"

if HAVE_HOSTED:
    from cra.collector import hosted_client
    from cra.common.errors import AuthError, ConfigError, OperationalError
    from cra.common.safety import read_json
    from cra.hosted.api import create_app
    from cra.hosted.db import Database, hash_token, utcnow
    from cra.hosted.settings import Settings
    from cra.hosted.storage import Storage
    from cra.hosted.worker import process_job, purge_expired, run_once


def tar_gz(members):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return data.getvalue()


MINIMAL = {"collection/collection.json": b"{}", "collection/manifest.json": b"{}"}


@unittest.skipUnless(HAVE_HOSTED, HOSTED_SKIP_REASON)
class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.data = Path(self._t.name)
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        self.settings = Settings(data_dir=self.data, grype=str(self.ws.root / "tools" / "grype"), kev_path=self.ws.root / "kev.json",
                                 max_upload_bytes=8 * 1024 * 1024, max_active_jobs_per_project=4, job_timeout_seconds=120)
        self.client = TestClient(create_app(self.settings), raise_server_exceptions=False)
        self.db = Database(self.settings.database)
        self.storage = Storage(self.settings.storage)
        self.tenant_a = self.db.create_tenant("tenant-a")
        self.tenant_b = self.db.create_tenant("tenant-b")
        policy = (self.ws.root / "policy.toml").read_text()
        self.project_a = self.db.create_project(self.tenant_a, "gateway", policy_toml=policy)
        self.project_b = self.db.create_project(self.tenant_b, "gateway", policy_toml=policy)
        self.token_a = self.db.create_token(self.project_a, ["submit", "read", "delete"])[0]
        self.token_b = self.db.create_token(self.project_b, ["submit", "read", "delete"])[0]

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def post(self, body=None, token=None, key="key-00000001", digest=None, headers=None):
        body = tar_gz(MINIMAL) if body is None else body
        return self.client.post("/v1/submissions", content=body, headers={
            **self.auth(token or self.token_a), "Content-Type": "application/gzip", "Idempotency-Key": key,
            "X-Content-SHA256": digest or hashlib.sha256(body).hexdigest(), **(headers or {})})

    def real_bundle(self):
        config = self.ws.config()
        self.ws.collect()
        work = tempfile.mkdtemp(dir=self.data)
        return hosted_client.build_upload(config, config.output_dir / "collection", work).read_bytes()


class Authentication(Base):
    def test_no_or_bad_token_is_rejected(self):
        self.assertEqual(self.client.get("/v1/audit").status_code, 401)
        self.assertEqual(self.client.get("/v1/audit", headers=self.auth("cra_wrong")).status_code, 401)
        self.assertEqual(self.client.get("/v1/audit", headers=self.auth("nonsense")).status_code, 401)
        self.assertEqual(self.client.get("/v1/audit", headers={"Authorization": "Basic abc"}).status_code, 401)

    def test_scope_is_enforced(self):
        read_only = self.db.create_token(self.project_a, ["read"])[0]
        self.assertEqual(self.post(token=read_only).status_code, 403)
        job = self.post().json()["job_id"]
        self.assertEqual(self.client.delete(f"/v1/jobs/{job}", headers=self.auth(read_only)).status_code, 403)
        submit_only = self.db.create_token(self.project_a, ["submit"])[0]
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(submit_only)).status_code, 403)

    def test_expired_and_revoked_tokens_fail(self):
        expired = self.db.create_token(self.project_a, ["read"], expires_at=utcnow() - dt.timedelta(days=1))[0]
        self.assertEqual(self.client.get("/v1/audit", headers=self.auth(expired)).status_code, 401)
        token, identifier = self.db.create_token(self.project_a, ["read"])
        self.assertEqual(self.client.get("/v1/audit", headers=self.auth(token)).status_code, 200)
        self.db.revoke_token(identifier)
        self.assertEqual(self.client.get("/v1/audit", headers=self.auth(token)).status_code, 401)

    def test_token_is_stored_only_as_a_hash(self):
        with self.db.connect() as connection:
            rows = [row["token_hash"] for row in connection.execute("SELECT token_hash FROM tokens").fetchall()]
        self.assertIn(hash_token(self.token_a), rows)
        self.assertNotIn(self.token_a, rows)
        self.assertNotIn(self.token_a.encode(), self.settings.database.read_bytes())

    def test_api_docs_and_schema_are_not_exposed(self):
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 404)


class CrossTenant(Base):
    def test_other_tenants_job_is_not_visible(self):
        job = self.post().json()["job_id"]
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).status_code, 200)
        for call in (self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_b)),
                     self.client.get(f"/v1/jobs/{job}/result", headers=self.auth(self.token_b)),
                     self.client.delete(f"/v1/jobs/{job}", headers=self.auth(self.token_b))):
            self.assertEqual(call.status_code, 404)
            self.assertEqual(call.json()["error"]["code"], "job_not_found")
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).json()["status"], "queued")

    def test_client_supplied_tenant_is_ignored(self):
        response = self.post(token=self.token_b, headers={"X-Tenant-ID": self.tenant_a, "X-Project-ID": self.project_a}, key="key-spoofing")
        job = response.json()["job_id"]
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).status_code, 404)
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_b)).status_code, 200)
        self.assertTrue(self.storage.bundle(self.tenant_b, self.project_b, job).is_file())

    def test_second_project_of_same_tenant_is_separate(self):
        other = self.db.create_project(self.tenant_a, "other", policy_toml=None)
        token = self.db.create_token(other, ["read"])[0]
        job = self.post().json()["job_id"]
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(token)).status_code, 404)

    def test_audit_is_project_scoped(self):
        job = self.post().json()["job_id"]
        records = self.client.get("/v1/audit", headers=self.auth(self.token_b)).json()["records"]
        self.assertFalse(any(row["subject"] == job for row in records))
        records = self.client.get("/v1/audit", headers=self.auth(self.token_a)).json()["records"]
        self.assertTrue(any(row["subject"] == job and row["action"] == "job.submit" for row in records))

    def test_same_key_in_two_tenants_gives_two_jobs(self):
        first = self.post(key="key-shared-0").json()["job_id"]
        second = self.post(token=self.token_b, key="key-shared-0").json()["job_id"]
        self.assertNotEqual(first, second)

    def test_job_id_format_blocks_path_tricks(self):
        for bad in ("..%2f..%2fetc", "ZZZ", "0" * 31):
            self.assertIn(self.client.get(f"/v1/jobs/{bad}", headers=self.auth(self.token_a)).status_code, (404,))

    def test_storage_refuses_non_generated_path_parts(self):
        with self.assertRaises(ValueError):
            self.storage.job_dir("../../evil", self.project_a, "0" * 32)


class Uploads(Base):
    def code(self, response):
        return response.json()["error"]["code"]

    def test_upload_bundle_is_reproducible_so_retries_reuse_the_key(self):
        config = self.ws.config()
        self.ws.collect()
        first = hosted_client.build_upload(config, config.output_dir / "collection", tempfile.mkdtemp(dir=self.data)).read_bytes()
        time.sleep(1.1)
        second = hosted_client.build_upload(config, config.output_dir / "collection", tempfile.mkdtemp(dir=self.data)).read_bytes()
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())

    def test_idempotent_replay_and_conflict(self):
        body = tar_gz(MINIMAL)
        first = self.post(body=body)
        second = self.post(body=body)
        self.assertEqual(first.status_code, 202)
        self.assertFalse(first.json()["idempotent_replay"])
        self.assertEqual(second.json()["job_id"], first.json()["job_id"])
        self.assertTrue(second.json()["idempotent_replay"])
        self.assertEqual(self.code(self.post(body=tar_gz({**MINIMAL, "collection/extra": b"x"}))), "idempotency_conflict")

    def test_header_validation(self):
        self.assertEqual(self.code(self.post(key="short")), "idempotency_key_invalid")
        self.assertEqual(self.code(self.post(key="bad key with spaces")), "idempotency_key_invalid")
        self.assertEqual(self.code(self.post(digest="abc")), "content_hash_invalid")
        self.assertEqual(self.code(self.post(digest="0" * 64)), "content_hash_mismatch")
        self.assertEqual(self.code(self.post(headers={"Content-Type": "text/plain"})), "media_type")

    def test_oversized_upload(self):
        big = os.urandom(self.settings.max_upload_bytes + 1)
        self.assertEqual(self.post(body=big).status_code, 413)

    def test_hostile_archives_are_rejected_and_not_stored(self):
        def traversal():
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                info = tarfile.TarInfo("../../evil")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            return data.getvalue()

        def symlink():
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                info = tarfile.TarInfo("collection/collection.json")
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                archive.addfile(info)
            return data.getvalue()

        for index, (body, code) in enumerate(((traversal(), "archive_traversal"), (symlink(), "archive_link"), (b"not a tar", "archive_invalid"),
                                              (tar_gz({"other": b"x"}), "bundle_incomplete"))):
            response = self.post(body=body, key=f"key-hostile-{index}")
            self.assertEqual(response.status_code, 422)
            self.assertEqual(self.code(response), code)
        with self.db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
        self.assertEqual(list(self.settings.storage.rglob("*.tar.gz")), [])

    def test_active_job_limit(self):
        for index in range(4):
            self.assertEqual(self.post(body=tar_gz({**MINIMAL, "n": str(index).encode()}), key=f"key-limit-{index}").status_code, 202)
        response = self.post(body=tar_gz({**MINIMAL, "n": b"9"}), key="key-limit-9")
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)

    def test_result_not_ready(self):
        job = self.post().json()["job_id"]
        response = self.client.get(f"/v1/jobs/{job}/result", headers=self.auth(self.token_a))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.code(response), "result_not_ready")


class Worker(Base):
    def submit_real(self):
        response = self.post(body=self.real_bundle(), key="key-real-0001")
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()["job_id"]

    def test_end_to_end_analysis_in_an_isolated_process(self):
        job = self.submit_real()
        self.assertEqual(run_once(self.db, self.storage, self.settings), "completed")
        status = self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).json()
        self.assertEqual((status["status"], status["scan_status"]), ("completed", "complete"))
        response = self.client.get(f"/v1/jobs/{job}/result", headers=self.auth(self.token_a))
        self.assertEqual(response.status_code, 200)
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
            names = archive.getnames()
            result = json.loads(archive.extractfile("result.json").read())
        self.assertIn("manifest.json", names)
        self.assertEqual(result["evaluation"]["build"]["outcome"], "policy_blocked")
        self.assertEqual(result["policy"]["version"], "test-1")

    def test_runner_has_no_credentials_or_control_plane_access(self):
        """The fake scanner records what it can see; tokens and server paths must be absent."""
        spy = self.ws.root / "tools" / "grype"
        original = spy.read_text()
        record = self.data / "env-record.json"
        spy.write_text(original.replace("args = sys.argv[1:]", f"import os; Path({str(record)!r}).write_text(json.dumps(dict(os.environ)))\nargs = sys.argv[1:]", 1))
        os.environ["CRA_TOKEN"] = self.token_a
        os.environ["CRA_SERVER_DATA"] = str(self.data)
        self.addCleanup(os.environ.pop, "CRA_TOKEN")
        self.addCleanup(os.environ.pop, "CRA_SERVER_DATA")
        self.submit_real()
        self.assertEqual(run_once(self.db, self.storage, self.settings), "completed")
        seen = json.loads(record.read_text())
        self.assertNotIn("CRA_TOKEN", seen)
        self.assertNotIn("CRA_SERVER_DATA", seen)
        self.assertNotIn(self.token_a, json.dumps(seen))
        self.assertNotIn(str(self.settings.database), json.dumps(seen))

    def test_scanner_only_is_executed_and_never_customer_recipes(self):
        spy = self.ws.root / "tools" / "grype"
        log = self.data / "argv.log"
        original = spy.read_text()
        spy.write_text(original.replace("args = sys.argv[1:]", f"args = sys.argv[1:]\nopen({str(log)!r}, 'a').write(' '.join(args) + chr(10))", 1))
        marker = self.data / "recipe-ran"
        (self.ws.root / "app" / "conanfile.py").write_text(f"import os\nos.system('touch {marker}')\n")
        self.submit_real()
        self.assertEqual(run_once(self.db, self.storage, self.settings), "completed")
        self.assertFalse(marker.exists())
        lines = log.read_text().splitlines()
        self.assertTrue(any(line.startswith("sbom:") for line in lines))
        self.assertTrue(all(line.startswith(("sbom:", "version", "db status")) for line in lines))

    def test_scanner_failure_gives_incomplete_result_not_a_pass(self):
        self.ws.set_behaviour({"grype": "fail"})
        job = self.submit_real()
        self.assertEqual(run_once(self.db, self.storage, self.settings), "completed")
        self.assertEqual(self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).json()["scan_status"], "incomplete")

    def test_bad_bundle_fails_the_job_with_a_safe_error(self):
        response = self.post(key="key-badbundle")
        job = response.json()["job_id"]
        self.assertEqual(run_once(self.db, self.storage, self.settings), "failed")
        status = self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).json()
        self.assertEqual(status["status"], "failed")
        self.assertTrue(status["error"]["code"])
        self.assertNotIn(str(self.data), json.dumps(status))
        self.assertEqual(self.client.get(f"/v1/jobs/{job}/result", headers=self.auth(self.token_a)).status_code, 409)

    def test_crashed_worker_lease_expires_and_retries_are_bounded(self):
        job = self.post(key="key-crashlease").json()["job_id"]
        for _ in range(self.settings.max_attempts):
            claimed = self.db.claim_job(-1, self.settings.max_attempts)
            self.assertEqual(claimed["id"], job)
        final = self.db.claim_job(-1, self.settings.max_attempts)
        self.assertTrue(final["exhausted"])
        status = self.client.get(f"/v1/jobs/{job}", headers=self.auth(self.token_a)).json()
        self.assertEqual((status["status"], status["error"]["code"]), ("failed", "worker_retries_exhausted"))

    def test_job_is_claimed_once(self):
        self.post(key="key-claimonce")
        self.assertIsNotNone(self.db.claim_job(600, 3))
        self.assertIsNone(self.db.claim_job(600, 3))

    def test_delete_removes_evidence_and_keeps_audit(self):
        job = self.submit_real()
        run_once(self.db, self.storage, self.settings)
        directory = self.storage.job_dir(self.tenant_a, self.project_a, job)
        self.assertTrue(directory.exists())
        response = self.client.delete(f"/v1/jobs/{job}", headers=self.auth(self.token_a))
        self.assertEqual(response.json()["status"], "deleted")
        self.assertFalse(directory.exists())
        self.assertEqual(self.client.get(f"/v1/jobs/{job}/result", headers=self.auth(self.token_a)).status_code, 409)
        actions = [row["action"] for row in self.client.get("/v1/audit", headers=self.auth(self.token_a)).json()["records"]]
        self.assertIn("job.delete", actions)

    def test_retry_of_failed_job_runs_again(self):
        body = tar_gz(MINIMAL)
        first = self.post(body=body, key="key-retryfail").json()["job_id"]
        self.assertEqual(run_once(self.db, self.storage, self.settings), "failed")
        response = self.post(body=body, key="key-retryfail")
        self.assertEqual(response.json()["job_id"], first)
        self.assertEqual(response.json()["status"], "queued")
        self.assertIsNotNone(self.db.claim_job(600, 3))

    def test_resubmitting_deleted_evidence_creates_a_new_job(self):
        body = tar_gz(MINIMAL)
        first = self.post(body=body, key="key-redeleted").json()["job_id"]
        self.client.delete(f"/v1/jobs/{first}", headers=self.auth(self.token_a))
        response = self.post(body=body, key="key-redeleted")
        self.assertEqual(response.status_code, 202)
        self.assertNotEqual(response.json()["job_id"], first)
        self.assertEqual(response.json()["status"], "queued")
        self.assertTrue(self.storage.bundle(self.tenant_a, self.project_a, response.json()["job_id"]).is_file())

    def test_delete_during_analysis_wins(self):
        job_id = self.submit_real()
        job = self.db.claim_job(600, 3)
        self.client.delete(f"/v1/jobs/{job_id}", headers=self.auth(self.token_a))
        self.assertEqual(process_job(job, self.db, self.storage, self.settings), "failed")
        self.assertEqual(self.client.get(f"/v1/jobs/{job_id}", headers=self.auth(self.token_a)).json()["status"], "deleted")
        self.assertFalse(self.storage.job_dir(self.tenant_a, self.project_a, job_id).exists())

    def test_retention_purges_only_what_has_expired(self):
        short = self.db.create_project(self.tenant_a, "short", retention_days=1, policy_toml=(self.ws.root / "policy.toml").read_text())
        token = self.db.create_token(short, ["submit", "read"])[0]
        expiring = self.post(token=token, key="key-expiring", body=self.real_bundle()).json()["job_id"]
        run_once(self.db, self.storage, self.settings)
        keeping = self.submit_real()
        run_once(self.db, self.storage, self.settings)
        self.assertEqual(purge_expired(self.db, self.storage), 0)
        self.assertEqual(purge_expired(self.db, self.storage, now=utcnow() + dt.timedelta(days=2)), 1)
        self.assertEqual(self.client.get(f"/v1/jobs/{expiring}", headers=self.auth(token)).json()["status"], "deleted")
        self.assertEqual(self.client.get(f"/v1/jobs/{keeping}", headers=self.auth(self.token_a)).json()["status"], "completed")

    def test_tenant_storage_is_separate(self):
        job_a = self.post(key="key-separate-a").json()["job_id"]
        job_b = self.post(token=self.token_b, key="key-separate-b").json()["job_id"]
        path_a, path_b = self.storage.bundle(self.tenant_a, self.project_a, job_a), self.storage.bundle(self.tenant_b, self.project_b, job_b)
        self.assertTrue(path_a.is_relative_to(self.settings.storage / self.tenant_a))
        self.assertTrue(path_b.is_relative_to(self.settings.storage / self.tenant_b))
        self.assertEqual(path_a.stat().st_mode & 0o777, 0o600)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(HAVE_HOSTED, HOSTED_SKIP_REASON)
class RealServerClient(Base):
    """A real uvicorn process, a real worker process and the real CLI client over loopback HTTP."""

    def start(self):
        port = free_port()
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(helpers.REPO / "src"), "CRA_SERVER_DATA": str(self.data),
               "CRA_SERVER_GRYPE": self.settings.grype, "CRA_SERVER_KEV": str(self.settings.kev_path)}
        self.server = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "cra.hosted.api:create_app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self._stop, self.server)
        self.worker = subprocess.Popen([sys.executable, "-m", "cra.hosted.worker"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self._stop, self.worker)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        self.ws.edit_config("[analysis]", f'[hosted]\nurl = "http://127.0.0.1:{port}"\npoll_seconds = 1\ntimeout_seconds = 60\n[analysis]')
        return port

    def _stop(self, process):
        process.kill()
        process.wait()
        if process.stderr:
            process.stderr.close()

    def run_cli(self, *args, token=None):
        import contextlib
        from cra import cli
        if token:
            os.environ["CRA_TOKEN"] = token
            self.addCleanup(os.environ.pop, "CRA_TOKEN", None)
        else:
            os.environ.pop("CRA_TOKEN", None)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = cli.main(list(args))
        return code, output.getvalue()

    def test_full_path_through_real_processes_and_gate(self):
        self.start()
        config = str(self.ws.root / "cra.toml")
        self.assertEqual(self.run_cli("collect", "--config", config)[0], 0)
        code, text = self.run_cli("analyze", "--config", config, "--hosted", token=self.token_a)
        self.assertEqual(code, 0, text)
        code, text = self.run_cli("gate", "--result", str(self.ws.analysis_dir))
        self.assertEqual(code, 10, text)
        self.assertIn("policy_blocked", text)
        code, text = self.run_cli("analyze", "--config", config, "--hosted", token=self.token_a)
        self.assertEqual(code, 0, text)

    def test_wrong_token_is_auth_failure_and_gate_is_not_clean(self):
        self.start()
        config = str(self.ws.root / "cra.toml")
        self.run_cli("collect", "--config", config)
        self.assertEqual(self.run_cli("analyze", "--config", config, "--hosted", token="cra_wrong")[0], 31)
        self.assertEqual(self.run_cli("analyze", "--config", config, "--hosted")[0], 31)
        self.assertEqual(self.run_cli("gate", "--result", str(self.ws.analysis_dir))[0], 20)

    def test_token_with_trailing_newline_is_accepted(self):
        self.start()
        config = str(self.ws.root / "cra.toml")
        self.run_cli("collect", "--config", config)
        code, text = self.run_cli("analyze", "--config", config, "--hosted", token=self.token_a + "\r\n")
        self.assertEqual(code, 0, text)

    def test_malformed_token_is_auth_failure_without_echo(self):
        config = str(self.ws.root / "cra.toml")
        self.ws.edit_config("[analysis]", f'[hosted]\nurl = "http://127.0.0.1:{free_port()}"\n[analysis]')
        self.run_cli("collect", "--config", config)
        code, text = self.run_cli("analyze", "--config", config, "--hosted", token="cra_secret value")
        self.assertEqual(code, 31, text)
        self.assertIn("hosted_token_invalid", text)
        self.assertNotIn("secret", text)

    def test_token_problem_still_clears_a_stale_result(self):
        from cra.common.bundle import write_manifest
        config = str(self.ws.root / "cra.toml")
        self.ws.edit_config("[analysis]", f'[hosted]\nurl = "http://127.0.0.1:{free_port()}"\n[analysis]')
        self.run_cli("collect", "--config", config)
        (self.ws.analysis_dir).mkdir(parents=True)
        (self.ws.analysis_dir / "result.json").write_text("{}")
        write_manifest(self.ws.analysis_dir, kind="analysis")
        self.assertEqual(self.run_cli("analyze", "--config", config, "--hosted")[0], 31)
        self.assertFalse((self.ws.analysis_dir / "result.json").exists())
        self.assertEqual(self.run_cli("gate", "--result", str(self.ws.analysis_dir))[0], 20)

    def test_service_outage_is_operational_failure_and_gate_is_not_clean(self):
        hosted_client.BACKOFF_SECONDS, saved = 0, hosted_client.BACKOFF_SECONDS
        self.addCleanup(setattr, hosted_client, "BACKOFF_SECONDS", saved)
        self.ws.edit_config("[analysis]", f'[hosted]\nurl = "http://127.0.0.1:{free_port()}"\n[analysis]')
        config = str(self.ws.root / "cra.toml")
        self.run_cli("collect", "--config", config)
        # A stale result from an earlier run, inside a recognized CRA analysis bundle.
        # analyze refuses to clear a folder without a CRA manifest, so a bare file would stop it first.
        from cra.common.bundle import write_manifest
        (self.ws.analysis_dir).mkdir(parents=True)
        (self.ws.analysis_dir / "result.json").write_text("{}")
        write_manifest(self.ws.analysis_dir, kind="analysis")
        code, text = self.run_cli("analyze", "--config", config, "--hosted", token=self.token_a)
        self.assertEqual(code, 32, text)
        self.assertIn("hosted_unavailable", text)
        self.assertNotIn(self.token_a, text)
        self.assertFalse((self.ws.analysis_dir / "result.json").exists())
        self.assertEqual(self.run_cli("gate", "--result", str(self.ws.analysis_dir))[0], 20)


@unittest.skipUnless(HAVE_HOSTED, HOSTED_SKIP_REASON)
class OperatorCommands(unittest.TestCase):
    def test_documented_admin_commands_run_and_issue_a_working_token(self):
        with tempfile.TemporaryDirectory() as work:
            env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(helpers.REPO / "src"), "CRA_SERVER_DATA": work}

            def admin(*args):
                done = subprocess.run([sys.executable, "-m", "cra.hosted.admin", *args], capture_output=True, text=True, env=env)
                self.assertEqual(done.returncode, 0, done.stderr)
                return done.stdout.strip()

            tenant = admin("create-tenant", "--name", "dev")
            project = admin("create-project", "--tenant", tenant, "--name", "gateway")
            token = admin("create-token", "--project", project, "--scopes", "submit,read")
            self.assertTrue(token.startswith("cra_"))
            database = Database(Path(work) / "control.sqlite3")
            principal = database.authenticate(token)
            self.assertEqual((principal.tenant_id, principal.project_id), (tenant, project))
            self.assertEqual(principal.scopes, {"submit", "read"})
            self.assertEqual(admin("purge-expired"), "0")


@unittest.skipUnless(HAVE_HOSTED, HOSTED_SKIP_REASON)
class ClientRules(unittest.TestCase):
    def test_url_rules(self):
        self.assertEqual(hosted_client.check_url("https://x.example/"), "https://x.example")
        self.assertEqual(hosted_client.check_url("http://localhost:8000"), "http://localhost:8000")
        self.assertEqual(hosted_client.check_url("http://127.0.0.1:8000"), "http://127.0.0.1:8000")
        for bad in ("http://x.example", "https://u:p@x.example", "", "ftp://x"):
            with self.assertRaises(ConfigError):
                hosted_client.check_url(bad)

    def test_redirect_is_not_followed_with_a_token(self):
        import http.server
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append((self.path, self.headers.get("Authorization")))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/stolen")
                self.end_headers()

            def log_message(self, *_):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with self.assertRaises(OperationalError):
            hosted_client.request("GET", f"http://127.0.0.1:{server.server_port}/start", "cra_secret", retries=1)
        self.assertEqual([path for path, _ in hits], ["/start"])

    def test_bad_token_stops_without_retrying(self):
        import http.server
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(401)
                self.end_headers()

            def log_message(self, *_):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with self.assertRaises(AuthError):
            hosted_client.request("GET", f"http://127.0.0.1:{server.server_port}/x", "cra_secret")
        self.assertEqual(len(hits), 1)


if __name__ == "__main__":
    unittest.main()
