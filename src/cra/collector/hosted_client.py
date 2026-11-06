"""Client for the hosted service. Standard library only, so the collector stays dependency-free.

Uploads are the collection bundle and VEX documents. Source code and built binaries
are not in that bundle. The token is read from the environment and sent to one host.
"""
import ipaddress
import json
import os
import shutil
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..common.archive import ArchiveLimits, create_tar_gz, safe_extract
from ..common.bundle import verify_manifest
from ..common.errors import EXIT_INCOMPLETE, EXIT_PASSED, AuthError, ConfigError, OperationalError, UntrustedInputError
from ..common.safety import read_json, redact_text, sha256_file

RETRIES = 4
BACKOFF_SECONDS = 2
RESULT_LIMITS = ArchiveLimits(max_members=5000, max_total_bytes=2048 * 1024 * 1024, max_member_bytes=1024 * 1024 * 1024)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could carry the token to another host, so it is treated as an error."""

    def redirect_request(self, *_args, **_kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def check_url(url):
    parts = urllib.parse.urlsplit(url or "")
    if not parts.scheme or not parts.hostname:
        raise ConfigError("hosted_url_missing", "Set hosted.url in cra.toml to use --hosted.")
    if parts.username or parts.password:
        raise ConfigError("hosted_url_invalid", "hosted.url must not contain credentials.")
    if parts.scheme == "https":
        return url.rstrip("/")
    loopback = parts.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        pass
    if parts.scheme == "http" and loopback:
        return url.rstrip("/")
    raise ConfigError("hosted_url_insecure", "hosted.url must use HTTPS. Plain HTTP is allowed only for loopback development.")


def request(method, url, token, *, data=None, headers=None, destination=None, timeout=120, retries=RETRIES):
    """Call the API with bounded retries. Same request, same idempotency key, safe to repeat."""
    last = None
    for attempt in range(retries):
        if attempt:
            time.sleep(BACKOFF_SECONDS * (2 ** (attempt - 1)))
        call = urllib.request.Request(url, data=data() if callable(data) else data, method=method, headers={"Authorization": f"Bearer {token}", **(headers or {})})
        try:
            with _OPENER.open(call, timeout=timeout) as response:
                if destination:
                    with open(destination, "wb") as output:
                        shutil.copyfileobj(response, output, 1024 * 1024)
                    return response.status, {}
                body = response.read(8 * 1024 * 1024)
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            detail = {}
            try:
                detail = json.loads(exc.read(64 * 1024)).get("error") or {}
            except (ValueError, AttributeError):
                pass
            if exc.code in (401, 403):
                raise AuthError(detail.get("code", "hosted_auth_failed"), redact_text(detail.get("message", f"The service refused this token ({exc.code})."))[0]) from None
            if exc.code in (408, 425, 429, 500, 502, 503, 504):
                last = f"HTTP {exc.code}"
                continue
            if 300 <= exc.code < 400:
                raise OperationalError("hosted_redirect_refused", "The service redirected the request; refusing to follow it with a token.") from None
            return exc.code, {"error": detail}
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
            last = redact_text(str(exc))[0]
    raise OperationalError("hosted_unavailable", f"The hosted service was unreachable after {retries} attempts ({last}). No result was produced, so `cra gate` will report incomplete.")


def build_upload(config, collection_dir, work):
    """Pack only the collection bundle and VEX documents."""
    stage = Path(work) / "stage"
    shutil.copytree(collection_dir, stage / "collection")
    problems = verify_manifest(stage / "collection")
    if problems:
        raise UntrustedInputError("collection_integrity", "; ".join(problems[:5]))
    if config.analysis.vex:
        (stage / "vex").mkdir()
        for index, path in enumerate(config.analysis.vex):
            config.scope.require(path, "vex")
            shutil.copyfile(path, stage / "vex" / f"{index:03d}-{Path(path).name}")
    bundle = Path(work) / "upload.tar.gz"
    create_tar_gz(stage, bundle)
    return bundle


def analyze_hosted(config, collection, destination, args):
    """Submit, wait, retrieve. On any failure no result exists, so the gate cannot pass."""
    base = check_url(config.hosted.url)
    token = os.environ.get(config.hosted.token_env)
    if not token:
        raise AuthError("hosted_token_missing", f"Set {config.hosted.token_env} to a project token.")
    if destination.exists():
        shutil.rmtree(destination)
    if not (collection / "collection.json").is_file():
        raise OperationalError("collection_missing", f"No collection at {collection}. Run `cra collect` first.")
    with tempfile.TemporaryDirectory(prefix="cra-upload-") as work:
        bundle = build_upload(config, collection, work)
        digest = sha256_file(bundle)
        key = "sha256:" + digest[:64]
        status, body = request("POST", f"{base}/v1/submissions", token, data=bundle.read_bytes,
                               headers={"Content-Type": "application/gzip", "Idempotency-Key": key, "X-Content-SHA256": digest})
        if status != 202:
            error = body.get("error") or {}
            raise OperationalError(error.get("code", "hosted_rejected"), f"The service rejected the upload ({status}): {error.get('message', '')}")
        job_id = body["job_id"]
        deadline = time.monotonic() + config.hosted.timeout_seconds
        while body.get("status") in ("queued", "running"):
            if time.monotonic() > deadline:
                raise OperationalError("hosted_timeout", f"Job {job_id} did not finish within {config.hosted.timeout_seconds} s. Retrying resumes the same job.")
            time.sleep(config.hosted.poll_seconds)
            status, body = request("GET", f"{base}/v1/jobs/{job_id}", token)
            if status != 200:
                raise OperationalError("hosted_status_failed", f"Could not read job {job_id} ({status}).")
        if body.get("status") != "completed":
            error = body.get("error") or {}
            raise OperationalError(error.get("code") or "hosted_job_failed", f"Job {job_id} ended as {body.get('status')}: {error.get('message', '')}. This is a service failure, not a product result.")
        archive = Path(work) / "result.tar.gz"
        status, result_body = request("GET", f"{base}/v1/jobs/{job_id}/result", token, destination=archive)
        if status != 200:
            raise OperationalError("hosted_result_failed", f"Could not retrieve the result ({status}).")
        staged = Path(work) / "result"
        safe_extract(archive, staged, RESULT_LIMITS)
        problems = verify_manifest(staged)
        if problems:
            raise OperationalError("hosted_result_integrity", "; ".join(problems[:5]))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staged), destination)
    result = read_json(destination / "result.json")
    print(f"Hosted analysis {result['scan_status']}: {result['summary']['total']} findings. Job {job_id}. Results in {destination}.")
    return EXIT_PASSED if result["scan_status"] == "complete" else EXIT_INCOMPLETE
