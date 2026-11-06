# Hosted API

For operators and integrators. Authentication is `Authorization: Bearer <project token>`. Errors have the form `{"error": {"code", "message"}}`.

| Method and path | Scope | Purpose |
| --- | --- | --- |
| `GET /healthz` | None | Liveness |
| `POST /v1/submissions` | `submit` | Upload a bundle and create a job |
| `GET /v1/jobs/{id}` | `read` | Status |
| `GET /v1/jobs/{id}/result` | `read` | Result bundle, `application/gzip` |
| `DELETE /v1/jobs/{id}` | `delete` | Remove evidence and results |
| `GET /v1/audit` | `read` | This project's audit records |

## Submitting

Required headers: `Content-Type: application/gzip`, `Idempotency-Key` (8 to 128 safe characters), and `X-Content-SHA256`.

| Response | Meaning |
| --- | --- |
| 202 | Accepted. `idempotent_replay` says whether the job already existed |
| 400 | Bad header or hash mismatch |
| 401 / 403 | Token invalid, or scope missing |
| 409 | The key was used with different content |
| 413 | Upload too large |
| 415 | Wrong media type |
| 422 | The archive failed validation, or lacks `collection/` |
| 429 | Too many active jobs; `Retry-After` is set |

Repeating a submission is safe. The same key and content returns the same job, and a failed job runs again. Deleted evidence can be resubmitted as a new job. `cra analyze --hosted` builds reproducible bundles, so its retries reuse the key. A new `cra collect` creates new content and therefore a new analysis.

Job status is `queued`, `running`, `completed`, `failed` or `deleted`. A `completed` job has `scan_status` of `complete` or `incomplete`. A `failed` job is a service failure and has no result.

## Behaviour during outages

| Situation | Client result | `cra gate` |
| --- | --- | --- |
| Service unreachable or returning 5xx | Retries with backoff, then exit 32 `hosted_unavailable` | Exit 20: no result exists |
| Token missing or refused | Exit 31, without retrying | Exit 20 |
| Job fails in the service | Exit 32 with the job's error | Exit 20 |
| Job does not finish in time | Exit 32 `hosted_timeout`. Rerunning resumes the same job | Exit 20 |
| Worker crashes | The lease expires and the job retries up to 3 times, then fails | Exit 20 until a result exists |
| Vulnerability data stale on the service | Result with `scan_status: incomplete` | Exit 20 |

An outage never produces a pass. Any older result in the output directory is removed before submission, so a stale result cannot be gated. Customers who must not block on outages should make that decision visibly in their workflow.

## Local development deployment

This is for development only. It uses plain HTTP on loopback, SQLite and a shared volume. **The Compose file and images have not been built in the environment where this was written, because Docker was unavailable.** The same API and worker processes are tested directly.

```bash
curl --proto '=https' -fsSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o deploy/dev-kev/kev.json
docker compose -f deploy/docker-compose.yml up --build -d

server() { docker compose -f deploy/docker-compose.yml exec api python -m cra.hosted.admin "$@"; }
TENANT=$(server create-tenant --name dev)
PROJECT=$(server create-project --tenant "$TENANT" --name gateway)
export CRA_TOKEN=$(server create-token --project "$PROJECT" --scopes submit,read,delete)
```

Then add this to `cra.toml` and run `cra analyze --hosted`:

```toml
[hosted]
url = "http://127.0.0.1:8000"
```

### Without Docker

This is the tested path. It needs `requirements/hosted.lock`.

```bash
export CRA_SERVER_DATA=$PWD/.cra/server CRA_SERVER_GRYPE=$PWD/.tools/grype CRA_SERVER_KEV=$PWD/reference/out/kev.json
export GRYPE_DB_CACHE_DIR=$HOME/.cache/grype/db PYTHONPATH=$PWD/src
python -m uvicorn --factory cra.hosted.api:create_app --host 127.0.0.1 --port 8000 &
python -m cra.hosted.worker &
```

A project's policy comes from `create-project --policy`. Without one, the built-in default applies, and it trusts no VEX author. Clients cannot choose the policy. Readiness records are not processed by the hosted service in this version.

Set `GRYPE_DB_CACHE_DIR` for the worker. Without it, Grype finds no database in the job's private home directory, and every job reports incomplete.
