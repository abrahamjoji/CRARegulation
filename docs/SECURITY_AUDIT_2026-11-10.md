# Security audit — 2026-11-10

Scope: source review of evidence handling, collector updates, matching, VEX/policy/gate decisions, hosted client, upload/queue/result lifecycle, and existing tests. This is a code audit with regression checks, not independent penetration testing or a compliance certification.

## Findings fixed

| Priority | Finding | Change |
| --- | --- | --- |
| High | Collection metadata could direct scanners outside the verified evidence bundle | Require canonical contained paths, reject symlinks, bind evidence IDs, paths, sizes and hashes to manifest entries before scanning |
| High | Reactivating an installed release trusted its descriptor without checking installed payload bytes | Reverify installed signature and hashes; verify the staged copy before activation; validate rollback version and directory identity |
| High | An expired worker could publish results over a newer attempt | Unique lease tokens fence completion and retries; result publication occurs only after validating ownership under the database write transaction |
| Medium | A queued job became visible before its upload existed | Adopt upload before committing the queue record; retries replace missing input and obey active-job limits |
| Medium | Manifest validation omitted nested manifest files and accepted ambiguous/duplicate entries | Validate complete file set, canonical paths, sizes, digest format and duplicate entries |
| Medium | Malformed policy values and nonfinite freshness limits could weaken decisions | Strict boolean/list/number validation; reject future vulnerability-data timestamps |
| Medium | A documented-risk register entry bypassed the configured severity gate | Keep the decision visible while enforcing the customer's configured severity policy |
| Medium | Future VEX statements could suppress present findings; scope types were unchecked | Reject invalid/future timestamps and malformed scope lists |
| Medium | Explicit unmatched package identities fell back to names from another ecosystem | Only use name/version fallback when a scanner supplies no PURL |
| Medium | Hosted result download had no transport size cap | Bound compressed download to 256 MiB and JSON to 8 MiB; validate object responses, URL controls and job identifiers |
| Low | Malformed gate records could crash; NaN age limits bypassed age checks | Reject malformed outcomes/artifacts, duplicate artifact IDs and invalid age limits |
| Low | Cosign verification wrote cache data into the release directory | Use a private temporary cache without deleting customer release-directory contents |

SHA-256 manifests provide integrity checks, not authentication. They remain editable by an actor who can replace the bundle.

## Validation

- Baseline: 305 tests ran successfully, 56 skipped.
- Final routine suite: 320 tests ran successfully in 56.250 seconds (264 passed, 56 skipped), using `.tools/venv3.12/bin/python -m unittest discover tests`. The final database migration-lock adjustment also passed all 12 security regression tests.
- New regressions exercise traversal and symlink rejection, evidence binding, policy types, release reactivation/rollback, upload commit ordering, failed publication rollback, stale worker fencing, retry limits and hosted response validation.
- Real local integration: Python virtual environment and `pip inspect` collection passed; actual C and C++ compilation/artifact collection passed. Syft directory test skipped because the pinned binary is absent.
- Docker daemon access is denied in this environment. Socket-dependent hosted API/client tests skip on their existing capability probe. Those integration paths need a rerun in CI with sockets and Docker enabled. Database concurrency regressions run without sockets and passed.
- Python source compilation and `git diff --check` passed.

## Remaining production blockers

See [PRODUCTION.md](PRODUCTION.md) for the full list. The highest priorities remain:

1. Per-job OS/container isolation with no access to control data, other tenants or network. A subprocess under the same UID is not a tenant security boundary.
2. Service-signed results verified by the gate, and authenticated VEX provenance. Author allowlists alone do not authenticate a manufacturer.
3. TLS, rate limits, short-lived CI workload identity, operational monitoring, backups and tenant-scoped storage credentials.
4. End-to-end deployment tests on Docker/Compose and real customer-shaped projects, including scanner database freshness and false-positive evaluation. Successful C/C++ artifact collection does not prove complete dependency identification.
5. Durable queue/object-store transaction recovery. SQLite and filesystem writes are coordinated here, but are not one crash-atomic transaction; crashes can leave orphaned files for operator cleanup.
6. Independent security review before handling unrelated customers' confidential data.

Use this version for development and controlled evaluation. This audit does not establish production readiness or complete CRA compliance.
