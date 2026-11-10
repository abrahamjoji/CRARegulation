# Threat model

For security reviewers. Status words: **implemented and tested**, **partial**, or **open**.

## Assets

- Customer inventories, logs and vulnerability data, which reveal product weaknesses.
- Tenant separation in the hosted service.
- Integrity of the gate decision.
- Project tokens and CI credentials.
- Integrity of distributed collector releases.

## Trust boundaries

| Boundary | Untrusted side | Trusted side |
| --- | --- | --- |
| Build tree to collector | Repository, metadata, archives, binaries, including pull-request code | Collector process |
| Tools to adapters | Scanner output | Parser |
| Client to API | All request content, including any stated tenant | API authorization |
| API to analysis process | Uploaded bundle | Worker and control records |
| Publisher to customer | Downloaded release | Configured signing identity |

## Threats and controls

| Threat | Control | Status |
| --- | --- | --- |
| Archive traversal, links, devices, bombs | All members validated before any write; size and count limits; `O_EXCL`, `O_NOFOLLOW` | Implemented and tested |
| Parser exhaustion by JSON | Size limit before reading, depth limit, no non-finite numbers | Implemented and tested |
| Malformed ELF | Bounds-checked parser, fuzz-style mutation test, nothing executed | Implemented and tested |
| Reply index reads other files | File names restricted; links refused | Implemented and tested |
| Shell injection | Argument lists, never a shell | Implemented and tested |
| Runaway tool | Time, CPU, file size and memory limits; process group killed | Implemented and tested |
| Scanner sees credentials | Allow-listed environment | Implemented and tested |
| Secrets in evidence or logs | Pattern and key redaction; CMake cache allow-list; stderr redacted | Implemented and tested. Redaction is pattern-based and can miss secrets |
| HTML or link injection in reports | Escaping, HTTP(S) links only, CSP, no external resources | Implemented and tested |
| Clean result from failed scan | Malformed, missing, stale or failed inputs all give `incomplete` | Implemented and tested |
| Findings suppressed to pass | Findings are never removed; VEX needs exact scope and a trusted author | Implemented and tested |
| Generated text treated as a decision | Generated statements cannot apply; no AI feature exists | Implemented and tested |
| Forged tenant identity | Tenant comes only from the token lookup | Implemented and tested |
| Reading another tenant's job | Project-scoped queries; same answer as a missing job | Implemented and tested |
| Token theft from the server database | Only hashes stored | Implemented and tested |
| Token sent to another host | Redirects refused; HTTPS required except loopback | Implemented and tested |
| Replay or duplicate submissions | Idempotency key per project; a key cannot be reused with other content | Implemented and tested |
| Customer code runs on the service | Worker parses and scans only | Implemented and tested |
| Malicious update | Signature verified before hashes; downgrade refused; versions immutable; rollback re-verified | Implemented. Real cosign tested with a local key. Keyless not exercised |
| Mutable remote script | None is executed; binaries are digest-checked | Implemented |
| Untrusted pull-request job gets credentials | Token only in a separate job with no repository code, never on pull requests | Example only; not run on GitHub |

## Open risks

These matter, and none of them is solved by this version.

- **Worker isolation is partial.** The analysis process has no credentials, a scrubbed environment, resource limits and a private copy of the bundle. It still runs as the same OS user as the worker. A parser or scanner compromise could read other tenants' files and the control database on the same volume. Production needs one sandboxed container per job, mounting only that job's bundle. See [PRODUCTION.md](PRODUCTION.md).
- **A local result can be forged.** Anyone who can write the result directory can also rewrite its manifest. Run the gate in a job that untrusted code cannot influence. Hosted results are not yet signed.
- **Collected evidence is self-reported.** A compromised build can supply false graphs and binaries. The binding options catch mismatches, not lies. Signed build provenance is not implemented.
- **VEX authors are names, not identities.** Anyone who can edit the VEX file can state a trusted author's name. Signature verification is not implemented, so protect these files with enforced code review.
- **Scanner input is parsed by Syft and Grype.** They are pinned, limited and given no credentials, but their parsers are not ours to harden.
- **Abuse limits are basic.** There are upload limits and active job limits only. Unauthenticated requests create audit rows, so a reverse proxy must rate-limit them.
- **Not independently reviewed.** The review behind this document was done by the author of the code, with automated tests. No penetration test was performed.
