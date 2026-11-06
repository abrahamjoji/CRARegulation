# Production requirements and known limitations

For whoever decides whether to run this for real customers. This version is not ready for that without the work below.

## Required before hosting customer data

| Area | This version | Production needs |
| --- | --- | --- |
| Worker isolation | Separate process, no credentials, limits, same OS user | One sandboxed container per job (gVisor, Kata or similar), mounting only that job's bundle, no network, no access to the control database or other tenants |
| Separation of API and worker | Share a volume | Queue and object store with separate least-privilege roles |
| Control data | SQLite, single host | Managed PostgreSQL or similar, with backups. The job-claim logic needs porting and retesting |
| Evidence storage | Local filesystem | Object storage, per-tenant encryption keys, lifecycle rules that also cover backups |
| TLS and edge | None; loopback only | TLS termination, rate limiting, request limits, WAF as appropriate |
| Authentication | Static hashed tokens | OIDC workload identity from CI for short-lived access, customer admin via SSO |
| Administration | Operator CLI on the host | Audited administrative access; customer self-service for projects and tokens |
| Result authenticity | Hash manifest only | Service-signed results, verified by `cra gate` |
| Audit | Ordinary database rows | Append-only store, retention policy, alerting |
| Vulnerability data | Manual `grype db update` | Scheduled update, monitoring, stored database archives for reproducibility |
| KEV | File at a configured path | Scheduled fetch with freshness alerting |
| Observability | Standard error | Metrics, tracing, on-call |
| Capacity | One worker loop | Horizontal workers, queue limits, per-tenant fairness |
| Legal and privacy | None | Data-processing terms, data location, subprocessors, breach process |
| Assurance | Author's review and tests | Independent security review and penetration test |

Do not publish images, run the signing workflow, or deploy without a separate decision. None of those has been done.

## Known limitations

### Discovery

- Linux only. Direct adapters cover pip inspect v1 and Conan 2/CMake; generic directories and OCI images use Syft. Other build systems can supply staged deployment inventories and component records, but do not have dedicated graph adapters. See [language support](LANGUAGE_SUPPORT.md).
- The File API sees targets, not what happens at run time. `dlopen`, plugins and files installed by custom steps are not linked to components.
- Header-only packages are reported through include paths. That shows compilation against them, not that any of their code ended up in the output.
- Static linking removes most evidence. Version-string detection covers only zlib, OpenSSL, Mbed TLS and curl, and link-time garbage collection can remove those strings too.
- ELF is the only binary format inspected. Other formats, including most raw firmware, get a hash and an `unsupported` status.
- Vendored source is noticed only under conventional directory names such as `third_party` and `vendor`. Copied files elsewhere are invisible.
- Dynamic system libraries such as `libc.so.6` are listed as unidentified, even when a final image contains the package providing them.
- Inside images, only Syft's identification applies. An application binary copied into an image is not connected to Conan evidence unless it is also selected as an artifact.
- Different configurations share one component entry when the version is the same. Per-configuration data is kept beneath it. Reports summarize by component.

### Matching

- Conan has no vulnerability feed of its own. Matching depends on a curated CPE table with about ten packages, or on opt-in generated CPEs. Other Conan packages get no matches, and are listed as `not_matchable`.
- CPE matches may misidentify a package, and cannot see recipe patches. Conan Center patches are not read.
- Backport awareness applies only where a distribution feed is used.
- Real-world false-match rate is unmeasured. It needs findings labelled by a human, on real software.
- Only Grype is integrated. A single scanner means single-source blind spots.
- No reachability analysis. Exploitability stays `unknown` unless a manufacturer's record says otherwise.

### Decisions and evidence

- VEX is not signature-verified. Author names are unauthenticated strings.
- A `fixed` VEX claim is not checked against the artifact.
- `--expect-artifact` compares hashes recorded at collection. It cannot show that a separately deployed file is the same unless you check that file.
- Reproducing a historical analysis needs a database archive this tool does not store.

### Hosted

- Readiness records are local-only.
- Policy is set by an operator per project, with no API.
- Multi-architecture images: Syft analyzes the runner's platform by default. Other platforms need their own entry.

### Not built

- Optional AI explanation. If it is ever added, it must be labelled and must not approve releases or create trusted VEX. The VEX code already refuses generated statements.
- Vulnerability lifecycle tracking across builds. Each result stands alone, and the existing register is the record of ongoing decisions.
- Offline edition.
- GitLab or other CI integrations.
