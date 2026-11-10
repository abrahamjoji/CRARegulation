# Implementation checklist

For anyone deciding what they can rely on. Status terms:

| Term | Meaning |
| --- | --- |
| **Tested** | Exercised with the real tool or component |
| **Mocked** | Exercised against a fake scanner or signer replaying real or constructed output |
| **Unverified** | Written, but never run, or only linted |
| **Unsupported** | Deliberately not provided in this version |

## Milestones

| # | Milestone | State |
| --- | --- | --- |
| 1 | Repository assessment and architecture decisions | Done. See below and [ARCHITECTURE.md](ARCHITECTURE.md) |
| 2 | Reference build and expected inventories | Done |
| 3 | Local prepare and collect pipeline | Done |
| 4 | Normalized inventory and artifact evidence | Done |
| 5 | Scanner integration, reports and policy gate | Done |
| 6 | CLI and container packaging, CI example | CLI and container images tested locally. CI unverified |
| 7 | Hosted API, isolated workers, local deployment | API, worker and local Compose tested. Isolation partial |
| 8 | Security review, documentation, pilot checklist | Done, as an author's review. No independent review |

## Repository assessment

- `security/production-hardening` already contained `main`, so development started from it, on `product/ci-evidence-platform`.
- `demo-hardening` has the same content as `main`, under a different commit. Nothing was lost.
- `step-1-evidence-and-register` is an earlier baseline that the later branches supersede. It was not merged.
- All 67 existing tests are preserved and pass.

## Audit follow-up

See [PROJECT_AUDIT.md](PROJECT_AUDIT.md) for the cross-language review, corrections and remaining deployment work. Added Python pip-inspect and generic directory adapters share the existing inventory, local/hosted analysis and gate. [LANGUAGE_SUPPORT.md](LANGUAGE_SUPPORT.md) explains supported evidence and limits. Hosted production isolation and authenticated results remain open; "Done" above refers to the original implementation milestone, not production assurance.

## Functionality

| Function | Status | Notes |
| --- | --- | --- |
| `cra prepare` with real CMake | Tested | CMake 4.4.4 |
| Conan graph collection | Tested | Conan 2.34.0, two configurations |
| CMake File API collection | Tested | Link and include paths mapped to Conan packages |
| ELF inspection and version strings | Tested | On real reference binaries; hostile input by mutation test |
| Exported OCI image archive, real Syft | Tested | Images are synthetic: real package records, not built from the Dockerfile |
| Pinned registry image, real Syft, no daemon | Tested | busybox by digest, including index digest handling |
| Docker-save archive format | Tested | `docker save` of the reference final and builder images, collected in the collector image |
| Real multi-stage Docker build | Tested | `reference/image/Dockerfile` built and run. Needed `make`, `CMAKE_BUILD_TYPE` and the image's compiler version |
| Customer component records | Tested | Own parser; no external tool involved |
| Reconciliation and conflicts | Tested | Reference matches the hand-written expectation. Conflict cases use constructed inputs |
| Grype adapter | Tested | Grype 0.121.2, including missing database |
| Scanner failure modes | Mocked | Timeouts, malformed output, wrong versions |
| KEV handling | Tested | Real catalogue. A listed match is constructed, since the reference has none |
| VEX scope and trust | Mocked | Rules tested with fake matches. One real run passes after scoped decisions |
| Policy and gate outcomes | Tested and mocked | Blocked and incomplete seen with real tools; all outcomes with fakes |
| Reports | Tested | Hostile content test uses constructed data. Layout not reviewed by a person in a browser |
| CRA readiness reuse | Mocked | Uses the repository's fictional demo records |
| Wheel packaging | Tested | Built, installed in a clean environment |
| Collector without engine | Tested | Real `collector` image: no `engine`, `hosted` or Grype; local analyze exits 32 with `engine_not_included` |
| Collector and server images | Tested | Docker 28.5.2. Built with checksum-pinned Syft and Grype; non-root uid 10001; collector, local and server images run |
| Docker Compose | Tested | Compose 2.40.3. Results equal `cra-local`; worker has no egress; read-only root, no capabilities; API on loopback only |
| Linux ARM64 (aarch64) | Partly verified | Installer and Dockerfiles select pinned ARM64 tools; digests, ELF machine type and image tool stages verified on x86-64. Not run on ARM64 hardware or emulation |
| Windows and macOS hosts | Unsupported | CLI is Linux-only; collector image under Docker Desktop or WSL2 untested |
| GitHub Action and workflows | Unverified | Passes `actionlint` 1.7.12. Never run on GitHub |
| Hosted API | Tested | Real uvicorn over loopback |
| Worker with real Grype | Tested | Findings match the local run |
| Cross-tenant, auth, uploads, retention, deletion | Tested | Real API code, using an in-process client for most cases |
| Service outage and auth failure paths | Tested | Real client against a closed port and a refused token |
| OS-level worker sandbox | Unsupported | See [PRODUCTION.md](PRODUCTION.md) |
| Release signing with a key, verify, rollback | Tested | Real cosign 3.1.4, local key, offline |
| Keyless signing | Unverified | Needs a CI identity |
| Publishing anything | Not done | Nothing pushed, published or deployed |
| PostgreSQL, object storage, TLS | Unsupported | Production requirements |
| AI explanation | Unsupported | Not built. Generated VEX statements are refused |
| Customer software | Not tried | Reference project only. Broad compatibility is not claimed |
