# Test results

For reviewers. Recorded on 6 November 2026 on Kali Linux, x86-64, GCC 16.2.0. No GitHub Actions run, Docker build or customer build is included. Vulnerability counts come from one database snapshot and will change.

## Re-verification after merging main, 10 November 2026

The merge of `main` (#3) had replaced the `scripts/cra_checks.py` and `scripts/cra_validation.py` compatibility aliases with a broken mix of both versions. `scripts/cra_checks.py` raised `NameError` on import, so the sample report crashed and `tests/test_pipeline.py` could not load (244 tests ran instead of 300). The aliases are restored. With hosted tests running for the first time on this host, an out-of-date outage test and a test-order dependency in the integration suite surfaced and were fixed. The hosted client now clears an earlier result before checking the token, and it rejects a malformed token without echoing it.

| Check | Result |
| --- | --- |
| `.tools/venv3.11/bin/python -m unittest discover tests` | 303 ran: 289 passed, 14 skipped (opt-in integration) |
| `.tools/venv3.12/bin/python -m unittest discover tests` | 303 ran: 289 passed, 14 skipped (opt-in integration) |
| `CRA_INTEGRATION=1 ... -m unittest discover -s tests/integration -t tests -v`, from an empty `reference/out` | 14 ran, 14 passed with real Conan, CMake, Syft, Grype and cosign |
| README sample report (`scripts/cra_report.py ... --gate`) | Gate passed, exit 0 |
| Manual: Python `pip inspect` project, directory scan, hosted server and worker | Gate 10 on real advisories; missing directory or symlink 20; hosted result equal to local; bad token 31; server down 32, then gate 20 |

Still not verified here: the GitHub Action and workflows on GitHub, keyless cosign.

## Docker and Compose, 10 November 2026

Docker 28.5.2 and Compose 2.40.3 on the same host. First run of the images and the development stack.

| Check | Result |
| --- | --- |
| Build `Dockerfile.server`, `Dockerfile.collector` (`collector`, `local`) | Built; Syft 1.57.0 and Grype 0.121.2 downloads passed their pinned checksums. All images run as uid 10001 |
| `collector` image contents | No `engine`, `hosted` or Grype. A local `analyze` exits 32 with `engine_not_included` |
| `docker compose up` (db-update, api, worker) | Database update completed; API and worker started |
| Python project: Compose service vs `cra-local` image | 23 findings each, identical finding ids and database build; gate 10 |
| Reference C++ build collected in the `collector` image, analyzed on Compose vs `cra-local` | 61 observations; 158 findings each, identical ids; gate 10 |
| Bad token / API stopped / API restarted | 31 / 32 then gate 20 / same job returned for the same upload |
| Worker isolation | No egress (IP and DNS both fail); read-only root and database mount; no capabilities. API published on 127.0.0.1 only |
| The shared action's `docker run` flags (`--network none`, host uid) | Directory scan with Syft and Python collection both complete |
| `reference/image/Dockerfile` | Did not build as committed. Fixed: `make` for Conan's dependency builds, `-DCMAKE_BUILD_TYPE=Release`, and the image's GCC 12 recorded instead of the host's 16. Built and ran |
| `docker save` archives of that image, `format = "docker-archive"` | 279 components, 1079 findings: 209 shipped (final image), 870 build-only (builder image); gate 10. A missing archive reported incomplete |

Observations: the images write as uid 10001, so a mounted workspace must be writable by that user, or the container must run with `--user` as the shared action does. The `local` image then cannot read the database volume, which is private to uid 10001. Image scans see Debian packages, not the statically linked Conan zlib inside the binary; that comes from the Conan and CMake evidence.

## Linux ARM64 support, 10 November 2026

Run on the same x86-64 host. No ARM64 hardware or CPU emulation was available, so nothing was executed as ARM64.

| Check | Result |
| --- | --- |
| ARM64 digests for Syft 1.57.0, Grype 0.121.2, cosign 3.1.4 | Release checksum files and the GitHub release asset API agree. The existing amd64 pins match the same files |
| `scripts/install_tools.sh` on x86-64 | Installs and runs all three tools |
| Installer with `uname -m` reporting `aarch64` | Downloads pass their digests; all three binaries are `ELF 64-bit, ARM aarch64`. The final version step cannot execute here |
| Installer with a changed digest | Aborts at the checksum, before unpacking |
| Installer on `riscv64` and `Darwin` | Stops with exit 30 and a message |
| Dockerfile tool stages with `--platform linux/arm64` | Syft and Grype ARM64 downloads pass their pinned checksums |
| x86-64 images after the change | Build and run; collector, local and server are 216, 311 and 236 MB (were 247, 375, 268). Compose end to end: 23 findings, gate 10 |
| `requirements/hosted.lock` | Universal lock: includes the ARM64 manylinux wheel hash for `pydantic-core`; other packages are pure Python |
| ELF inspection of the ARM64 cosign binary on x86-64 | Parsed: machine 183 (AArch64) |
| `tests/test_tool_pins.py` | Installer and Dockerfile pins agree for both architectures; a changed digest fails the test |

Not verified: running `cra`, the tools or the images on ARM64. GitHub's ARM64 runners are not used, because this repository is private and they would be a paid resource.

## Cross-language audit verification

The follow-up audit added Python pip-inspect and language-independent directory collection, output safety, configuration validation and gate consistency checks. Current local verification:

| Check | Result |
| --- | --- |
| `.tools/venv3.12/bin/python -m unittest discover tests` | 300 ran: 247 passed, 53 skipped |
| Non-hosted routine tests, explicitly selected | 247 ran, 247 passed |
| `CRA_INTEGRATION=1 ... -m unittest discover -s tests/integration -p test_language_collectors.py -v` | 3 ran, 3 passed with actual tools |
| Real Python requirements directory → Syft → Grype → report/gate | 2 components, 11 findings; every finding joined inventory; gate correctly returned 10 |
| Mixed Conan/CMake/image/Python evidence | Shared inventory and policy gate passed the integration assertions with fixture scanners |
| YAML and embedded shell syntax | Repository workflows/action, both customer examples and Compose parsed; shell syntax passed |
| `git diff --check` | Passed |

The 53 skips comprise 14 opt-in integration tests and 39 hosted tests. This execution environment permits creating a socket pair but denies writing to it (`PermissionError: Operation not permitted`). Both Starlette TestClient and a direct ASGI test stalled when they needed thread-to-event-loop wakeups. Hosted tests now probe that capability and skip explicitly instead of hanging. They remain enabled on CI/hosts that permit socket operations. This review does **not** claim a new hosted end-to-end verification in this environment.

The three real-tool checks create an isolated Python environment and capture real pip inspect JSON, scan a Python requirements directory with Syft 1.57.0, and compile/inspect actual C and C++ ELF binaries without Conan. The native artifact-only case correctly remains incomplete when package versions cannot be identified. No dependency installations from the network are required for these three checks.

The previous results below are historical records from the initial implementation, not substitutes for the current environmental limits. External hosted CI and customer software remain unverified here; Docker is covered in the section above.

## Summary

| Suite | Command | Result |
| --- | --- | --- |
| Routine, Python 3.11.18, locked hashes | `python -m unittest discover tests` | 276 ran, 265 passed, 11 skipped |
| Routine, Python 3.12.16, locked hashes | Same | 276 ran, 265 passed, 11 skipped |
| Routine, Python 3.14.8 | Same | 276 ran, 265 passed, 11 skipped |
| Real tools | `CRA_INTEGRATION=1 python -m unittest discover -s tests/integration -t tests` | 11 ran, 11 passed |
| README path from a fresh clone | Install, build, collect, analyze, gate | Worked; gate exit 10 |
| No-Docker hosted path from a fresh clone | Commands in [HOSTED_API.md](HOSTED_API.md), real Grype | Worked; gate exit 10 |
| Workflow lint | `actionlint` 1.7.12 | No problems |

The 11 skipped routine tests are the real-tool tests, which need `CRA_INTEGRATION=1`. The real-tools row runs them.

Routine tests need no network. Their scanners are fakes replaying output captured from a real build. Tests of hosted code also skip if FastAPI is not installed, and schema tests skip without `jsonschema`.

## Routine suite

| File | Tests | Covers |
| --- | --- | --- |
| `test_pipeline.py`, `test_security.py` | 67 | Earlier pipeline, preserved |
| `test_platform_safety.py` | 26 | Bounded JSON, hostile archives, subprocess limits, redaction, path scope, HTML |
| `test_platform_collect.py` | 43 | Conan, CMake, ELF, images, records, configuration |
| `test_platform_analysis.py` | 63 | Inventory, conflicts, findings, VEX, outcomes, gate binding, report safety, readiness |
| `test_platform_cli.py` | 12 | Exit codes through the real entry point, collector without engine |
| `test_platform_hosted.py` | 39 | Auth, cross-tenant, uploads, worker, retention, outages, real processes |
| `test_platform_release.py` | 12 | Update verification and rollback |
| `test_platform_schemas.py` | 3 | Real outputs against published schemas |

## Real-tool suite

Real Conan 2.34.0, CMake 4.4.4, Ninja, GCC 16.2.0, Syft 1.57.0, Grype 0.121.2 and cosign 3.1.4. Network access was needed for Conan Center, Docker Hub and the CISA catalogue.

- Reference build from clean, with `cra prepare` first.
- Collection and analysis complete, with versions recorded.
- Inventory equals the expectation.
- Every finding has an explanation and joins the inventory.
- The gate blocks on real findings in shipped components.
- With an empty Grype database directory, analysis and gate report incomplete.
- After scoped VEX decisions on the shipped blockers, the gate passes and no findings disappear.
- The hosted path produces the same findings as local analysis.
- Syft pulls a digest-pinned image with no Docker daemon.
- Cosign signs and verifies. Tampering and the wrong key are refused. Upgrade and rollback work.

## First acceptance criterion

The demonstrated path, with real tools:

| Step | Evidence |
| --- | --- |
| Reference customer build | Two Conan and CMake configurations built and run |
| Collected dependency evidence | 61 observations from 9 sources |
| Reconciled inventory | 14 components, matching the expectation |
| Vulnerability analysis | Grype, 158 findings |
| Explainable result | `result.json` and `report.html` |
| Correct CI gate outcome | Exit 10, as the shipped `libc6` findings require |

The outcomes seen with real tools were exit 10, exit 20 with the database absent, and exit 0 after scoped triage. The triage decisions in that last case are test fixtures, not a real assessment.

## Measurements

### Inventory against the hand-written expectation

Measured on the real reference build, using `cra.engine.measure.compare`.

| Measure | Result |
| --- | --- |
| Expected components | 14 |
| Found | 14 |
| Completeness | 100% |
| Unexpected components | 0 |
| Attribute mismatches (shipped, scope, linkage, configuration) | 0 |

This is one small project designed for this tool, and it does not predict results on customer software. It would also not show a dependency that both the tool and the author of the expectation had missed. The test `test_measurement_detects_a_wrong_inventory` confirms the measure can fail.

### Findings on the reference build

Database built 2026-11-06T06:21:59Z. KEV catalogue 2026.11.04.

| Measure | Count |
| --- | --- |
| Total findings | 158 |
| In shipped components | 49 |
| In build-only components | 109 |
| Match confidence high (distribution feed) | 157 |
| Match confidence medium (CPE) | 1 |
| KEV listed | 0 |
| Build-mode violations | 19 |
| Release-mode violations | 86 |

Most findings arise because the synthetic images deliberately use old package versions. They show that build-stage packages do not block a shipped-product gate, and say nothing about real image quality.

### Conan matching and CPE sources

On the same build-derived inventory:

| CPE source | Matches |
| --- | --- |
| None | 0 |
| Curated hints (default) | 1: CVE-2026-27171 on zlib |
| Generated by Grype | 1: the same |

Without a CPE, Conan packages get no matches. That confirmed the need to list unmatchable components, rather than let silence read as clean.

### False matches

**The real-world false-match rate is not measured.** Nobody has labelled the 158 real findings as correct or incorrect, and the CPE match on zlib has not been checked against the zlib source. `cra.engine.measure.compare_findings` scores labelled findings, and has been tested on constructed labels only. Measuring it is a pilot task.

## Defects found by these tests

Listed because they show what the tests can catch, and were all fixed:

- Mutation testing of ELF input found an unhandled overflow.
- Real output showed the synthetic Debian records had wrong source package names, which hid shipped findings and let the gate pass wrongly.
- Real output showed Conan packages with no CPE were silently unmatched.
- Registry testing showed a digest check that wrongly failed on multi-platform images.
- Bundle hashes changed between runs, which broke retries across invocations.
- A failed or deleted hosted job could not be resubmitted under the same key.
- Writing the operator documentation showed the admin module could not be run as documented.
- Tests showed `cra.toml` without `supplier` was rejected.
