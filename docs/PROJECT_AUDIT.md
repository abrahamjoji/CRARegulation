# Implementation audit and language support

Reviewed the `product/ci-evidence-platform` implementation locally. Changes are isolated on `product/multilanguage-audit`; nothing is deployed or published by this review.

## Assessment

The repository contains a substantive first implementation of the intended architecture: prepare/collect/analyze/gate CLI, Conan/CMake/image/artifact adapters, normalized inventory, local engine, hosted API/worker, project-scoped tokens and storage, reproducible upload bundles, reports, release verification and container definitions. This is broader than the original reporting prototype.

It is not yet an independently validated production SaaS. The existing milestone checklist correctly labels Docker builds, hosted CI, customer builds and several infrastructure controls as unverified or unsupported. Documentation alone is not proof of deployment or sandbox isolation.

## Changes from this audit

| Gap | Correction |
| --- | --- |
| Hosted tests could hang indefinitely in restricted environments denying local socket writes | Probe socketpair wakeup capability and report the environmental skip explicitly; no production runtime workaround |
| Collection assumed native build metadata or images; no direct Python adapter | Added pip inspect v1 ingestion from actual installed environments, normalized PyPI identities, configuration/scope separation and explicit shipping claims |
| No generic filesystem collection input | Added `[[directories]]` through pinned Syft, allowing language-independent package metadata discovery in source or staged deployment trees |
| Output paths could delete arbitrary existing directories in collect/local analyze/hosted analyze | Replace only recognized CRA outputs; reject unrelated nonempty directories, symlinks, unlisted user files and overlapping inputs |
| Boolean config strings were silently coerced; invalid lists could fail internally | Validate boolean/list/numeric fields and duplicate artifact IDs before collection |
| Repository Syft configuration could influence a scanner subprocess | Run Syft from an isolated temporary working directory |
| Native CPE name hints could affect similarly named Python distributions | Apply curated native hints only to Conan/generic identities |
| A gate result could say passed while containing blocking reasons | Reject contradictory outcomes, malformed reason lists and mismatched gate modes |
| Real-tool CI installed Conan with `--no-deps`, although its runtime dependencies were absent from the test lock | Install the pinned build tools with their dependencies so the reference build can run |
| Example hosted workflow swallowed every analysis error | Preserve authentication/operational failures; only a completed or explicitly incomplete analysis reaches the gate |

The directory adapter snapshots only regular files using no-follow file descriptors, bounded counts/bytes and explicit scope. Source contents are not placed into upload bundles. Zero detected packages stays incomplete.

## Language support

- Python: observed distribution metadata from the actual environment; conditional requirements and native extension dependencies remain explicit limitations.
- C and C++: use the same native evidence adapters. Conan is optional. ELF-only evidence can remain incomplete when package identities cannot be determined.
- Other build systems/languages: staged directory/image inventories and customer component records can feed the same engine. No claim of complete source-code or arbitrary-language vulnerability analysis is made.

See [LANGUAGE_SUPPORT.md](LANGUAGE_SUPPORT.md) and the Python/native/directory configurations under `examples/projects/`. The existing thin CI action works with all of these evidence sources.

## Remaining deployment requirements

1. Isolate each hosted worker with OS/container boundaries and separate storage/control-plane privileges. A subprocess running under the same user is insufficient isolation for adversarial tenants.
2. Authenticate service results with a signature rooted in customer-approved trust. Current hash manifests detect changes relative to a manifest but do not authenticate its author.
3. Validate the collector/server images and Compose deployment with real Docker, and execute the workflows on the target hosted CI platform.
4. Configure TLS, workload identity, operational monitoring, customer-controlled retention, backups and immutable audit storage before hosting confidential customer data.
5. Run customer pilots and measure missed dependencies and false matches against independently reviewed inventories. Synthetic/reference tests do not establish broad compatibility.
6. Complete manufacturer-specific product testing, support processes, risk assessment and conformity documentation separately from the scanner.

The full developer wheel contains the local analysis engine. Use the collector-only container target when proprietary logic must remain hosted; never distribute the full wheel expecting that logic to stay secret.

The collector and engine remain a Linux implementation. Windows/macOS native collection, dedicated Poetry/uv/Conda/Make/Meson graph adapters, reachability analysis, source-level SAST and automatic proof of exploitability are not implemented. Source manifests can still be inspected through generic Syft detection where supported, with declared rather than verified shipped presence.
