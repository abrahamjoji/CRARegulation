# Repository layout and ownership

The scanner product, proofs of concept and tests have separate homes. Keep the standard Python `src` layout so packaging and imports remain conventional.

| Folder | What belongs here | What does not |
| --- | --- | --- |
| `src/cra/` | Shipping collector, adapters, analysis engine, gate, hosted service, schemas, mappings and blank onboarding templates | Fictional product records, built customer products, captured demo reports |
| `poc/legacy/` | Original DEMO-200 pipeline, legacy conversion/report scripts, sample inputs, blank legacy templates and example reports | New production scanning logic |
| `poc/reference/` | Reference application, vendor fixtures, expected inventory, CMake/Conan and image build setup | Scanner implementation or credentials |
| `tests/` | Product regression tests; `legacy/` for PoC tests, `integration/` for real tools, `fixtures/` for deterministic evidence | Runtime imports used by the shipping product |
| `examples/` | Small reusable customer configs and CI integration recipes | Large sample product builds |
| `deploy/` | Product Dockerfiles and service deployment configuration | Test workloads |
| `scripts/` | Product installation and release-building tools | Legacy report scripts |
| `requirements/` | Dependency locks for development and optional service dependencies | Customer inventories |
| `docs/` | Current architecture, integration, security and operating guidance | Generated scan output |

`pyproject.toml` packages only modules discovered under `src/`; production templates/mapping data are explicitly included there. Customers do not need to copy `poc/` or `tests/` to run scanning. The Docker build context excludes PoCs, tests and benchmarks; image contents still come from the product source.

## What moved

- Root `firmware/`, `sample-data/`, `sbom/`, `vex/`, `risk/`, `vuln/`, `templates/`, `product.json` and example `out/` are now inside `poc/legacy/`.
- Legacy `cra_report.py`, `cra_evidence.py`, `cra_checks.py`, `cra_validation.py`, `merge_sbom.py` and `spdx_to_cdx.py` moved from `scripts/` to `poc/legacy/scripts/`.
- `reference/` moved to `poc/reference/`.
- Legacy pipeline/security regressions moved to `tests/legacy/`; product tests and captured fixtures stay under `tests/`.
- The legacy guide moved out of the root README into `poc/legacy/README.md`.

Existing root-relative commands using those old paths must use the new location. Run legacy commands from `poc/legacy/`; run packaging, product tests and the reference build commands from the repository root. Compatibility script aliases still import the shared readiness rules from `src/cra/`, avoiding a second implementation of those rules.

CI working directories, artifact paths, test fixture roots, reference tool paths and ignore rules were updated. Sample-data contents and historical scanner captures are preserved. Cached builds can contain obsolete absolute paths; rebuild/reconfigure rather than editing generated CMake/Conan caches.

## Generated and private data

Use `.cra/` for local scanner output and `data/` for advisory data in customer projects; `cra init` writes those ignore entries. Keep `.venv/`, `.tools/`, `build/`, `dist/` and reference build output untracked. The checked-in legacy example reports are intentional PoC documentation, not current scan results.

The pre-existing untracked root `benchmark/` folder was left untouched. If those experiments are later adopted, review their content first and put demonstration material under `poc/benchmarks/`; deterministic performance regressions belong under `tests/`. Do not commit customer captures, secrets or machine-specific environments as part of a structural cleanup.

## Recommended rule for future work

Implement reusable scanner behaviour under `src/cra/`, demonstrate it under `poc/` or `examples/`, and verify it under `tests/`. Keep customer-specific product records out of the shipping package. Splitting this repository into separate repositories is not necessary yet; the folder boundaries keep development and CI manageable.

## Verification after the move

Full routine suite: 355 tests ran successfully (299 passed, 56 skipped by existing capability/integration guards). The standalone legacy demo report and sample gate passed from `poc/legacy/`. Real local Python environment and C/C++ artifact tests passed; Syft was skipped because the pinned executable is absent. Documentation links, workflow working directories, Python compilation and reference shell syntax were checked. Docker images and network-dependent reference builds were not rebuilt here.
