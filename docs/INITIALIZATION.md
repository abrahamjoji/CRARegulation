# Generate your configuration

`cra init` discovers existing build evidence and writes a reviewable starting point. It never builds the project, executes project code, installs dependencies, invents component versions, guesses a supplier/author, or treats dependency declarations as proof of shipment.

Use the **product repository root**, not a folder containing only old CRA reports. Detectors are bounded static readers; broad compatibility must be established with real customer builds.

```bash
# Preview first: nothing is written, including temporary project files.
cra init --root /path/to/product --name my-product --version 1.2.3 \
  --supplier 'My organisation' --author 'My security team' --dry-run

# Write the validated plan.
cra init --root /path/to/product --name my-product --version 1.2.3 \
  --supplier 'My organisation' --author 'My security team'
cd /path/to/product
cra validate --config cra.toml
cra data update --config cra.toml
# Run cra prepare BEFORE CMake configures, if CMake is configured.
# Build/capture the actual inputs and review records/configuration first.
cra validate --config cra.toml --check-inputs
cra collect --config cra.toml
cra analyze --config cra.toml
cra gate --result .cra/analysis --mode build
```

The next commands are printed, never run automatically. Install the pinned scanners separately. `init` is offline: its optional Grype database checks use the **existing** local database with updates disabled; no NVD requests or SDK downloads happen. Missing Grype, an unavailable DB, unsupported DB-search output and CPEs with no advisory results are warnings. `--skip-cpe-check` explicitly skips these checks. Run init again after provisioning data to repeat them.

`cra data update` is an **explicit network operation**, using the configured Grype executable to update its database and HTTPS to download the CISA KEV catalogue. It keeps the old KEV file on download/validation failure. Database and KEV updates are not one transaction; the DB may have refreshed before a KEV failure. To import approved local data:

```bash
cra data update --config cra.toml --kev-file /approved/kev.json --skip-db
```

## Generated files and identity

The default output is `cra.toml`, `policy.toml`, `records/components.json` and additive `.gitignore` entries for `.cra/`, `data/`, and the init lock. There is no fabricated SDK record in an empty project: the scaffold stays empty and warns that collection still needs real evidence.

Product name/version precedence is per field: command-line options, settings, then literal CMake `project()`, `pyproject.toml [project]`, `package.json`, `Cargo.toml [package]`, and the `go.mod` module name. Git describe is the last version fallback, clearly labelled as a source label. If name/version cannot be inferred, the command fails and requests options. Supplier and VEX authors come only from explicit options/settings. Dynamic variables, evaluated metadata, workspaces and conditional CMake logic are not executed or resolved. Pass explicit values for those projects.

The root of the output is the scanned project root. Paths are relative to it, not the shell's current directory. `cra init --version` is the **product** version; `cra --version` is the tool version.

## Detector registry and limits

Each detector is a module in `src/cra/onboard/detectors/`. The registry explicitly imports shipped modules; it does not load executable plugins from a customer's repository.

| Detector | Evidence and configuration | Limits and review needed |
| --- | --- | --- |
| Conan 2 | JSON graph captures recognised by content or graph-related names; same-directory CMake evidence shares a configuration | Capture from the actual install/create. Unusually named captures are recognised when the graph key is in the first 4 KiB; otherwise configure explicitly. Resolved runtime dependencies remain shipping-unknown. No Conan recipe is executed. |
| Conan 1/locks | `conaninfo.txt` target OS/version and directory entries for `conan.lock`/`conaninfo.txt` | Limited Syft source fallback; no dedicated Conan 1 graph adapter. A successful directory scan does not guarantee Conan packages were identified. Add explicit records. |
| CMake | `CMakeCache.txt`, literal system/toolchain metadata and existing File API targets/artifacts | Requires reconfiguration after prepare. Only present, in-root outputs named by the File API are selected. No inferred install execution. Multi-config replies become separate configurations. |
| Python | Captured pip inspect v1 JSON (content or conventional filename); `pyvenv.cfg`, `.venv`/`venv` markers or a root pyproject prompt a capture | Never executes a discovered interpreter. Missing capture is configured and the exact `python -m pip inspect --local` command is printed. Shipping defaults false. |
| Lockfiles | npm/yarn/pnpm, Cargo, Go, Poetry/Pipfile/uv/requirements, NuGet, Ruby, Composer | Adds source directories, not shipped packages. Actual catalogue support depends on pinned Syft; no full parser for every format is promised. |
| Image archives | Validated OCI/Docker tar layout | Defaults to build-stage. Change to final only after deployment review. Registry image references are not guessed. Image content is not loaded into memory for hashing. |
| QNX SDK plugin | Explicit SDK root, `QNX_BASE`, or literal QNX toolchain path; `.packages/metadata` package/version directories | One baseline/version must be unambiguous. SDK and target version disagreement fails. Retains installed package build identifiers. Installed SDK does not prove target image patch level. Multiple unrelated SDK/target versions require separate generation scopes or explicit records; their association is not guessed. No fixed installation paths or guessed QNX CPEs. |
| Zephyr plugin | VERSION fields plus a Zephyr marker | Preserves version, not an attested firmware deployment. Custom layouts need records. |
| SPDX plugin | SPDX 2 JSON packages from Zephyr/Yocto or another build | Imports package identities/CPE external references as generated claims. SPDX 3 and tag-value files are reported unsupported. Not all relationships, patches or product shipping are inferred. |
| Linux rootfs | Explicit `rootfs` list in settings | A final-directory selection is a user deployment claim. Arbitrary development directories are not automatically called a rootfs. Syft determines identifiable packages. |

Plain C/C++ source alone is not added as a required directory scan. A source tree without captured metadata must not be presented as a useful dependency inventory. Unsupported native formats and missing artifacts still need explicit evidence.

Discovery skips `.git`, `.cra`, `.tools`, conventional venvs, `node_modules`, `data` and common caches; it does not follow symlinks. It visits at most 20,000 files to depth 8, sniffs at most 4 KiB per JSON candidate, then reads at most 4 MiB per text/JSON input and 32 MiB of retained detector inputs in total. Use a focused project root if limits are reached. Image validation retains its separate archive limits. Scope coverage is a configured boundary, never a claim of complete software discovery.

## Settings and overrides

```toml
schema_version = "cra.init-settings/1"
trusted_authors = ["Product Security"]
policy_version = "reviewed-policy-1"
sdk_roots = ["/explicit/path/to/sdk"]
rootfs = ["deploy/rootfs"]
cpe_mappings = "cra-cpe-mappings.json"
test_frameworks = ["gtest", "gmock", "catch2", "doctest", "my-test-library"]
test_targets = ["integration_tests"]
# Exclude a detector only after recording how that coverage will be supplied.
exclude_detectors = []

[product]
name = "my-product"
version = "1.2.3"
supplier = "My organisation"

[overrides.vendor-sdk]
scope = "runtime"
# Filling reviewed_by means your team actually reviewed this claim.
# reviewed_by = "Named reviewer"
# shipped = true
```

Use `--settings /path/to/settings.toml`. `--sdk-root` may repeat. Rootfs paths must be inside the selected project. SDK roots may be external because they were explicitly selected. No shell or environment substitution is performed in settings values.

Known test frameworks live in `src/cra/data/test-frameworks.json`. Settings/`tools.test_frameworks` replace this list, and `tools.test_targets` names explicit test executables. CMake classifies an executable as test from the configured override or a framework dependency; libraries used only by those test executables receive test scope. Libraries also used by runtime/installed targets stay runtime. This is a heuristic over the available code model, not proof of shipping. Conan's actual test/tool edge contexts remain distinct. Conan `requires` is runtime resolution evidence, **not shipped evidence**.

## CPE mappings and checks

Built-in hints live in `src/cra/data/cpe-mappings.json`. A project-local extension has this format:

```json
{
  "schema_version": "cra.cpe-mappings/1",
  "mappings": {
    "vendor-rtos": "cpe:2.3:o:vendor:product:{version}:*:*:*:*:*:*:*",
    "vendor-sdk": "cpe:2.3:a:vendor:sdk:{version}:*:*:*:*:*:*:*"
  }
}
```

The example identities are placeholders; replace them with reviewed vendor/advisory identities. Use `o` for an operating system, `a` for application/development software, or `h` for hardware. An SDK and its target RTOS are separate records. Templates must have exactly one `{version}` and a structurally valid CPE 2.3 form. Structural validation cannot tell whether a vendor/product is correct.

Init copies the merged map to `records/cpe-mappings.json` and configures `tools.cpe_mappings`; analysis consumes the same map. This prevents generator and scanner hints drifting into different code tables. Overrides can also provide explicit record `cpes`.

Init invokes `grype db search --pkg CPE --limit 1 -o json` for final merged record CPEs. [Grype's search ignores version/update fields](https://oss.anchore.com/docs/guides/vulnerability/database/): this check is advisory-data coverage for the identity, not an affected-version check or a CPE dictionary validation. **Zero results never mean safe.** Even nonzero results do not prove the mapping describes your component. Review supplier advisories and record triage separately. QNX CPEs are deliberately not invented.

## Policy and readiness

```bash
cra policy init --out policy.toml --author 'Product Security' --version policy-1
cra init --name my-product --version 1.2.3 --policy strict --with-readiness
```

Default policy mirrors the engine defaults. Strict mode blocks medium build findings and inventory conflicts, blocks low release findings, and requires readiness. Empty author lists trust nobody; supplier names are not substituted as authors. The policy generator also offers `--strictness strict`, `--dry-run` and merge-only `--force`.

`--with-readiness` copies packaged templates into `readiness/` and wires product, risk, register and OpenVEX paths into analysis. They are intentionally incomplete. No fictional risk assessment or closing VEX statement is generated. Strict readiness requires real human work before release.

`cra validate` checks the config, policy semantics, component-record schema/identities and mapping file without invoking scanners. `--check-inputs` additionally requires configured build/capture paths to exist. Unreviewed generated records are warnings at validation; analysis keeps them incomplete until reviewed. Validation is not a dependency scan and does not prove the configured data is current.

## Reruns, reviews and failure behaviour

Without `--force`, existing managed files cause a clear error before writing. `.gitignore` is extended without replacing existing lines. With `--force`, init merges existing parsed values with detections: existing scalars, notes, review names, manual records and scalar lists (including an intentionally empty author list) win. Evidence arrays grow by stable ID; new entries are added even when the earlier array was empty. Removed/stale detections are **not silently deleted**. Review them manually. Generated records with the same name but conflicting versions stop the merge.

Existing TOML comments/formatting may change on a forced merge; semantic values are preserved. `--force` does not reset policy strictness, trust lists or shipping decisions. Edit those deliberately, or generate a new policy at another path and compare. JSON manual record fields must be in the published schema (`note` and `notes` are supported).

Generated records carry `generated: true`, empty `reviewed_by`, provenance and input hashes. They cannot silently suppress findings through a generated `shipped: false` or vendored-source coverage claim. Analysis reports `generated_record_unreviewed` until reviewed. Filling a reviewer string is a recorded claim, not cryptographic authentication. Provenance includes absolute SDK paths: review it before sharing.

The config header records generator version, UTC date, identity sources and SHA-256 hashes of consulted files. Directory-derived SDK facts use a deterministic installed-package listing hash labelled as such. Existing preserved values retain their earlier record provenance. Git fallback is labelled explicitly rather than treated as a release version.

All generated config, policy and component records are validated before any managed file is published, using the bundled schemas plus runtime semantics. The standard-library validator intentionally supports the keywords used in those schemas and fails on unsupported validation keywords; tests cross-check generated outputs with jsonschema Draft 2020-12. Resources ship in wheels and collector-only layouts.

Writes reject symlink destinations, use an exclusive init lock, stage files and roll back normal write failures. Concurrent content changes abort instead of overwriting newly edited reviews. Multi-file writes are not a power-loss transaction; if interrupted, inspect the lock and files before retrying. No output outside the selected project is generated. No network, dependency install or application build is triggered by init or validate.

## Additional issues to address in a real pilot

- Use actual target/deployment evidence, not the build machine OS or an installed SDK alone.
- CMake runtime loading, optional plugins, native Python extensions and static/vendored code can remain invisible.
- Review scanner database age, source revisions and artifact bindings separately; generation is not scanning.
- A clean CPE lookup is not proof of correct mapping, safe code, or full advisory coverage.
- Confirm rootfs and image role, architecture, patch/backport state and non-runtime classification before gating.
- Keep credentials out of jobs executing untrusted code; no generated config solves hosted isolation or service-result signing.

## Verification in this checkout (2026-11-12)

- Full routine-suite run: 354 tests, successful, 56 skipped by existing integration/socket capability guards. Final onboarding regression suite: 35 tests, all passed, including subsequent merge/provenance and quoted CMake identity checks.
- Checks include dry-run without writes, exact schema cross-validation, safe merge of reviews/manual records, multiple existing component versions, symlink refusal, concurrent edits, publication rollback, SDK mismatch, CPE-map consistency, image layout detection and test-only versus shared-runtime CMake dependencies.
- Built a wheel and verified packaged schemas/templates/mappings, then ran init and validation outside the source checkout. Collector-only operation without engine/hosted packages also passed.
- Real local language integrations: compiled C/C++ artifact collection and actual Python environment capture passed. Syft integration skipped because the pinned executable is absent. Live Grype DB searches, network data refresh, Docker and a real installed QNX/Zephyr/Yocto product SDK were not exercised here; SDK/capture/layout regression checks use fixtures. These need a product-machine pilot.
- Used `/home/abrahamjoji/cra/cra` only for a forced-merge dry run: existing product information and both manual records were preserved. No reference scan files were changed. Implementation belongs to the CRARegulation Git checkout, not that reference-data folder.
