# Integration guide and CLI reference

For engineers adding the tool to a Linux CI build. Python, C, C++ and generic directory/image evidence use the same collect/analyze/gate path; see [language support](LANGUAGE_SUPPORT.md). Conan and CMake are optional.

## Generate your config

Start with `cra init --dry-run` in the product root, then review and write the proposed config. Use `cra validate` before collection and `cra data update` to explicitly refresh advisory inputs. See [generation, detectors and merge rules](INITIALIZATION.md) for the complete reference.

## Order of operations

```bash
cra prepare --config cra.toml     # before CMake configures
conan install . -pr:h <profile> -pr:b default --build=missing -of build -f json --out-file conan-graph.json
cmake -S . -B <tree> -DCMAKE_TOOLCHAIN_FILE=<tree>/generators/conan_toolchain.cmake
cmake --build <tree>
cra collect --config cra.toml     # after the build
cra analyze --config cra.toml     # or --hosted
cra gate --result .cra/analysis   # decides the CI outcome
```

Capture the Conan JSON during your real `conan install` or `conan create`. The tool never runs Conan itself, because a graph resolved with guessed defaults would not be your build.

## Commands

### `cra prepare`

Writes `<build dir>/.cmake/api/v1/query/client-cra/query.json` for each configuration, requesting `codemodel` v2, `cache` v2, `toolchains` v1 and `cmakeFiles` v1. If a tree was already configured, it says that CMake must run again.

### `cra collect`

Python-only projects need no preparation step: capture `python -m pip inspect --local > pip-inspect.json` from the actual environment and configure `pip_inspect`.

Reads only what `cra.toml` names, inside `scope.roots`. It writes `<output.dir>/collection/` with `collection.json`, `evidence/` and `manifest.json`. Existing nonempty destinations are replaced only when recognized as CRA outputs without unlisted files; unrelated directories and input/output overlaps are refused. A required source that is missing, partial, unsupported or failed makes it exit 20, with the reason listed.

### `cra analyze`

Reconciles the bundle, scans with Grype, applies VEX and evaluates policy. It writes `<output.dir>/analysis/`:

| File | Contents |
| --- | --- |
| `result.json` | Findings, evaluation for both gate modes, versions, diagnostics |
| `inventory.json` | Reconciled inventory, conflicts, coverage |
| `sbom.cdx.json` | CycloneDX 1.5 export |
| `report.html` | Human-readable report, no external resources |
| `summary.md` | Short summary for a CI job page |
| `evidence/` | Raw scanner output and VEX inputs |
| `manifest.json` | SHA-256 of every file |

It exits 0 when the analysis completed, whatever it found, and 20 when incomplete. Use `--hosted` to submit to the service, and `--kev <file>` to name a KEV catalogue. Analysis never updates the vulnerability database: run `grype db update` as a separate, visible step.

### `cra gate`

Evaluates an existing result and never rescans.

| Option | Effect |
| --- | --- |
| `--result DIR` | Analysis directory |
| `--mode build\|release` | Which evaluation applies |
| `--expect-revision SHA` | Incomplete unless the result is for this revision |
| `--expect-artifact ID=SHA256` | Incomplete unless this artifact hash is in the result |
| `--expect-policy SHA256` | Incomplete unless the result used this policy |
| `--max-age-hours N` | Incomplete if the result is older |
| `--record FILE` | Write the gate record: mode, outcome, reasons and all version metadata |

A missing, malformed, altered or mismatched result is `incomplete`.

### `cra release`

`verify`, `activate`, `rollback` and `status` for collector releases. See [PROVENANCE.md](PROVENANCE.md).

## Exit codes

| Code | Name | Examples |
| --- | --- | --- |
| 0 | Passed | Policy passed, or a step completed |
| 10 | Policy violation | `severity_blocked`, `kev_untriaged`, `vex_rejected`, `investigation_overdue`, `untriaged`, `inventory_conflict`, `readiness` |
| 20 | Incomplete | `source_missing`, `unknown_version`, `inventory_empty`, `vendored_source_unidentified`, `scanner_failed`, `vulnerability_data_stale`, `kev_unavailable`, `result_missing`, `result_integrity`, `revision_mismatch` |
| 30 | Configuration | Unknown key, wrong schema version, bad policy, mutable image reference, bad command line |
| 31 | Authentication | Token missing or refused, release signature invalid |
| 32 | Operational | Service unreachable, job failed in the service, internal error |

If a result has both incomplete reasons and policy violations, the outcome is `incomplete`, and both lists are kept. The cause is always in the structured output, not only in the exit code.

## Configuration: `cra.toml`

Schema: [`src/cra/schemas/config.schema.json`](../src/cra/schemas/config.schema.json). Unknown keys are errors. Paths resolve against the config file. [`reference/cra.toml`](../reference/cra.toml) is a full example.

| Section | Keys |
| --- | --- |
| `schema_version` | `"cra.config/1"` |
| `[product]` | `name`, `version`, `supplier` |
| `[source]` | `revision`: a value, or `env:GITHUB_SHA`. Otherwise read from git |
| `[scope]` | `roots`: required list of directories the collector may read |
| `[output]` | `dir` |
| `[[configurations]]` | `id`, `conan_graph`, `conan_manifest`, `conan_lockfile`, `cmake_build_dir`, `cmake_config`, `pip_inspect`, `pip_inspect_shipped`, `pip_inspect_scope`, `required` |
| `[[directories]]` | `id`, `path`, `role` (`source`, `final`, `build-stage`), `required` |
| `[[images]]` | `id`, `role` (`final` or `build-stage`), one of `archive` or `reference`, `format`, `expected_digest`, `required` |
| `[[artifacts]]` | `id`, `path`, `configuration`, `shipped`, `required` |
| `[components]` | `records`: component record files |
| `[tools]` | `syft`, `grype`, `timeout_seconds`, `allow_unverified_versions`, `add_generated_cpes`, `env_passthrough`, `cpe_mappings`, `test_frameworks`, `test_targets` |
| `[analysis]` | `policy`, `vex`, `kev`, `product_file`, `risk_file`, `register_file` |
| `[hosted]` | `url`, `token_env`, `poll_seconds`, `timeout_seconds` |

An image `reference` must be pinned with `@sha256:`. A tag is refused. Registry pulls and archive scans use Syft directly and never need a Docker daemon socket.

## Policy

Schema: [`policy.schema.json`](../src/cra/schemas/policy.schema.json). Example: [`reference/policy.toml`](../reference/policy.toml).

| Key | Meaning | Default |
| --- | --- | --- |
| `version` | Your version label; recorded in every result | required |
| `vex.trusted_authors` | Exact author names whose VEX may apply | empty, so no VEX applies |
| `freshness.max_vulnerability_data_age_hours` | Older data makes the result incomplete | 168 |
| `freshness.max_kev_age_hours` | Same for KEV | 168 |
| `freshness.kev_required` | A missing catalogue makes the result incomplete | true |
| `triage.max_investigation_days` | A project policy, not a legal deadline | 14 |
| `build.*` and `release.*` | See below | |

| Mode key | Meaning | Build default | Release default |
| --- | --- | --- | --- |
| `block_severities` | Open findings at these severities block | critical, high | critical, high, medium |
| `block_scope` | `shipped`, `shipped_or_unknown` or `all` | shipped_or_unknown | shipped_or_unknown |
| `block_kev_untriaged` | A KEV-listed finding needs a decision | true | true |
| `block_vex_problems` | A rejected VEX statement blocks | true | true |
| `minimum_confidence` | Matches below this do not block on severity alone | medium | low |
| `block_conflicts` | Inventory conflicts block | false | true |
| `require_all_triaged` | Every in-scope finding needs a decision | n/a | true |
| `require_readiness` | CRA readiness records must pass | n/a | false |

Findings are never removed to satisfy a gate. A low-confidence or build-only finding that does not block stays listed.

## Component records

For what tools cannot identify: vendored source, vendor SDKs, patched or ambiguous components. Schema: [`component-records.schema.json`](../src/cra/schemas/component-records.schema.json). Example: [`reference/records/vendor-components.json`](../reference/records/vendor-components.json).

A record is a claim and is labelled as one. Useful fields:

- `source_paths` ties a record to vendored source that CMake built. It clears the `vendored_source_unidentified` reason and lets CMake evidence corroborate shipping.
- `patched` records a claimed fix. It adds uncertainty to the finding and does not close it. Record a VEX decision to do that.
- `candidates` lists several possible identities. All are scanned, and the conflict stays visible until resolved.

## VEX decisions

Use [OpenVEX](https://github.com/openvex/spec). A statement applies only if all of these hold:

- Its author is in `vex.trusted_authors`.
- It names the exact versioned component, either as a product `@id`, or as a subcomponent of the exact versioned product `pkg:generic/<name>@<version>`.
- It has valid content: `not_affected` needs a justification and an impact statement, and `affected` needs an action statement.
- It is not marked generated (`x_cra_generated_by`). Generated statements can never become trusted decisions.
- Its optional `x_cra_scope` covers the finding: `configurations`, `artifacts`, `expires`.

A later statement replaces an earlier one. Disagreeing statements with no clear latest stay untriaged, with the problem recorded. VEX signatures are not verified in this version, so provenance always says `authenticated: false`. Protect these files with repository review.

## Schemas

| Document | `schema_version` | Schema file |
| --- | --- | --- |
| Configuration | `cra.config/1` | `config.schema.json` |
| Policy | `cra.policy/1` | `policy.schema.json` |
| Component records | `cra.component-records/1` | `component-records.schema.json` |
| Collection | `cra.collection/1` | `collection.schema.json` |
| Inventory | `cra.inventory/1` | `inventory.schema.json` |
| Result | `cra.result/1` | `result.schema.json` |
| Gate record | `cra.gate/1` | `gate.schema.json` |

Tests validate real outputs against these schemas.

## Packaging

| Form | Contents | Verified here |
| --- | --- | --- |
| Python wheel | `cra` command, collector, local engine, gate | Built and installed into a clean environment |
| Collector image, `deploy/Dockerfile.collector` target `collector` | Same code, no engine, plus Syft | Not built: no Docker here. The engine-free layout is tested |
| Local image, target `local` | Adds engine and Grype | Not built |
| GitHub Action, `.github/actions/cra-collect` | Thin wrapper around a digest-pinned image | Linted, not run |

An example customer workflow is in [`examples/github-actions/cra.yml`](../examples/github-actions/cra.yml).
