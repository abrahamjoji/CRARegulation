# Security and production review — 6 November 2026

## Remediation update

The follow-up implementation now pins action commits and scanner versions/digests, removes remote installer execution, isolates Dependency-Track credentials on a fresh runner, checks candidates through a manual strict-gate input, removes public release uploads, and schedules six-hour monitoring. It validates complete checklist coverage, reserves computed fields, scopes register decisions by component, rejects duplicate decisions and inconsistent reporting chronology, and records gate results. Evidence snapshots retain linked files and provenance with hashes. The SBOM merger now preserves dependency aliases and later metadata, rejecting conflicts and unsupported nested inventories.

The original findings below describe the reviewed baseline. The mutable installer, shared runner credentials, silent graph loss, missing linked evidence and CVE-only decision reuse findings have been addressed in local code. Candidate checks are available, but deployment must still enforce them; the workflow does not publish a product. Archive authentication, automatic source freshness validation, firmware/SBOM identity verification, device testing, protected human approvals and external retention remain open. See [production setup](PRODUCTION_SETUP.md).

Validation after follow-up: 57 unit tests pass. Workflow YAML and shell syntax are checked locally; live GitHub Actions, scanner downloads and Dependency-Track integration have not been executed in this environment.

## Assessment

This is a useful evidence-collection prototype. It is not yet a production release authorization system. It scans dependency declarations and evaluates supplied records; it does not inspect a real controller, establish firmware integrity, or prove the records are correct. Do not interpret the readiness percentage as the probability that a device is secure or compliant.

Scope: local source, workflow and fixture review, with automated regression tests. No live device testing, GitHub settings audit, live scanner execution, penetration test or legal verification was performed. Regulatory statements and the cited Commission guidance in the existing project have not been independently verified in this review.

## Fixed in this change

| Finding | Consequence before the fix | Change |
| --- | --- | --- |
| High: invalid scan shape | `matches: null` or `{}` looked like a successful scan with zero vulnerabilities | Require an array; invalid input fails the gate |
| High: report HTML injection | Untrusted severity text could escape the HTML class attribute; a finding link could use `javascript:` | Escape class values and allow only HTTP(S) links |
| High: overly broad VEX suppression | Missing product scope acted as a wildcard across components | Require exact, non-empty component identity when applying a statement; reject duplicate decisions |
| High: contradictory release decision | `fix_before_release` counted as permission to release an open finding | Explicitly block that release |
| High: incomplete checklist accepted | Missing or partial requirements did not themselves fail the release gate | Block release on missing/partial checklist items |
| Medium: future reporting records | A future notification could count as already submitted | Reject future register event timestamps; future investigation timestamps fail the investigation gate |
| Medium: VEX justification validation | Arbitrary justification text was accepted | Validate against the recognized justification values |
| Medium: secret exposure scope | Dependency-Track credentials were available to the entire scan job, including downloaded installers | Limit credentials to the upload step, restrict automatic uploads to main pushes, require HTTPS |
| Low: report network dependency | Opening sensitive reports contacted Google Fonts | Remove external font loading and disable outgoing referrers |

These fixes improve validation; they do not authenticate the supplied evidence or decisions.

## Original production findings (see remediation update above)

### High — release checking happens after publication

Location: `.github/workflows/cra-pipeline.yml`, `release: types: [published]`.

A failing release gate cannot prevent distribution: the release is already published. The separate archive job intentionally runs even after failure. An attached evidence archive therefore does not mean a release passed.

Before real deployment: build and validate the exact candidate artifact in a manually triggered or tag-based release workflow, require the gate job to succeed, then publish from a separate protected job. Protect release tags and the deployment environment; restrict release permissions. Record gate status in the archived summary as well as the CI logs. A production firmware publication workflow must depend on this successful check.

### High — mutable remote code executes in CI

Location: the `Install Syft and Grype` step downloads install scripts from `main` and pipes them to a shell. GitHub Actions also use mutable major-version tags.

A compromised upstream script or moved tag can change the scanner, forge evidence, or read the checkout. Restricting secret scope reduces immediate exposure but a malicious earlier step can still leave code that runs later.

Before real deployment: select reviewed scanner releases, pin tool versions and action commit SHAs, verify downloaded binaries against independently trusted checksums or signatures, and update through reviewed dependency PRs. Do not run installer code in any job that later receives credentials; use an isolated upload job with no repository code execution. No versions or hashes were guessed in this change.

### High — no binding between product, firmware, SBOM and scan

Locations: `firmware/conanfile.txt`, `build()` in `scripts/cra_report.py`, and the workflow.

A genuine scan of an old or different product can be supplied alongside the current SBOM and still pass structural checks. Scanning a dependency declaration does not establish what was linked into the shipped image, which OS/BSP is installed, or what vendor binaries contain. Empty matches can legitimately mean clean, so shape validation alone cannot detect an unrelated scan.

Before real deployment: generate the SBOM from the built image plus build metadata, hash the firmware and all input evidence, record the exact source commit and scanner versions/database timestamps, verify scan target identity, and sign the evidence manifest. Include hardware revision, configuration and deployment variants. Reject stale or mismatched evidence. An ordinary SHA-256 file stored beside mutable evidence detects accidents but does not authenticate an attacker-controlled archive.

### High — decisions and checklist coverage are still self-authored

Locations: `vex_index()`, `validate_register()`, checklist loading and `evidence_exists()`.

A contributor who can edit the records can declare a finding fixed, mark a risk treated, provide arbitrary non-empty evidence, enlarge the investigation limit, or remove checklist rows. Exact component VEX matching helps scope but does not establish who approved it or that a fix reached the shipped firmware. Register decisions are indexed by vulnerability ID, so the same CVE in different components can share a decision incorrectly.

Before real deployment: enforce a canonical checklist schema and complete requirement set; validate all input structures; scope register records by vulnerability plus component/version and product build; validate fixed decisions against changed artifacts; require security-owner review of VEX, risk, policy and workflow changes. Use protected branches and CODEOWNERS with enforced approval. Store decision history and review identity. Treat signed VEX as authenticated statements, not automatic proof of correctness.

### High — this does not test device attack surfaces

No tests cover authentication, authorization, network services, update signature verification, rollback protection, boot integrity, debug ports, credential storage, physical access, unsafe robot motion or recovery after a failed update.

Before real deployment: build a product threat model and verification plan, test the actual hardware and firmware, and connect reviewed test results to the checklist. For the fictional robot use case, involve the product safety team when evaluating security failures that could affect motion. Establish secure update and vulnerability response processes with named owners.

### Medium — monitoring and deadlines depend on CI activity

The workflow has no scheduled trigger. No push means no new KEV lookup, investigation-age check or reporting deadline check. Old KEV files and scans are not rejected based on age. A reporter manually editing an event date can move its deadline; the records have no protected audit trail. Late completed submissions are shown but no longer fail the gate.

Before real deployment: run scheduled monitoring, validate source freshness and event chronology, retain immutable event history, and send deadline alerts to an operational owner. Track acknowledgements from the actual reporting system. Keep missed deadlines visible as historical failures even after submission. Do not rely on this repository as an unattended incident response service.

### Medium — evidence can be disclosed or lost

Release archives include vulnerability and incident registers, risk assessments and product metadata. For a public repository these may expose sensitive findings and product details. Linked evidence files themselves are not collected by the workflow, and manual SBOM input and tool provenance are not retained independently. Release assets are mutable/deletable by administrators.

Before real deployment: classify evidence, separate public disclosure records from private incident data, collect every referenced evidence file inside an approved root, include source/tool provenance and KEV input, and replicate signed archives into manufacturer-controlled retention storage with access controls. The workflow now retains the KEV input, but full evidence collection remains unfinished.

### Medium — SBOM merge can lose information

Location: `scripts/merge_sbom.py`.

The helper merges only top-level components, keeps the first duplicate, and does not reconcile dependency graphs, nested components, conflicting versions/identifiers or later security metadata. Incomplete identity and dependency data can reduce vulnerability matching accuracy.

Before real deployment: validate CycloneDX documents, preserve/reconcile component references and dependency graphs, reject conflicting identities, test representative Yocto/Zephyr/vendor SBOMs, and compare against the installed product inventory.

## Suggested order

1. Keep this change and review the new validation regressions.
2. Design the real product threat model and firmware inventory; replace demo decisions and dates.
3. Bind evidence to the exact built firmware and enforce complete input schemas.
4. Harden and isolate CI tools, credentials and decision review.
5. Make release publication depend on a successful candidate check.
6. Add scheduled monitoring, protected incident history and private evidence retention.
7. Independently review regulatory applicability, reporting logic and conformity requirements against authoritative current sources.

## Validation

`python -m unittest discover tests`: 42 tests passed after the changes, including new regressions for active URLs, attribute injection, unscoped/duplicate VEX, malformed scan matches, contradictory release decisions, future submissions and incomplete release requirements. Existing sample and converter tests still pass. `git diff --check` passed. The GitHub workflow was inspected locally but was not executed against GitHub or Dependency-Track.
