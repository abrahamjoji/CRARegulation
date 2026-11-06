# Production setup after hardening

## Run a candidate check

In GitHub Actions, choose **CRA pipeline → Run workflow**, select the candidate ref, and enable **release_candidate**. Use the strict gate before distributing a product. The workflow never publishes anything, and a green ordinary build is not a passed release check.

The demo intentionally fails the strict gate. Replace fictional assessments with reviewed records and real test evidence; do not remove requirements or relax triage policy just to obtain a passing score.

The checked candidate commit is recorded in the evidence manifest. Your actual firmware publication process must require a successful strict check for the same commit and exact built firmware. Manual GitHub releases can bypass this workflow until repository access and the publication process enforce it.

## Repository controls to configure in GitHub

- Protect the production branch and release tags against unreviewed changes and force pushes.
- Require CI checks and security-owner approval for scripts, workflows, risk assessments, VEX, register decisions and policy changes. Configure actual owners in CODEOWNERS and enable enforced owner review; no placeholder owner was added.
- Keep incident records and evidence in a private repository or suitably restricted storage. CI artifact visibility follows repository access.
- Enable Dependabot PR review for the pinned actions. Update scanner URL, version and digest together from official release assets. A matching digest does not prove the upstream binary is free of malicious code.
- Configure workflow failure notifications for the responsible security team. Scheduled workflows can be delayed or disabled; six-hour CI checks are not a guaranteed reporting alarm service.

## Connect the real build

1. Build your product and retain its exact firmware image or package.
2. Generate the SBOM from the build output, including the OS/BSP and vendor components. The provided workflow still scans demo source declarations.
3. Scan that SBOM, record tool/database provenance, and review identity and freshness. The report does not yet authenticate scan origin or require a maximum feed age.
4. Supply component-specific register `purl` values and reviewed, scoped VEX statements. A `fixed` claim still needs independent verification that the shipped version contains the correction.
5. Add the built artifact to the evidence command with `--firmware path/to/image.bin`. This stores and hashes the image but does not verify that it corresponds to the SBOM.
6. Require both a successful strict gate and a complete evidence bundle in the real publication job. Sign the bundle using manufacturer-controlled identity and replicate it to protected retention storage.

The merger now rejects nested component inventories, conflicting component metadata, different CycloneDX versions, unsupported services/compositions/vulnerability sections, and dangling graph references. Use a full schema-aware CycloneDX tool for those cases; do not delete data to bypass a rejection.

## Evidence handling

`cra_evidence.py` copies required inputs and evidence referenced by the product checklist into a new folder. Each manifest entry contains a relative bundle path, size and SHA-256. Existing bundles are never overwritten. Linked evidence cannot escape the product directory, including through a symlink. A missing/empty linked file fails the snapshot.

Snapshot hashes detect later changes relative to the manifest. The manifest explicitly says `authenticated: false`; a protected signature and immutable storage are still required to establish provenance outside CI. Do not archive secrets as checklist evidence. Keep failed runs as diagnostics, separately from successful release authorization records.

## Validation scope

The local unit suite exercises report and gate regressions, checklist coverage, component-scoped decisions, event chronology, evidence collection and dependency-graph integrity. Live scanners and the hosted workflow require a GitHub CI run after these changes are pushed. Device authentication, update integrity, rollback protection, debug ports, safe recovery and robot motion behavior require actual hardware tests.

Workflow syntax reference: [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax). Scanner pins were obtained from the official [Syft release API](https://api.github.com/repos/anchore/syft/releases/tags/v1.57.0) and [Grype release API](https://api.github.com/repos/anchore/grype/releases/tags/v0.121.2) on 6 November 2026. Legal applicability and reporting interpretations need a separate authoritative review.
