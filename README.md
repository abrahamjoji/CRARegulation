# CRA readiness pipeline (demo)

A working example of the engineering evidence the EU Cyber Resilience Act (Regulation (EU) 2024/2847) asks of a product manufacturer, built from open-source tools and running in CI on every build.

The example product is the **RC-200 robot arm controller** by **Nordwerk Robotics GmbH**. Both are fictional. The vulnerabilities in the sample data are real public CVEs for the listed component versions.

## What it does

| Step | Tool | CRA reference |
| --- | --- | --- |
| 1. SBOM from firmware sources | Syft (CycloneDX) | Annex I Part II (1) |
| 2. Manual components (kernel from BSP, closed vendor SDK) | `scripts/merge_sbom.py` | Annex I Part II (1) |
| 3. Match against known vulnerabilities | Grype | Annex I Part I (2)(a), Part II (2) |
| 4. Known-exploited check | CISA KEV catalogue | Article 14 reporting |
| 5. Triage decisions | OpenVEX (`vex/`) | Part II (2), technical documentation |
| 6. Readiness report + JSON evidence, CI gate | `scripts/cra_report.py` | Annex VII technical documentation |
| 7. Continuous monitoring after release | OWASP Dependency-Track (optional) | Part II (2), (3) |

The CI gate fails the build when a known-exploited vulnerability has no VEX decision. A known-exploited CVE may never sit untriaged, because it can start the 24-hour reporting clock. The gate also fails when the KEV catalogue is missing, unreadable or empty, because the check could not run.

## Run it locally with the sample data

Python 3.10+ only, no packages needed.

```bash
python scripts/cra_report.py \
  --product product.json \
  --sbom sample-data/sbom.syft.cdx.json \
  --manual sbom/manual-components.cdx.json \
  --scan sample-data/scan.grype.json \
  --vex vex/rc200.openvex.json \
  --kev sample-data/kev.json \
  --out out/cra-report.html --sample --gate
```

Open `out/cra-report.html` in a browser.

## Run it for real

Push this repository to GitHub. The workflow in `.github/workflows/cra-pipeline.yml` installs Syft and Grype, scans `firmware/conanfile.txt`, fetches the live KEV catalogue and builds the report. Download it from the run's artifacts. Results from the live vulnerability database can differ from the sample data.

To adapt it to a real product:

- **Yocto:** replace step 1 with the SBOM from `create-spdx`, converted to CycloneDX. Extract the image's `.spdx.tar.zst` first, then run `python scripts/spdx_to_cdx.py <extracted dir> --name <image> -o out/sbom.cdx.json`. SPDX 3 is not supported, so on releases that default to it use `INHERIT += "create-spdx-2.2"`.
- **Zephyr:** replace step 1 with `west spdx`, then run `python scripts/spdx_to_cdx.py <build dir>/spdx --name <app> -o out/sbom.cdx.json`.
- **After converting:** read the converter's warnings. A component with no version cannot be matched to CVEs. The workflow runs Grype with `--add-cpes-if-none` so that components with no CPE are still checked; generated CPEs can add false matches, which you record in VEX.
- **Containers or root filesystems:** `syft scan <image or dir>`.
- Pin the Syft and Grype versions in the install step for reproducible builds.
- Edit `product.json` with the product's Annex I self-assessment and `vex/*.openvex.json` with triage decisions.

## Keeping the evidence

CRA technical documentation must stay available for at least 10 years, or the support period if longer. Every run uploads a CI artifact that expires after 90 days, which suits ordinary builds. When a GitHub release is published, the `archive-release-evidence` job also attaches the evidence and SHA-256 checksums to that release, including when the gate fails.

Release assets do not expire, but repository admins can delete them and they disappear with the repository. Copy them to storage the manufacturer controls, ideally write-once such as S3 Object Lock.

## Files

```
product.json                     product data and Annex I checklist status
firmware/conanfile.txt           example dependencies the scanner finds
sbom/manual-components.cdx.json  components the scanner cannot see
vex/rc200.openvex.json           triage decisions with justifications
sample-data/                     offline SBOM, scan and KEV subset for the demo
scripts/cra_report.py            report generator and CI gate
scripts/merge_sbom.py            SBOM merge helper
scripts/spdx_to_cdx.py           SPDX 2.x to CycloneDX converter for Yocto and Zephyr
tests/                           tests for the converter and the gate
.github/workflows/               the CI pipeline
```

## Limits

This pipeline produces technical evidence. It is not legal advice. The manufacturer stays responsible for the risk assessment, the EU declaration of conformity and CE marking.
