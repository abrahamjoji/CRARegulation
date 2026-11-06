# CRA readiness pipeline

Collects and checks the engineering evidence the EU Cyber Resilience Act (Regulation (EU) 2024/2847) asks of a product manufacturer, using open-source tools in CI on every build.

The repository ships with demo data for the **RC-200 robot arm controller** by **Nordwerk Robotics GmbH**. Both are fictional, and so are the demo's triage decisions and risk assessment. The vulnerabilities in the sample data are real public CVEs for the listed component versions. To use your own product, see [Set up a real product](#set-up-a-real-product).

Paragraph numbers below refer to the Commission guidance on the CRA, C(2026) 5252 annex, which is non-binding.

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

## The score

The score is a readiness indicator, not proof of conformity. It is 70% Annex I checklist and 30% findings decided. A finding under investigation does not count as decided.

The checklist does not take claims at face value:

| Status in `product.json` | How it counts |
| --- | --- |
| `met` with `evidence_refs` to existing non-empty files | Met (full credit) |
| `met` with no evidence, or a missing file | Unverified (half credit) |
| `partial` | Half credit |
| `missing` | No credit |
| `not_applicable` with a reason in the risk assessment | Left out of the score (para 33) |
| `not_applicable` with no reason | Counted as missing |

Three items are checked from pipeline data, whatever `product.json` claims:

- **I.1** comes from the risk assessment (para 166).
- **I.2(a)** drops to partial while open findings have no release decision.
- **II.1** needs an SBOM that has components, all with versions.

Only a file's existence is checked, not its content, so someone still has to review the evidence.

## The gates

`--gate` runs on every build and fails on problems that must never wait:

- The KEV catalogue, the scan or the SBOM is unusable or empty.
- A known-exploited vulnerability has no triage decision.
- A VEX decision is rejected: `not_affected` needs a justification and a written impact statement, and `affected` needs an action statement.
- An investigation is older than `triage_policy.max_investigation_days`. The default of 14 is a project policy; the guidance asks for prompt action and sets no number of days (para 214).
- An Article 14 step is overdue, or the register is invalid.

`--release-gate` runs when a GitHub release is published, and also requires:

- A complete risk assessment, market dates, a classification rationale and a support period of at least 5 years, or a reason for less (para 128).
- SBOM versions on every component.
- Every finding triaged, and a recorded release decision for each open one (para 237).
- For known-exploited findings, an answer on whether they are exploited in this product (para 218).
- For `affected` findings, the upstream reporting status (Article 13(6)).
- Impacted users informed for anything reportable (Article 14(8)).
- No `met` item without evidence.

The demo deliberately fails `--release-gate`. Its investigation of CVE-2022-0847 also passes the 14-day limit after 19 November 2026, so a live run of the demo fails `--gate` from then on. Use `--date 2026-11-05` to reproduce the sample report.

## Article 14 reporting

`vuln/register.json` records vulnerabilities from any source, including ones a scanner cannot see: researchers, customers, your own tests and the media (paras 233-234). Those also appear as findings.

A KEV listing alone does not start the clock. Exploitation must be in your product (para 218), and the clock runs from when you have reasonable certainty (para 213). Awareness before 11 September 2026 needs no retroactive report (para 217). Once you set `actively_exploited_in_product: true` and `aware_at`, or add an `incident` entry, the report tracks:

- Early warning within 24 hours.
- Notification within 72 hours.
- Final report 14 days after a fix for a vulnerability, or one month after the notification for an incident.

Reporting itself happens on the ENISA Single Reporting Platform; this tool only tracks the deadlines.

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
  --risk risk/risk-assessment.json \
  --register vuln/register.json \
  --out out/cra-report.html --summary out/cra-summary.json \
  --sample --date 2026-11-05 --gate
```

Run the tests with `python -m unittest discover tests`.

Open `out/cra-report.html` in a browser.

## Run it for real

Push this repository to GitHub. The workflow in `.github/workflows/cra-pipeline.yml` installs Syft and Grype, scans `firmware/conanfile.txt`, fetches the live KEV catalogue and builds the report. Download it from the run's artifacts. Results from the live vulnerability database can differ from the sample data.

## Set up a real product

1. Copy `templates/` into your repository: `product.json`, `risk-assessment.json`, `register.json` and `openvex.json`.
2. Do the risk assessment first. It decides which Part I requirements apply (para 33), and cost or risk appetite cannot justify leaving a risk unaddressed (paras 158, 163).
3. Decide whether your product has remote data processing, such as a cloud service it needs for one of its functions (section 8).
4. Fill in `product.json`, including `classification_rationale`, `market` and the support period. Link evidence files through `evidence_refs`, with paths relative to `product.json`.
5. Set the paths at the top of `.github/workflows/cra-pipeline.yml`.
6. Replace step 1 with an SBOM from your real firmware, using the options below.

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
risk/risk-assessment.json        cybersecurity risk assessment (demo)
vuln/register.json               vulnerability and incident register (demo)
templates/                       blank files for a real product
firmware/conanfile.txt           example dependencies the scanner finds
sbom/manual-components.cdx.json  components the scanner cannot see
vex/rc200.openvex.json           triage decisions with justifications
sample-data/                     offline SBOM, scan and KEV subset for the demo
scripts/cra_report.py            report generator
scripts/cra_checks.py            score, evidence, register and gate rules
scripts/merge_sbom.py            SBOM merge helper
scripts/spdx_to_cdx.py           SPDX 2.x to CycloneDX converter for Yocto and Zephyr
tests/                           tests for the converter, checks and gates
.github/workflows/               the CI pipeline
```

## Limits

This pipeline produces technical evidence and checks that records exist and agree with each other. It cannot judge whether a risk assessment or a triage decision is right, and it does not yet test the device itself, so most Part I requirements still rest on evidence you supply. It is not legal advice. The manufacturer stays responsible for the risk assessment, the EU declaration of conformity and CE marking.

Not covered yet: component due diligence (Article 13(5)), checks for substantial modifications, tracking certificates under other laws, firmware and code scanning, and device testing.
