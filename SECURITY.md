# Security Policy

## Supported versions

Security fixes are made on the `main` branch. Please test against the latest `main` before reporting.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the affected files or commands, and steps to reproduce it.

You can expect an acknowledgement within 7 days. Once the issue is confirmed, a fix is prepared in a private security advisory and released with credit to you, unless you prefer to stay anonymous. Please give us reasonable time to release a fix before disclosing the issue publicly.

## Scope

In scope: the `cra` CLI, the collector, the local engine and gate, the hosted API, the container images in `deploy/`, and the GitHub Action in `.github/actions/`.

Out of scope: the demonstration code under `poc/`, and vulnerabilities in third-party scanners (Syft, Grype, cosign), which should be reported to their own projects.

The project's threat model and earlier reviews are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).
