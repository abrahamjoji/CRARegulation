# Updates and provenance

For anyone deciding how far to trust a result or a release.

## Hashes, signatures and trusted provenance

These three answer different questions, and each one depends on the one before.

| Mechanism | Answers | Does not answer |
| --- | --- | --- |
| **Hash** (SHA-256) | Is this the same set of bytes as that one? | Who made it. Anyone can hash anything, and anyone who can edit the file can edit a hash beside it |
| **Signature** | Did the holder of this key or identity sign these bytes? | Whether the signer's process was honest, or what the bytes contain |
| **Trusted provenance** | How was this built: from which source, by which builder, under what controls? | Whether the software is safe. And it is only as good as the builder that attests it |

What this version does:

- **Evidence and result manifests are hashes only.** `manifest.json` says `authenticated: false`. It catches accidents and tampering by someone who did not also rewrite the manifest. It does not authenticate anything.
- **Collector releases are signed.** `release.json` is signed with cosign and lists payload hashes, so the signature covers the payload.
- **Build provenance attestations are not implemented.** `release.json` records a source revision, as a claim covered by the signature. SLSA-style attestations from a hardened builder are future work.

## Recorded with every decision

| Item | Field in the result or gate record |
| --- | --- |
| Collector version | `collector.version` |
| Analysis-engine version | `engine.version` |
| Policy version and hash | `policy.version`, `policy.sha256` |
| Vulnerability-data identity and timestamp | `vulnerability_data.grype`: `built`, `schema`, `source` with checksum |
| KEV identity and timestamp | `vulnerability_data.kev`: `catalog_version`, `date_released`, `sha256` |
| Scanner versions and output schema | `scanners` |
| Source revision | `source.revision`, `source.dirty` |
| Artifact hashes and image digests | `artifacts` |
| Gate mode, outcome and reasons | The gate record from `--record` |

To explain a historical decision, keep the collection bundle, the analysis bundle and the gate record together. Reproducing an exact past analysis also needs the same Grype version and database archive, which the recorded `source` identifies, but this tool does not store or restore it.

## Releases

A release directory contains the payload, `release.json` and `release.json.sigstore.json`.

```bash
# Build and sign. Keyless identity in CI, or a key file for testing. This publishes nothing.
python scripts/build_release.py --out dist/0.1.0 --cosign .tools/cosign --key cosign.key

cra release verify   --dir dist/0.1.0 --cosign .tools/cosign --public-key cosign.pub
cra release activate --dir dist/0.1.0 --home .cra/releases --cosign .tools/cosign --public-key cosign.pub
cra release status   --home .cra/releases
cra release rollback --home .cra/releases --cosign .tools/cosign --public-key cosign.pub
```

For keyless verification, replace `--public-key` with `--certificate-identity` and `--certificate-issuer`. Those must name your release workflow exactly.

Verification order is signature first, then every listed hash. Failing either stops the operation, and the current release stays active.

## Upgrade and rollback rules

- Nothing is fetched or executed from a remote location. You supply the directory.
- A version is immutable. Installing different content under an installed version is refused.
- Moving to an older version needs `rollback` or an explicit `--allow-downgrade`.
- Rollback re-verifies the stored release, so a release altered on disk is refused.
- CI should pin an exact wheel hash or image digest, and change it through reviewed pull requests.

`activate` records which verified release is current. Installing the payload into a CI image remains your pinned deployment step.

## Trust and rotation

Not yet set up, because no public release exists. The recommended arrangement is:

| Item | Recommendation |
| --- | --- |
| Signing identity | Keyless cosign from a protected release workflow on a protected tag. Customers pin the certificate identity and issuer |
| If using a key | Hold it in a KMS, and publish the public key by a channel separate from releases |
| Rotation | Publish the new identity in a release signed by the old one, then keep both accepted for a stated overlap period |
| Compromise | Revoke, announce through a separate channel, re-sign from a clean builder. Customers replace the pinned trust root |

## Keeping scanner pins current

Scanner versions, digests and verified-version lists must change together in `scripts/install_tools.sh`, `deploy/Dockerfile.*`, `cra/collector/container.py` and `cra/engine/grype.py`. A digest proves you got what was reviewed. It does not prove upstream's binary is free of malicious code.
