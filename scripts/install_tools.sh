#!/usr/bin/env bash
# Install the pinned scanner and signing binaries into .tools/ (or $1).
# Versions and digests are reviewed together. No remote script is executed, and
# a digest mismatch aborts before anything is unpacked. Digests come from the
# official GitHub release asset API; a digest proves "same bytes as reviewed",
# not that upstream's binary is free of malicious code.
set -euo pipefail
dest="${1:-$(cd "$(dirname "$0")/.." && pwd)/.tools}"
mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 180 "$1" -o "$2"; }

fetch https://github.com/anchore/syft/releases/download/v1.57.0/syft_1.57.0_linux_amd64.tar.gz "$tmp/syft.tar.gz"
echo "9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704  $tmp/syft.tar.gz" | sha256sum -c --strict --quiet
fetch https://github.com/anchore/grype/releases/download/v0.121.2/grype_0.121.2_linux_amd64.tar.gz "$tmp/grype.tar.gz"
echo "9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12  $tmp/grype.tar.gz" | sha256sum -c --strict --quiet
fetch https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 "$tmp/cosign"
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  $tmp/cosign" | sha256sum -c --strict --quiet

tar -xzf "$tmp/syft.tar.gz" -C "$dest" syft
tar -xzf "$tmp/grype.tar.gz" -C "$dest" grype
install -m 0755 "$tmp/cosign" "$dest/cosign"
"$dest/syft" version | grep -E '^Version'
"$dest/grype" version | grep -E '^Version'
"$dest/cosign" version 2>&1 | grep -E 'GitVersion'
