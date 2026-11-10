#!/usr/bin/env bash
# Install the pinned scanner and signing binaries into .tools/ (or $1).
# Versions and digests are reviewed together. No remote script is executed, and
# a digest mismatch aborts before anything is unpacked. Digests come from the
# official GitHub release asset API and match each release's checksum file; a
# digest proves "same bytes as reviewed", not that upstream's binary is free of
# malicious code.
#
# Supported: Linux on x86-64 (amd64) and ARM64 (aarch64). Other platforms stop here.
set -euo pipefail
dest="${1:-$(cd "$(dirname "$0")/.." && pwd)/.tools}"

if [ "$(uname -s)" != "Linux" ]; then
  echo "install_tools.sh supports Linux only (found $(uname -s)). On Windows or macOS, use the collector container image." >&2
  exit 30
fi
case "$(uname -m)" in
  x86_64 | amd64)
    arch=amd64
    syft_sha=9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704
    grype_sha=9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12
    cosign_sha=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
    ;;
  aarch64 | arm64)
    arch=arm64
    syft_sha=410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb
    grype_sha=d7d2e160255b0f087280feabf6f213cf4c45d475690f3f1fe5dc336eb1037bf0
    cosign_sha=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2
    ;;
  *)
    echo "install_tools.sh supports x86_64 and aarch64 (found $(uname -m))." >&2
    exit 30
    ;;
esac

mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 180 "$1" -o "$2"; }

fetch "https://github.com/anchore/syft/releases/download/v1.57.0/syft_1.57.0_linux_${arch}.tar.gz" "$tmp/syft.tar.gz"
echo "$syft_sha  $tmp/syft.tar.gz" | sha256sum -c --strict --quiet
fetch "https://github.com/anchore/grype/releases/download/v0.121.2/grype_0.121.2_linux_${arch}.tar.gz" "$tmp/grype.tar.gz"
echo "$grype_sha  $tmp/grype.tar.gz" | sha256sum -c --strict --quiet
fetch "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-${arch}" "$tmp/cosign"
echo "$cosign_sha  $tmp/cosign" | sha256sum -c --strict --quiet

tar -xzf "$tmp/syft.tar.gz" -C "$dest" syft
tar -xzf "$tmp/grype.tar.gz" -C "$dest" grype
install -m 0755 "$tmp/cosign" "$dest/cosign"
echo "Installed for linux/${arch}:"
"$dest/syft" version | grep -E '^Version'
"$dest/grype" version | grep -E '^Version'
"$dest/cosign" version 2>&1 | grep -E 'GitVersion'
