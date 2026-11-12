#!/usr/bin/env python3
"""Write two small OCI archives without a Docker daemon: a final image and a build stage.

These are synthetic test images. They carry real Debian package metadata records
and the reference binary, and exist to exercise inventory separation offline.
"""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path

OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nID=debian\n'
# name: (version, architecture, Debian source package). Debian's feed is keyed by source package.
DPKG_FINAL = {"libc6": ("2.36-9+deb12u4", "amd64", "glibc"), "zlib1g": ("1:1.2.13.dfsg-1", "amd64", "zlib"), "libstdc++6": ("12.2.0-14", "amd64", "gcc-12")}
DPKG_BUILDER = {**DPKG_FINAL, "gcc-12": ("12.2.0-14", "amd64", "gcc-12"), "cmake": ("3.25.1-1", "amd64", "cmake"), "openssl": ("3.0.11-1~deb12u2", "amd64", "openssl"), "curl": ("7.88.1-10+deb12u5", "amd64", "curl")}


def _status(packages):
    return "\n".join(f"Package: {name}\nStatus: install ok installed\nPriority: optional\nSection: libs\nMaintainer: Debian\nArchitecture: {arch}\nSource: {source}\nVersion: {version}\nDescription: {name}\n" for name, (version, arch, source) in sorted(packages.items()))


def _layer(files):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(content))
    return data.getvalue()


def _blob(archive, data):
    digest = hashlib.sha256(data).hexdigest()
    info = tarfile.TarInfo(f"blobs/sha256/{digest}")
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
    return digest


def build(path, files, tag):
    layer = _layer(files)
    with tarfile.open(path, "w") as archive:
        layer_digest = _blob(archive, layer)
        config = json.dumps({"architecture": "amd64", "os": "linux", "config": {},
                             "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_digest}"]},
                             "history": [{"created_by": tag}]}, sort_keys=True).encode()
        config_digest = _blob(archive, config)
        manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                               "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": f"sha256:{config_digest}", "size": len(config)},
                               "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": f"sha256:{layer_digest}", "size": len(layer)}]}, sort_keys=True).encode()
        manifest_digest = _blob(archive, manifest)
        for name, content in (("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                              ("index.json", json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": f"sha256:{manifest_digest}", "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": tag}}]}).encode())):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return f"sha256:{manifest_digest}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="Reference binary to place in the final image")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    binary = args.binary.read_bytes() if args.binary else b"\x7fELF placeholder"
    common = {"etc/os-release": OS_RELEASE.encode()}
    final = build(args.out / "reference-final.oci.tar", {**common, "var/lib/dpkg/status": _status(DPKG_FINAL).encode(), "opt/gateway/gateway": binary}, "reference-final:1.0.0")
    builder = build(args.out / "reference-builder.oci.tar", {**common, "var/lib/dpkg/status": _status(DPKG_BUILDER).encode()}, "reference-builder:1.0.0")
    print(json.dumps({"final": final, "builder": builder}))


if __name__ == "__main__":
    main()
