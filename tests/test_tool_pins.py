"""The scanner pins are repeated in the installer and the Dockerfiles. They must agree."""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ARCHES = {"amd64", "arm64"}
URL = re.compile(r"releases/download/v(?P<version>[0-9.]+)/(?P<tool>syft|grype|cosign)[_-](?:[0-9.]+_)?linux[_-](?P<arch>amd64|arm64)")


def installer_pins():
    """{(tool, arch): sha256} from the case blocks of scripts/install_tools.sh."""
    text = (REPO / "scripts" / "install_tools.sh").read_text()
    pins = {}
    for arch, body in re.findall(r"^\s*[a-z0-9_ |]+\)\n\s*arch=(\w+)\n(.*?);;", text, re.M | re.S):
        for tool, digest in re.findall(r"(\w+)_sha=([0-9a-f]{64})", body):
            pins[(tool, arch)] = digest
    versions = {match["tool"]: match["version"] for match in URL.finditer(text.replace("${arch}", "amd64"))}
    return pins, versions


def dockerfile_pins(name):
    text = (REPO / "deploy" / name).read_text()
    pins = {}
    for digest, url in re.findall(r"ADD --checksum=sha256:([0-9a-f]{64}) (\S+)", text):
        match = URL.search(url)
        pins[(match["tool"], match["arch"])] = (digest, match["version"])
    return pins


class ToolPins(unittest.TestCase):
    def test_installer_covers_both_architectures(self):
        pins, versions = installer_pins()
        self.assertEqual(set(pins), {(tool, arch) for tool in ("syft", "grype", "cosign") for arch in ARCHES})
        self.assertEqual(set(versions), {"syft", "grype", "cosign"})

    def test_dockerfiles_match_installer(self):
        pins, versions = installer_pins()
        expected_tools = {"Dockerfile.collector": {"syft", "grype"}, "Dockerfile.server": {"grype"}}
        for name, tools in expected_tools.items():
            with self.subTest(name):
                found = dockerfile_pins(name)
                self.assertEqual(set(found), {(tool, arch) for tool in tools for arch in ARCHES})
                for (tool, arch), (digest, version) in found.items():
                    self.assertEqual(digest, pins[(tool, arch)], f"{name}: {tool} {arch}")
                    self.assertEqual(version, versions[tool], f"{name}: {tool} version")


if __name__ == "__main__":
    unittest.main()
