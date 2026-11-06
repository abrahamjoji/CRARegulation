"""Tests for the SPDX converter and the CI gate. Run: python -m unittest discover tests"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

YOCTO_JSON = {
    "spdxVersion": "SPDX-2.2",
    "name": "recipe-openssl",
    "packages": [{
        "name": "openssl",
        "versionInfo": "3.0.1",
        "licenseDeclared": "Apache-2.0",
        "supplier": "Organization: OpenEmbedded ()",
        "externalRefs": [{
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*",
        }],
    }],
}
ZEPHYR_TAG_VALUE = """SPDXVersion: SPDX-2.3
DocumentName: zephyr-sources
PackageName: mbedtls
PackageVersion: 3.5.0
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: <text>
PackageName: not-a-package
</text>
ExternalRef: PACKAGE-MANAGER purl pkg:github/Mbed-TLS/mbedtls@3.5.0
FileName: ./ignored.c
PackageName: zephyr-app
"""


def run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)


class SpdxToCdx(TempDirTest):
    def convert(self, *inputs):
        out = self.tmp / "out.cdx.json"
        result = run("spdx_to_cdx.py", *inputs, "-o", out)
        return result, json.loads(out.read_text(encoding="utf-8")) if result.returncode == 0 else None

    def test_json_document(self):
        path = self.tmp / "recipe-openssl.spdx.json"
        path.write_text(json.dumps(YOCTO_JSON), encoding="utf-8")
        result, bom = self.convert(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        c = bom["components"][0]
        self.assertEqual((c["name"], c["version"]), ("openssl", "3.0.1"))
        self.assertEqual(c["cpe"], "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*")
        self.assertEqual(c["licenses"], [{"expression": "Apache-2.0"}])
        self.assertEqual(c["supplier"], {"name": "OpenEmbedded ()"})
        self.assertEqual(c["purl"], "pkg:generic/openssl@3.0.1")

    def test_tag_value_skips_multiline_text_and_warns(self):
        path = self.tmp / "zephyr.spdx"
        path.write_text(ZEPHYR_TAG_VALUE, encoding="utf-8")
        result, bom = self.convert(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [c["name"] for c in bom["components"]]
        self.assertEqual(names, ["mbedtls", "zephyr-app"])
        self.assertEqual(bom["components"][0]["purl"], "pkg:github/Mbed-TLS/mbedtls@3.5.0")
        self.assertNotIn("licenses", bom["components"][0])
        self.assertIn("1 component(s) have no version", result.stdout)
        self.assertIn("2 component(s) have no CPE", result.stdout)

    def test_operating_system_purpose_stays_scannable(self):
        path = self.tmp / "kernel.spdx.json"
        path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "name": "kernel", "packages": [
            {"name": "linux-yocto", "versionInfo": "5.15.0", "primaryPackagePurpose": "OPERATING-SYSTEM"},
        ]}), encoding="utf-8")
        _, bom = self.convert(path)
        self.assertEqual(bom["components"][0]["type"], "library")

    def test_directory_merge_keeps_cpe_from_later_document(self):
        (self.tmp / "a.spdx.json").write_text(json.dumps({
            "spdxVersion": "SPDX-2.2", "name": "a", "packages": [{"name": "openssl", "versionInfo": "3.0.1"}],
        }), encoding="utf-8")
        (self.tmp / "b.spdx.json").write_text(json.dumps(YOCTO_JSON), encoding="utf-8")
        (self.tmp / "index.json").write_text("{}", encoding="utf-8")
        result, bom = self.convert(self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(bom["components"]), 1)
        self.assertIn("cpe", bom["components"][0])

    def test_rejected_inputs_fail(self):
        spdx3 = self.tmp / "image.spdx.json"
        spdx3.write_text(json.dumps({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}), encoding="utf-8")
        cyclonedx = self.tmp / "other.json"
        cyclonedx.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
        empty = self.tmp / "empty.spdx.json"
        empty.write_text(json.dumps({"spdxVersion": "SPDX-2.2", "packages": []}), encoding="utf-8")
        for path, message in ((spdx3, "SPDX 3"), (cyclonedx, "not an SPDX 2.x"), (empty, "no packages"), (self.tmp / "missing", "no such file")):
            result, _ = self.convert(path)
            self.assertEqual(result.returncode, 1, path)
            self.assertIn(message, result.stderr)


class ManualComponents(unittest.TestCase):
    def test_types_are_scanned_by_grype(self):
        bom = json.loads((ROOT / "sbom/manual-components.cdx.json").read_text(encoding="utf-8"))
        for c in bom["components"]:
            self.assertNotIn(c["type"], ("operating-system", "device", "file", "container"), c["name"])


class KevGate(TempDirTest):
    def gate(self, kev=None, vex="vex/rc200.openvex.json"):
        args = ["--product", ROOT / "product.json", "--sbom", ROOT / "sample-data/sbom.syft.cdx.json",
                "--scan", ROOT / "sample-data/scan.grype.json", "--vex", ROOT / vex,
                "--out", self.tmp / "report.html", "--summary", self.tmp / "summary.json", "--gate"]
        if kev:
            args += ["--kev", kev]
        return run("cra_report.py", *args)

    def test_triaged_sample_passes(self):
        result = self.gate(ROOT / "sample-data/kev.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads((self.tmp / "summary.json").read_text(encoding="utf-8"))["kev_loaded"])

    def test_untriaged_known_exploited_fails(self):
        vex = self.tmp / "empty.openvex.json"
        vex.write_text(json.dumps({"statements": []}), encoding="utf-8")
        result = self.gate(ROOT / "sample-data/kev.json", vex)
        self.assertEqual(result.returncode, 2)
        self.assertIn("CVE-2022-0847", result.stdout)

    def test_unusable_catalogue_fails(self):
        bad = {"empty.json": '{"vulnerabilities":[]}', "html.json": "<html>503</html>", "wrong.json": "[]"}
        for name, text in bad.items():
            path = self.tmp / name
            path.write_text(text, encoding="utf-8")
            result = self.gate(path)
            self.assertEqual(result.returncode, 2, name)
            self.assertIn("did not run", (self.tmp / "report.html").read_text(encoding="utf-8"))
        for missing in (None, self.tmp / "absent.json"):
            self.assertEqual(self.gate(missing).returncode, 2, missing)


if __name__ == "__main__":
    unittest.main()
