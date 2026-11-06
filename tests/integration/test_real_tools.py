"""Real external tools. Explicitly opt-in: CRA_INTEGRATION=1, plus network, conan, cmake and .tools/.

Nothing here is faked. Vulnerability counts change as databases update, so these
tests assert structure and outcomes, not exact numbers.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from cra import cli  # noqa: E402
from cra.collector import update  # noqa: E402
from cra.common.safety import read_json  # noqa: E402
from cra.engine import measure  # noqa: E402
from cra.gate import evaluate_gate  # noqa: E402

ENABLED = os.environ.get("CRA_INTEGRATION") == "1"
REFERENCE = REPO / "reference"
OUTPUT = REFERENCE / "out"
CRA = str(REFERENCE / "cra.toml")
ANALYSIS = OUTPUT / "cra" / "analysis"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@unittest.skipUnless(ENABLED, "set CRA_INTEGRATION=1 to run real external tools")
class ReferenceEndToEnd(unittest.TestCase):
    """The first acceptance criterion, with real Conan, CMake, Syft and Grype."""

    @classmethod
    def setUpClass(cls):
        shutil.rmtree(REFERENCE / "app" / "build-release-static", ignore_errors=True)
        shutil.rmtree(REFERENCE / "app" / "build-debug-shared-lz4", ignore_errors=True)
        subprocess.run([str(REFERENCE / "build_reference.sh")], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["curl", "--proto", "=https", "-fsSL", "--max-time", "120", KEV_URL, "-o", str(OUTPUT / "kev.json")], check=True)

    def test_01_prepare_ran_before_configure_and_reply_exists(self):
        replies = list((REFERENCE / "app/build-release-static/build/Release/.cmake/api/v1/reply").glob("index-*.json"))
        self.assertEqual(len(replies), 1)

    def test_02_collect(self):
        self.assertEqual(cli.main(["collect", "--config", CRA]), 0)

    def test_03_analyze(self):
        self.assertEqual(cli.main(["analyze", "--config", CRA]), 0)
        result = read_json(ANALYSIS / "result.json")
        self.assertEqual(result["scan_status"], "complete")
        self.assertEqual({row["name"] for row in result["scanners"]}, {"grype", "syft"})
        self.assertTrue(result["vulnerability_data"]["grype"]["built"])
        self.assertTrue(result["vulnerability_data"]["kev"]["catalog_version"])

    def test_04_inventory_matches_known_expectation(self):
        metrics = measure.compare_files(ANALYSIS / "inventory.json", REFERENCE / "expected" / "inventory.json")
        self.assertEqual(metrics["missing"], [])
        self.assertEqual(metrics["unexpected"], [])
        self.assertEqual(metrics["attribute_mismatches"], [])

    def test_05_findings_are_explained(self):
        result = read_json(ANALYSIS / "result.json")
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            self.assertTrue(finding["component"]["joined_to_inventory"], finding["component"])
            self.assertTrue(finding["matching"]["rationale"])
            self.assertTrue(finding["vulnerability"]["source"]["namespace"])
            self.assertFalse(finding["exploitability"]["established"])
        shipped = {item["component"]["name"] for item in result["findings"] if item["presence"]["shipped"] == "yes"}
        build_only = {item["component"]["name"] for item in result["findings"] if item["presence"]["shipped"] == "no"}
        self.assertIn("libc6", shipped)
        self.assertIn("openssl", build_only)

    def test_06_gate_blocks_on_real_shipped_findings(self):
        record = evaluate_gate(ANALYSIS, "build")
        self.assertEqual((record["outcome"], record["exit_code"]), ("policy_blocked", 10))

    def test_07_gate_incomplete_when_scanner_database_is_absent(self):
        with tempfile.TemporaryDirectory() as empty:
            before = os.environ.get("GRYPE_DB_CACHE_DIR")
            os.environ["GRYPE_DB_CACHE_DIR"] = empty
            try:
                out = Path(empty) / "analysis"
                code = cli.main(["analyze", "--config", CRA, "--out", str(out)])
            finally:
                if before is None:
                    os.environ.pop("GRYPE_DB_CACHE_DIR")
                else:
                    os.environ["GRYPE_DB_CACHE_DIR"] = before
            self.assertEqual(code, 20)
            self.assertEqual(evaluate_gate(out, "build")["outcome"], "incomplete")

    def test_08_gate_passes_only_after_scoped_triage_of_shipped_blockers(self):
        result = read_json(ANALYSIS / "result.json")
        statements = [{"vulnerability": {"name": item["vulnerability"]["id"]}, "products": [{"@id": item["component"]["purl"]}], "status": "not_affected",
                       "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "Integration-test fixture decision, not a real assessment.", "timestamp": "2026-11-01T00:00:00Z"}
                      for item in result["findings"] if item["presence"]["shipped"] != "no" and item["severity"] in ("critical", "high")]
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "vex.json").write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/test", "author": "Reference Security Team (fictional)", "timestamp": "2026-11-01T00:00:00Z", "version": 1, "statements": statements}))
            config = (REFERENCE / "cra.toml").read_text().replace('vex = ["vex/reference.openvex.json"]', f'vex = ["{root}/vex.json"]')
            temp_config = REFERENCE / "out" / "cra-triaged.toml"
            temp_config.write_text(config.replace('roots = [".", "out"]', 'roots = [".."]').replace('"app/', '"../app/').replace('"out/', '"./').replace('"records/', '"../records/').replace('"../.tools/', '"../../.tools/').replace('policy = "policy.toml"', 'policy = "../policy.toml"'))
            out = root / "analysis"
            self.assertEqual(cli.main(["analyze", "--config", str(temp_config), "--collection", str(OUTPUT / "cra" / "collection"), "--out", str(out)]), 0)
            record = evaluate_gate(out, "build")
            self.assertEqual((record["outcome"], record["exit_code"]), ("passed", 0), record["reasons"][:3])
            kept = read_json(out / "result.json")
            self.assertEqual(kept["summary"]["total"], result["summary"]["total"])
            temp_config.unlink()


@unittest.skipUnless(ENABLED, "set CRA_INTEGRATION=1 to run real external tools")
class RealRegistryImage(unittest.TestCase):
    def test_syft_pulls_a_pinned_image_without_a_docker_daemon(self):
        """Needs registry access. The digest is looked up here, so nothing mutable is scanned."""
        import urllib.request
        token = json.load(urllib.request.urlopen("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/busybox:pull", timeout=20))["token"]
        request = urllib.request.Request("https://registry-1.docker.io/v2/library/busybox/manifests/1.37.0", method="HEAD",
                                         headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"})
        digest = urllib.request.urlopen(request, timeout=20).headers["docker-content-digest"]
        from cra.collector import container
        from cra.common.bundle import EvidenceStore
        from cra.common.config import Image, Tools
        with tempfile.TemporaryDirectory() as work:
            image = Image(id="busybox", role="final", reference=f"docker.io/library/busybox@{digest}")
            record, observations, status, reason, tool = container.collect_image(image, Tools(syft=str(REPO / ".tools" / "syft"), timeout_seconds=300), EvidenceStore(work))
        self.assertIn(status, ("complete", "partial"), reason)
        self.assertEqual(tool["version"], "1.57.0")
        self.assertTrue(record["digest"])


@unittest.skipUnless(ENABLED, "set CRA_INTEGRATION=1 to run real external tools")
class RealCosign(unittest.TestCase):
    """Local key signing and verification with real cosign. Nothing leaves this machine."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = Path(self._t.name).resolve()
        self.cosign = str(REPO / ".tools" / "cosign")
        env = {"PATH": "/usr/bin:/bin", "COSIGN_PASSWORD": "integration-test-only", "HOME": str(self.root)}
        subprocess.run([self.cosign, "generate-key-pair"], cwd=self.root, env=env, check=True, capture_output=True)
        self.env = env
        self.key = self.root / "cosign.key"
        self.public = self.root / "cosign.pub"
        self.wheel = self.root / "cra_evidence-0.1.0-py3-none-any.whl"
        self.wheel.write_bytes(b"pretend wheel")

    def build(self, name, version):
        directory = self.root / name
        result = subprocess.run([sys.executable, str(REPO / "scripts" / "build_release.py"), "--out", str(directory), "--wheel", str(self.wheel), "--version", version,
                                 "--cosign", self.cosign, "--key", str(self.key)], env={**self.env, "PATH": os.environ["PATH"]}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return directory

    def test_sign_verify_tamper_upgrade_rollback(self):
        trust = {"cosign": self.cosign, "public_key": str(self.public)}
        first = self.build("r1", "1.0.0")
        self.assertEqual(update.verify_release(first, **trust)["version"], "1.0.0")
        home = self.root / "home"
        update.activate(first, home, **trust)
        second = self.build("r2", "1.1.0")
        self.assertEqual(update.activate(second, home, **trust)["current"], "1.1.0")
        self.assertEqual(update.rollback(home, **trust)["current"], "1.0.0")
        tampered = self.build("r3", "1.2.0")
        document = json.loads((tampered / "release.json").read_text())
        document["version"] = "9.9.9"
        (tampered / "release.json").write_text(json.dumps(document))
        from cra.common.errors import CraError
        with self.assertRaises(CraError) as caught:
            update.verify_release(tampered, **trust)
        self.assertEqual(caught.exception.code, "release_signature_invalid")
        subprocess.run([self.cosign, "generate-key-pair", "--output-key-prefix", "other"], cwd=self.root, env=self.env, check=True, capture_output=True)
        with self.assertRaises(CraError) as caught:
            update.verify_release(second, cosign=self.cosign, public_key=str(self.root / "other.pub"))
        self.assertEqual(caught.exception.code, "release_signature_invalid")


if __name__ == "__main__":
    unittest.main()
