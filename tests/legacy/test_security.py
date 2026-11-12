"""Integrity and dependency-graph regressions for production evidence handling."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "poc" / "legacy" / "scripts"))
from cra_evidence import snapshot
from merge_sbom import merge


class EvidenceSnapshot(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.product = self.root / "product.json"
        self.product.write_text(json.dumps({"annex_i": {"part_1": [{"evidence_refs": ["proof.txt"]}]}}))
        (self.root / "proof.txt").write_text("reviewed evidence")
        self.scan = self.root / "scan.json"
        self.scan.write_text('{"matches": []}')

    def test_snapshot_contains_linked_evidence_and_verifiable_hashes(self):
        manifest = snapshot([self.scan], self.product, self.root / "bundle", revision="commit-123")
        self.assertEqual(manifest["source_revision"], "commit-123")
        self.assertFalse(manifest["authenticated"])
        self.assertEqual({f["role"] for f in manifest["files"]}, {"input", "product", "linked-evidence"})
        for record in manifest["files"]:
            data = (self.root / "bundle" / record["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
        self.scan.write_text("changed after snapshot")
        self.assertEqual((self.root / "bundle" / manifest["files"][0]["path"]).read_text(), '{"matches": []}')

    def test_existing_bundle_is_not_overwritten(self):
        snapshot([self.scan], self.product, self.root / "bundle")
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            snapshot([self.scan], self.product, self.root / "bundle")

    def test_escaping_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "outside.txt"
            secret.write_text("outside root")
            (self.root / "proof.txt").unlink()
            (self.root / "proof.txt").symlink_to(secret)
            with self.assertRaisesRegex(ValueError, "escapes product root"):
                snapshot([self.scan], self.product, self.root / "bundle")
        self.assertFalse((self.root / "bundle").exists())

    def test_missing_evidence_does_not_leave_partial_bundle(self):
        (self.root / "proof.txt").unlink()
        with self.assertRaisesRegex(ValueError, "missing or empty"):
            snapshot([self.scan], self.product, self.root / "bundle")
        self.assertFalse((self.root / "bundle").exists())


class SbomIntegrity(unittest.TestCase):
    def setUp(self):
        self.base = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"name": "lib", "version": "1", "purl": "pkg:generic/lib@1", "bom-ref": "lib-a"}],
            "dependencies": [{"ref": "lib-a", "dependsOn": []}]}

    def test_duplicate_metadata_and_alias_edges_are_preserved(self):
        other = copy.deepcopy(self.base)
        other["components"][0].update({"bom-ref": "lib-b", "cpe": "cpe:2.3:a:vendor:lib:1:*:*:*:*:*:*:*"})
        other["components"].append({"name": "dep", "version": "2", "bom-ref": "dep"})
        other["dependencies"] = [{"ref": "lib-b", "dependsOn": ["dep"]}]
        result = merge([self.base, other])
        self.assertEqual(len(result["components"]), 2)
        self.assertIn("cpe", result["components"][0])
        self.assertEqual(result["dependencies"], [{"ref": "lib-a", "dependsOn": ["dep"]}])

    def test_mismatched_schema_versions_fail_with_both_versions(self):
        newer = copy.deepcopy(self.base)
        newer["specVersion"] = "1.6"
        with self.assertRaisesRegex(ValueError, "first input uses '1.6'.*another input uses '1.5'"):
            merge([newer, self.base])

    def test_conflicting_identity_is_rejected(self):
        other = copy.deepcopy(self.base)
        other["components"][0]["version"] = "different"
        with self.assertRaisesRegex(ValueError, "conflicting version"):
            merge([self.base, other])

    def test_ref_collision_is_rejected(self):
        other = copy.deepcopy(self.base)
        other["components"][0]["purl"] = "pkg:generic/other@2"
        with self.assertRaisesRegex(ValueError, "conflicting bom-ref"):
            merge([self.base, other])

    def test_dangling_dependency_is_rejected(self):
        self.base["dependencies"][0]["dependsOn"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "unknown component"):
            merge([self.base])

    def test_nested_inventory_is_not_silently_lost(self):
        self.base["components"][0]["components"] = [{"name": "nested"}]
        with self.assertRaisesRegex(ValueError, "nested components"):
            merge([self.base])


if __name__ == "__main__":
    unittest.main()
