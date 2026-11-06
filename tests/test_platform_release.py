"""Update verification and rollback with a fake cosign. Real cosign runs in tests/integration."""
import json
import stat
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from cra.collector import update
from cra.common.errors import ConfigError, CraError, EXIT_AUTH
from cra.common.safety import sha256_bytes

FAKE_COSIGN = r'''#!/usr/bin/env python3
import hashlib, sys
from pathlib import Path
args = sys.argv[1:]
blob = Path(args[1])
bundle = Path(args[args.index("--bundle") + 1])
if bundle.read_text() != hashlib.sha256(blob.read_bytes()).hexdigest():
    print("signature mismatch", file=sys.stderr)
    sys.exit(1)
'''


def sign(path):
    (path.parent / (path.name + ".sigstore.json")).write_text(sha256_bytes(path.read_bytes()))


class Release(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = Path(self._t.name).resolve()
        self.cosign = self.root / "cosign"
        self.cosign.write_text(FAKE_COSIGN)
        self.cosign.chmod(stat.S_IRWXU)
        self.key = self.root / "cosign.pub"
        self.key.write_text("public key")
        self.trust = {"cosign": str(self.cosign), "public_key": str(self.key)}
        self.home = self.root / "home"

    def make(self, version, payload=b"wheel", signed=True, name=None):
        directory = self.root / (name or f"r-{version}")
        directory.mkdir()
        (directory / "cra.whl").write_bytes(payload)
        document = directory / "release.json"
        document.write_text(json.dumps({"schema_version": update.RELEASE_SCHEMA, "version": version, "files": [{"name": "cra.whl", "sha256": sha256_bytes(payload)}]}))
        if signed:
            sign(document)
        return directory

    def code(self, call):
        with self.assertRaises(CraError) as caught:
            call()
        return caught.exception.code, caught.exception.exit_code

    def test_valid_release_verifies(self):
        self.assertEqual(update.verify_release(self.make("1.0.0"), **self.trust)["version"], "1.0.0")

    def test_unsigned_release_refused(self):
        self.assertEqual(self.code(lambda: update.verify_release(self.make("1.0.0", signed=False), **self.trust)), ("release_unsigned", EXIT_AUTH))

    def test_tampered_document_refused(self):
        directory = self.make("1.0.0")
        document = json.loads((directory / "release.json").read_text())
        document["version"] = "9.0.0"
        (directory / "release.json").write_text(json.dumps(document))
        self.assertEqual(self.code(lambda: update.verify_release(directory, **self.trust))[0], "release_signature_invalid")

    def test_tampered_payload_refused(self):
        directory = self.make("1.0.0")
        (directory / "cra.whl").write_bytes(b"evil")
        self.assertEqual(self.code(lambda: update.verify_release(directory, **self.trust))[0], "release_hash_mismatch")

    def test_unsafe_file_name_refused(self):
        directory = self.make("1.0.0")
        document = directory / "release.json"
        document.write_text(json.dumps({"schema_version": update.RELEASE_SCHEMA, "version": "1.0.0", "files": [{"name": "../evil", "sha256": "x"}]}))
        sign(document)
        self.assertEqual(self.code(lambda: update.verify_release(directory, **self.trust))[0], "release_document_invalid")

    def test_trust_root_is_mandatory(self):
        with self.assertRaises(ConfigError):
            update.verify_release(self.make("1.0.0"), cosign=str(self.cosign))
        with self.assertRaises(ConfigError):
            update.verify_release(self.make("1.0.1"), cosign=str(self.cosign), certificate_identity="x")

    def test_activate_upgrade_and_rollback(self):
        update.activate(self.make("1.0.0"), self.home, **self.trust)
        state = update.activate(self.make("1.1.0"), self.home, **self.trust)
        self.assertEqual((state["current"], state["previous"]), ("1.1.0", "1.0.0"))
        state = update.rollback(self.home, **self.trust)
        self.assertEqual((state["current"], state["previous"]), ("1.0.0", "1.1.0"))
        self.assertEqual(state["history"][-1], {"action": "rollback", "version": "1.0.0"})

    def test_silent_downgrade_refused(self):
        update.activate(self.make("2.0.0"), self.home, **self.trust)
        self.assertEqual(self.code(lambda: update.activate(self.make("1.0.0"), self.home, **self.trust))[0], "release_downgrade")
        self.assertEqual(update.activate(self.root / "r-1.0.0", self.home, allow_downgrade=True, **self.trust)["current"], "1.0.0")

    def test_version_is_immutable(self):
        update.activate(self.make("1.0.0", b"a", name="a"), self.home, **self.trust)
        self.assertEqual(self.code(lambda: update.activate(self.make("1.0.0", b"b", name="b"), self.home, **self.trust))[0], "release_mutated")

    def test_failed_verification_leaves_current_release_active(self):
        update.activate(self.make("1.0.0"), self.home, **self.trust)
        bad = self.make("1.1.0")
        (bad / "cra.whl").write_bytes(b"evil")
        with self.assertRaises(CraError):
            update.activate(bad, self.home, **self.trust)
        self.assertEqual(update.load_state(self.home)["current"], "1.0.0")
        self.assertFalse((self.home / "versions" / "1.1.0").exists())

    def test_rollback_reverifies_and_detects_tampered_stored_release(self):
        update.activate(self.make("1.0.0"), self.home, **self.trust)
        update.activate(self.make("1.1.0"), self.home, **self.trust)
        (self.home / "versions" / "1.0.0" / "cra.whl").write_bytes(b"evil")
        self.assertEqual(self.code(lambda: update.rollback(self.home, **self.trust))[0], "release_hash_mismatch")
        self.assertEqual(update.load_state(self.home)["current"], "1.1.0")

    def test_rollback_without_earlier_release(self):
        update.activate(self.make("1.0.0"), self.home, **self.trust)
        self.assertEqual(self.code(lambda: update.rollback(self.home, **self.trust))[0], "rollback_unavailable")


if __name__ == "__main__":
    unittest.main()
