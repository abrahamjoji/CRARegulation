"""Boundaries for untrusted input: parsing, archives, subprocesses, redaction, HTML."""
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

import helpers  # noqa: F401
from cra.common.archive import ArchiveLimits, inspect_tar, safe_extract
from cra.common.errors import UntrustedInputError
from cra.common.safety import Limits, PathScope, parse_json_bytes, read_json, redact, redact_text, run_tool, tool_environment
from cra.engine.report import esc, safe_url


def tar_with(path, build):
    with tarfile.open(path, "w") as archive:
        build(archive)


def regular(archive, name, data=b"x"):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


class Temp(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = Path(self._t.name)


class Json(Temp):
    def test_oversize_file_refused_before_loading(self):
        path = self.root / "big.json"
        path.write_text("[" + "1," * 1000 + "1]")
        with self.assertRaises(UntrustedInputError) as caught:
            read_json(path, max_bytes=100)
        self.assertEqual(caught.exception.code, "file_too_large")

    def test_deep_nesting_refused(self):
        with self.assertRaises(UntrustedInputError) as caught:
            parse_json_bytes(b"[" * 100000 + b"]" * 100000)
        self.assertEqual(caught.exception.code, "json_too_deep")
        with self.assertRaises(UntrustedInputError):
            parse_json_bytes(b"[" * 200 + b"]" * 200)

    def test_non_finite_numbers_refused(self):
        with self.assertRaises(UntrustedInputError):
            parse_json_bytes(b'{"score": NaN}')

    def test_directory_and_missing_file_refused(self):
        for path in (self.root, self.root / "absent.json"):
            with self.assertRaises(UntrustedInputError):
                read_json(path)


class Archives(Temp):
    def expect(self, code, build):
        path = self.root / f"{code}.tar"
        tar_with(path, build)
        with self.assertRaises(UntrustedInputError) as caught:
            inspect_tar(path)
        self.assertEqual(caught.exception.code, code)

    def test_traversal(self):
        self.expect("archive_traversal", lambda a: regular(a, "../evil"))

    def test_absolute_path(self):
        self.expect("archive_traversal", lambda a: regular(a, "/etc/evil"))

    def test_symlink_and_hardlink(self):
        def symlink(archive):
            info = tarfile.TarInfo("link")
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(info)
        self.expect("archive_link", symlink)
        def hardlink(archive):
            info = tarfile.TarInfo("hard")
            info.type, info.linkname = tarfile.LNKTYPE, "/etc/passwd"
            archive.addfile(info)
        self.expect("archive_link", hardlink)

    def test_device_and_fifo(self):
        def device(archive):
            info = tarfile.TarInfo("dev")
            info.type = tarfile.CHRTYPE
            archive.addfile(info)
        self.expect("archive_special", device)

    def test_duplicate_member(self):
        self.expect("archive_duplicate", lambda a: (regular(a, "same"), regular(a, "same")))

    def test_member_count_and_expansion_limits(self):
        path = self.root / "many.tar"
        tar_with(path, lambda a: [regular(a, f"f{i}") for i in range(5)])
        with self.assertRaises(UntrustedInputError) as caught:
            inspect_tar(path, ArchiveLimits(max_members=3))
        self.assertEqual(caught.exception.code, "archive_too_many")
        with self.assertRaises(UntrustedInputError) as caught:
            inspect_tar(path, ArchiveLimits(max_total_bytes=2))
        self.assertEqual(caught.exception.code, "archive_too_large")

    def test_gzip_bomb_stops_at_the_limit(self):
        path = self.root / "bomb.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            regular(archive, "zeros", b"\0" * (4 * 1024 * 1024))
        self.assertLess(path.stat().st_size, 100 * 1024)
        with self.assertRaises(UntrustedInputError) as caught:
            inspect_tar(path, ArchiveLimits(max_member_bytes=1024 * 1024))
        self.assertEqual(caught.exception.code, "archive_too_large")

    def test_not_an_archive(self):
        path = self.root / "garbage.tar"
        path.write_bytes(os.urandom(2048))
        with self.assertRaises(UntrustedInputError) as caught:
            inspect_tar(path)
        self.assertEqual(caught.exception.code, "archive_invalid")

    def test_safe_extract_writes_regular_files_without_execute_bits(self):
        path = self.root / "good.tar"
        def build(archive):
            info = tarfile.TarInfo("dir/run.sh")
            info.size, info.mode = 2, 0o4777
            archive.addfile(info, io.BytesIO(b"hi"))
        tar_with(path, build)
        out = safe_extract(path, self.root / "out")
        target = out / "dir" / "run.sh"
        self.assertEqual(target.read_bytes(), b"hi")
        self.assertEqual(target.stat().st_mode & 0o7777, 0o600)

    def test_safe_extract_refuses_hostile_archive_and_writes_nothing(self):
        path = self.root / "mixed.tar"
        tar_with(path, lambda a: (regular(a, "good"), regular(a, "../../evil")))
        with self.assertRaises(UntrustedInputError):
            safe_extract(path, self.root / "out")
        self.assertFalse((self.root / "out").exists())
        self.assertFalse((self.root.parent / "evil").exists())


class Subprocesses(Temp):
    def test_no_shell_interpolation(self):
        marker = self.root / "pwned"
        output = self.root / "out"
        run_tool(["/bin/echo", f"$(touch {marker}); touch {marker}"], stdout_path=output)
        self.assertFalse(marker.exists())
        self.assertIn("touch", output.read_text())

    def test_timeout_kills_process_tree(self):
        start = time.monotonic()
        result = run_tool(["/bin/sh", "-c", "sleep 60 & wait"], limits=Limits(timeout_seconds=1))
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - start, 15)

    def test_missing_tool_reported(self):
        result = run_tool([str(self.root / "absent")])
        self.assertTrue(result.missing)

    def test_output_size_limit_enforced(self):
        output = self.root / "big"
        result = run_tool(["/bin/sh", "-c", "head -c 5000000 /dev/zero"], stdout_path=output, limits=Limits(output_bytes=1024 * 1024))
        self.assertNotEqual(result.returncode, 0)
        self.assertLessEqual(output.stat().st_size, 1024 * 1024)

    def test_credentials_do_not_reach_tools(self):
        os.environ["CRA_TOKEN"] = "cra_shouldnotleak000000000000"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "abc"
        self.addCleanup(os.environ.pop, "CRA_TOKEN")
        self.addCleanup(os.environ.pop, "AWS_SECRET_ACCESS_KEY")
        env = tool_environment()
        self.assertNotIn("CRA_TOKEN", env)
        output = self.root / "env"
        run_tool(["/usr/bin/env"], stdout_path=output)
        text = output.read_text()
        self.assertNotIn("shouldnotleak", text)
        self.assertNotIn("AWS_SECRET", text)

    def test_stderr_is_redacted(self):
        result = run_tool(["/bin/sh", "-c", "echo 'password=hunter2 https://user:pw@example.com/x' >&2; exit 1"])
        self.assertNotIn("hunter2", result.stderr)
        self.assertNotIn("user:pw", result.stderr)


class Redaction(unittest.TestCase):
    def test_known_token_shapes(self):
        for secret in ("ghp_" + "a" * 36, "AKIA" + "B" * 16, "glpat-" + "c" * 20, "cra_" + "d" * 30,
                       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijkl"):
            cleaned, count = redact_text(f"value {secret} end")
            self.assertNotIn(secret, cleaned)
            self.assertGreater(count, 0)

    def test_json_keys_and_cmake_cache_shape(self):
        cleaned, count = redact({"api_key": "k1", "nested": [{"name": "MY_TOKEN", "value": "v1"}, {"name": "CMAKE_BUILD_TYPE", "value": "Release"}],
                                 "url": "https://joe:pw@host/repo", "author": "Jane"})
        text = json.dumps(cleaned)
        self.assertNotIn("k1", text)
        self.assertNotIn('"v1"', text)
        self.assertNotIn("joe:pw", text)
        self.assertIn("Release", text)
        self.assertIn("Jane", text)
        self.assertEqual(count, 3)

    def test_private_key_block(self):
        cleaned, _ = redact_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
        self.assertNotIn("abc", cleaned)


class Scope(Temp):
    def test_symlink_cannot_escape_scope(self):
        inside = self.root / "inside"
        inside.mkdir()
        with tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "secret"
            secret.write_text("s")
            link = inside / "link"
            link.symlink_to(secret)
            scope = PathScope([inside])
            with self.assertRaises(UntrustedInputError) as caught:
                scope.require(link)
            self.assertEqual(caught.exception.code, "path_out_of_scope")


class Html(unittest.TestCase):
    def test_active_links_are_removed(self):
        for url in ("javascript:alert(1)", "data:text/html,x", "JAVASCRIPT:alert(1)", " javascript:alert(1)", "http://", "java\nscript:alert(1)"):
            self.assertEqual(safe_url(url), "")
        self.assertEqual(safe_url("https://nvd.nist.gov/x"), "https://nvd.nist.gov/x")

    def test_escape(self):
        self.assertEqual(esc('"><script>'), "&quot;&gt;&lt;script&gt;")


if __name__ == "__main__":
    unittest.main()
