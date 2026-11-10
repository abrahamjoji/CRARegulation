"""Documented exit codes, through the real command-line entry point."""
import contextlib
import io
import json
import subprocess
import sys
import unittest
from unittest import mock

import helpers
from helpers import Workspace
from cra import cli
from cra.common import errors


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue(), err.getvalue()


class Exits(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        self.config = str(self.ws.root / "cra.toml")

    def flow(self):
        self.assertEqual(run("prepare", "--config", self.config)[0], 0)
        self.assertEqual(run("collect", "--config", self.config)[0], 0)
        return run("analyze", "--config", self.config)[0]

    def test_constants_are_the_documented_values(self):
        self.assertEqual((errors.EXIT_PASSED, errors.EXIT_POLICY, errors.EXIT_INCOMPLETE, errors.EXIT_CONFIG, errors.EXIT_AUTH, errors.EXIT_OPERATIONAL), (0, 10, 20, 30, 31, 32))

    def test_full_flow_policy_block(self):
        self.assertEqual(self.flow(), 0)
        record = self.ws.root / "gate.json"
        code, out, _ = run("gate", "--result", str(self.ws.analysis_dir), "--record", str(record))
        self.assertEqual(code, 10)
        self.assertIn("policy_blocked", out)
        self.assertEqual(json.loads(record.read_text())["outcome"], "policy_blocked")

    def test_pass_after_scoped_triage(self):
        self.ws.triage_all_blockers(self.ws.analyze())
        self.assertEqual(self.flow(), 0)
        self.assertEqual(run("gate", "--result", str(self.ws.analysis_dir))[0], 0)

    def test_incomplete_flow(self):
        self.ws.set_behaviour({"grype": "fail"})
        self.assertEqual(self.flow(), 20)
        code, out, _ = run("gate", "--result", str(self.ws.analysis_dir))
        self.assertEqual(code, 20)
        self.assertIn("scanner_failed", out)

    def test_collect_reports_incomplete_when_required_source_missing(self):
        (self.ws.root / "release-static.graph.json").unlink()
        code, out, _ = run("collect", "--config", self.config)
        self.assertEqual(code, 20)
        self.assertIn("missing", out)

    def test_config_errors(self):
        self.assertEqual(run("collect", "--config", str(self.ws.root / "absent.toml"))[0], 30)
        self.assertEqual(run("gate", "--mode", "nonsense")[0], 30)
        self.assertEqual(run()[0], 30)
        self.ws.edit_config('policy = "policy.toml"', 'policy = "absent.toml"')
        self.assertEqual(run("collect", "--config", self.config)[0], 0)
        self.assertEqual(run("analyze", "--config", self.config)[0], 30)

    def test_analyze_without_collection_is_incomplete(self):
        self.assertEqual(run("analyze", "--config", self.config)[0], 20)

    def test_gate_without_result_is_incomplete(self):
        self.assertEqual(run("gate", "--result", str(self.ws.root / "nowhere"))[0], 20)

    def test_internal_bug_is_operational_failure_and_redacted(self):
        with mock.patch("cra.collector.collect.collect", side_effect=RuntimeError("password=hunter2 oops")):
            code, _, err = run("collect", "--config", self.config)
        self.assertEqual(code, 32)
        self.assertIn("internal failure", err)
        self.assertNotIn("hunter2", err)

    def test_hosted_without_a_url_is_config_error(self):
        self.flow()
        self.assertEqual(run("analyze", "--config", self.config, "--hosted")[0], 30)

    def test_version_flag(self):
        code, out, _ = run("--version")
        self.assertEqual(code, 0)
        self.assertIn("cra 0.1.0", out)

    def test_collector_only_distribution_runs_without_engine(self):
        """The shipped collector package must work with the proprietary engine removed."""
        import shutil
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as work:
            package = Path(work) / "cra"
            shutil.copytree(helpers.REPO / "src" / "cra", package, ignore=shutil.ignore_patterns("engine", "hosted", "__pycache__"))
            # The fake scanners start with `#!/usr/bin/env python3`; keep this interpreter's folder on PATH,
            # because official Python images and pyenv have no python3 in /usr/bin.
            environment = {"PYTHONPATH": work, "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"}
            self.ws.analyze()
            command = [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {work!r}); from cra.cli import entrypoint; sys.argv = sys.argv[0:1] + sys.argv[1:]; entrypoint()"]
            result = subprocess.run(command + ["collect", "--config", self.config], capture_output=True, text=True, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(command + ["gate", "--result", str(self.ws.analysis_dir)], capture_output=True, text=True, env=environment)
            self.assertEqual(result.returncode, 10, result.stderr)
            result = subprocess.run(command + ["analyze", "--config", self.config], capture_output=True, text=True, env=environment)
            self.assertEqual(result.returncode, 32)
            self.assertIn("engine_not_included", result.stderr)


if __name__ == "__main__":
    unittest.main()
