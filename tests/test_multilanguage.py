"""Python and language-independent collection; no network or customer code execution."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import helpers
from cra import cli
from cra.collector import directory, python_env
from cra.collector.collect import collect
from cra.common.bundle import reset_output, verify_manifest, write_manifest
from cra.common.config import Configuration, load_config
from cra.common.errors import ConfigError, UntrustedInputError
from cra.common.safety import ToolResult
from cra.engine.reconcile import reconcile, export_cyclonedx


def inspect_document():
    return {"version": "1", "pip_version": "26.1.2", "environment": {"python_version": "3.12", "sys_platform": "linux"},
            "installed": [{"metadata": {"name": "My_App", "version": "1.0", "requires_dist": ["Demo.Lib>=2", "Other; sys_platform == 'win32'"]},
                           "requested": True, "metadata_location": "/env/my_app.dist-info"},
                          {"metadata": {"name": "Demo.Lib", "version": "2.1"}, "requested": False}]}


class PythonMetadata(unittest.TestCase):
    def parse(self, document=None, **kwargs):
        return python_env.collect_inspect(document if document is not None else inspect_document(), Configuration("python", **kwargs), "ev")

    def test_installed_packages_normalized_and_edges_scoped(self):
        result = self.parse()
        self.assertEqual({r["identity"]["purl"] for r in result["observations"]}, {"pkg:pypi/my-app@1.0", "pkg:pypi/demo-lib@2.1"})
        self.assertTrue(any(e["from"] == "pkg:pypi/my-app@1.0" and e["to"] == "pkg:pypi/demo-lib@2.1" for e in result["edges"]))
        self.assertFalse(any("other" in e["to"] for e in result["edges"]))
        self.assertTrue(any("conditional" in note for note in result["limitations"]))
        self.assertEqual(result["problems"], [])

    def test_missing_unconditional_distribution_is_partial(self):
        doc = inspect_document()
        doc["installed"].pop()
        self.assertIn("absent", self.parse(doc)["problems"][0])

    def test_unknown_schema_duplicate_and_malformed_packages_fail(self):
        base = inspect_document()
        bad = [{}, {**base, "version": "2"}, {**base, "installed": None},
               {**base, "installed": base["installed"] * 2},
               {**base, "installed": [{"metadata": {"name": "bad/name", "version": "1"}}]},
               {**base, "installed": [{"metadata": {"name": "ok", "version": "1", "requires_dist": "dep"}}]}]
        for doc in bad:
            with self.subTest(doc=doc), self.assertRaises(UntrustedInputError):
                self.parse(doc)

    def test_empty_environment_is_not_clean(self):
        doc = inspect_document()
        doc["installed"] = []
        self.assertTrue(self.parse(doc)["problems"])

    def test_editable_or_direct_install_is_not_proven_upstream(self):
        doc = inspect_document()
        doc["installed"][0]["direct_url"] = {"url": "file:///checkout", "dir_info": {"editable": True}}
        result = self.parse(doc)
        self.assertTrue(any("forks" in note for note in result["limitations"]))
        self.assertFalse(result["observations"][0]["shipped_claim"])


class Project(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = '''schema_version = "cra.config/1"
[product]
name = "mixed-project"
version = "1.0"
[scope]
roots = ["."]
[output]
dir = "out"
'''
        self.path = self.root / "cra.toml"

    def config(self, extra=""):
        self.path.write_text(self.base + extra)
        return load_config(self.path)

    def python_project(self, **kwargs):
        (self.root / "pip.json").write_text(json.dumps(inspect_document()))
        extra = '\n[[configurations]]\nid = "python"\npip_inspect = "pip.json"\n'
        extra += '\n'.join(f'{key} = {str(value).lower() if isinstance(value, bool) else json.dumps(value)}' for key, value in kwargs.items())
        return self.config(extra)

    def test_python_only_collection_requires_no_conan_cmake_or_syft(self):
        config = self.python_project(pip_inspect_shipped=True)
        out, destination = collect(config)
        inventory = reconcile(out)
        self.assertEqual(inventory["coverage"]["status"], "complete")
        self.assertTrue(all(c["presence"]["shipped"] == "yes" for c in inventory["components"]))
        self.assertEqual(verify_manifest(destination), [])
        self.assertTrue(all(c["purl"].startswith("pkg:pypi/") for c in export_cyclonedx(inventory)["components"]))

    def test_python_build_tools_do_not_become_shipped_dependencies(self):
        out, _ = collect(self.python_project(pip_inspect_scope="build_tool"))
        self.assertTrue(all(c["presence"]["shipped"] == "no" for c in reconcile(out)["components"]))

    def test_missing_and_unsupported_python_metadata_are_incomplete(self):
        config = self.python_project()
        (self.root / "pip.json").unlink()
        out, _ = collect(config)
        self.assertEqual(reconcile(out)["coverage"]["status"], "incomplete")
        (self.root / "pip.json").write_text('{"version": "999"}')
        out, _ = collect(config)
        self.assertEqual(reconcile(out)["coverage"]["status"], "incomplete")

    def test_python_prepare_is_a_successful_noop(self):
        self.python_project()
        self.assertEqual(cli.main(["prepare", "--config", str(self.path)]), 0)

    def test_boolean_strings_and_conflicting_shipped_scope_rejected(self):
        for extra in ('\n[[configurations]]\nid="py"\nrequired="false"',
                      '\n[[configurations]]\nid="py"\npip_inspect_shipped=true\npip_inspect_scope="test"',
                      '\n[tools]\nallow_unverified_versions="false"',
                      '\n[hosted]\npoll_seconds=0',
                      '\n[components]\nrecords="one.json"'):
            with self.subTest(extra=extra), self.assertRaises(ConfigError):
                self.config(extra)

    def test_duplicate_artifact_ids_across_adapters_rejected(self):
        with self.assertRaises(ConfigError):
            self.config('\n[[directories]]\nid="same"\npath="."\n[[artifacts]]\nid="same"\npath="app"')

    def test_output_cannot_delete_customer_source_directory(self):
        config = self.python_project()
        code = self.root / "source"
        code.mkdir()
        (code / "app.py").write_text("print('keep me')")
        with self.assertRaises(UntrustedInputError):
            collect(config, code)
        self.assertTrue((code / "app.py").exists())
        with self.assertRaises(UntrustedInputError):
            collect(config, self.root)
        self.assertTrue(self.path.exists())

    def test_recognized_outputs_can_be_replaced_but_extra_files_cannot(self):
        config = self.python_project()
        collect(config)
        _, output = collect(config)
        (output / "user-note.txt").write_text("keep")
        with self.assertRaises(UntrustedInputError):
            collect(config)
        self.assertTrue((output / "user-note.txt").exists())

    def test_output_symlink_is_refused(self):
        config = self.python_project()
        target = self.root / "target"
        target.mkdir()
        output = self.root / "link"
        output.symlink_to(target, target_is_directory=True)
        with self.assertRaises(UntrustedInputError):
            collect(config, output)
        self.assertTrue(output.is_symlink())

    def test_analysis_output_cannot_overlap_collection_or_user_files(self):
        from cra.engine.analyze import run_analysis
        config = self.python_project()
        _, collection = collect(config)
        with self.assertRaises(UntrustedInputError):
            run_analysis(collection, config.analysis, config.tools, collection)
        self.assertTrue((collection / "collection.json").is_file())
        unrelated = self.root / "customer"
        unrelated.mkdir()
        (unrelated / "source.c").write_text("int main(void){return 0;}")
        with self.assertRaises(UntrustedInputError):
            run_analysis(collection, config.analysis, config.tools, unrelated)
        self.assertTrue((unrelated / "source.c").is_file())

    def test_directory_adapter_retains_raw_inventory_and_never_uploads_sources(self):
        (self.root / "project").mkdir()
        (self.root / "project" / "app.py").write_text("private-source-marker")
        config = self.config('\n[[directories]]\nid="app"\npath="project"\nrole="final"')
        document = json.loads((helpers.FIXTURES / "final.syft.json").read_text())
        def scan(target, tools, output):
            Path(output).write_text(json.dumps(document))
            return ToolResult(0, "", False)
        with patch.object(directory, 'tool_versions', return_value='1.57.0'), patch.object(directory, 'run_syft', side_effect=scan):
            out, dest = collect(config)
        self.assertTrue(out["observations"])
        self.assertTrue(all(o["source"] == "directory:final" for o in out["observations"]))
        self.assertTrue(all(c["presence"]["shipped"] == "yes" for c in reconcile(out)["components"]))
        for path in dest.rglob('*'):
            if path.is_file():
                self.assertNotIn("private-source-marker", path.read_text(errors='replace'))

    def test_directory_symlinks_special_files_and_size_limit_are_refused(self):
        source, stage = self.root / 'project', self.root / 'stage'
        source.mkdir(); stage.mkdir()
        (source / 'link').symlink_to('/etc/hostname')
        with self.assertRaises(UntrustedInputError):
            directory.snapshot(source, stage)
        (source / 'link').unlink()
        os.mkfifo(source / 'fifo')
        with self.assertRaises(UntrustedInputError):
            directory.snapshot(source, stage)
        (source / 'fifo').unlink()
        (source / 'large').write_text('too big')
        with patch.object(directory, 'MAX_BYTES', 2), self.assertRaises(UntrustedInputError):
            directory.snapshot(source, stage)

    def test_missing_directory_is_incomplete(self):
        config = self.config('\n[[directories]]\nid="app"\npath="missing"')
        out, _ = collect(config)
        self.assertEqual(reconcile(out)["coverage"]["status"], "incomplete")

    def test_schema_matches_new_inputs(self):
        try:
            import jsonschema, tomllib
        except ImportError:
            self.skipTest('jsonschema unavailable')
        self.python_project(pip_inspect_shipped=True)
        schema = json.loads((helpers.REPO / 'src/cra/schemas/config.schema.json').read_text())
        jsonschema.validate(tomllib.loads(self.path.read_text()), schema)
        self.config('\n[[directories]]\nid="app"\npath="project"\nrole="source"')
        jsonschema.validate(tomllib.loads(self.path.read_text()), schema)


class GateAndMatching(unittest.TestCase):
    def test_native_cpe_hints_are_not_applied_to_pypi_names(self):
        from cra.engine.grype import apply_cpe_hints
        document = {'components': [{'name': 'zlib', 'version': '1.0', 'purl': 'pkg:pypi/zlib@1.0', 'bom-ref': 'python'},
                                   {'name': 'zlib', 'version': '1.0', 'purl': 'pkg:conan/zlib@1.0', 'bom-ref': 'native'}]}
        self.assertEqual(apply_cpe_hints(document), {'native'})
        self.assertNotIn('cpe', document['components'][0])

    def test_contradictory_and_malformed_gate_records_cannot_pass(self):
        from cra.gate import evaluate_gate
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            evaluation = {'mode': 'build', 'outcome': 'passed', 'incomplete_reasons': [], 'policy_violations': []}
            result = {'schema_version': 'cra.result/1', 'scan_status': 'complete', 'source': {}, 'policy': {}, 'artifacts': [],
                      'evaluation': {'build': evaluation}}
            for changes in ({'policy_violations': [{'code': 'blocked', 'message': 'stop'}]},
                            {'incomplete_reasons': [{'code': 'missing', 'message': 'unknown'}]},
                            {'policy_violations': 'bad'}, {'mode': 'release'}):
                bad = copy.deepcopy(result)
                bad['evaluation']['build'].update(changes)
                (root / 'result.json').write_text(json.dumps(bad))
                write_manifest(root, kind='analysis')
                self.assertEqual(evaluate_gate(root)['exit_code'], 20, changes)


if __name__ == '__main__':
    unittest.main()
