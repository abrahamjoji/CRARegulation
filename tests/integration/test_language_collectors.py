"""Real local tools, no downloads: pip inspect, C/C++ compilers and Syft directory scanning."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from cra.collector.collect import collect
from cra.common.config import load_config
from cra.engine.reconcile import reconcile


@unittest.skipUnless(os.environ.get('CRA_INTEGRATION') == '1', 'set CRA_INTEGRATION=1 for real tools')
class LanguageCollectors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def config(self, extra):
        path = self.root / 'cra.toml'
        path.write_text('''schema_version = "cra.config/1"
[product]
name = "language-reference"
version = "1"
[scope]
roots = ["."]
[output]
dir = "out"
[tools]
syft = ''' + json.dumps(str(REPO / '.tools/syft')) + '\n' + extra)
        return load_config(path)

    def test_real_python_environment_is_collected_without_conan(self):
        subprocess.run([sys.executable, '-m', 'venv', str(self.root / 'env')], check=True, capture_output=True)
        python = self.root / 'env/bin/python'
        site = Path(subprocess.check_output([str(python), '-c', 'import sysconfig;print(sysconfig.get_path("purelib"))'], text=True).strip())
        for name, requirements in [('demo_lib', ''), ('demo_app', 'Requires-Dist: demo-lib>=1\n')]:
            info = site / f'{name}-1.0.dist-info'
            info.mkdir()
            (info / 'METADATA').write_text(f'Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n{requirements}')
        with (self.root / 'pip.json').open('wb') as output:
            subprocess.run([str(python), '-m', 'pip', 'inspect', '--local'], stdout=output, stderr=subprocess.PIPE, check=True)
        out, _ = collect(self.config('''[[configurations]]
id = "python"
pip_inspect = "pip.json"
pip_inspect_shipped = true
'''))
        inventory = reconcile(out)
        self.assertEqual(inventory['coverage']['status'], 'complete')
        purls = {c['identity']['purl'] for c in inventory['components']}
        self.assertIn('pkg:pypi/demo-lib@1.0', purls)
        self.assertIn('pkg:pypi/demo-app@1.0', purls)
        self.assertTrue(all(c['presence']['shipped'] == 'yes' for c in inventory['components']))

    def test_real_syft_directory_finds_python_requirements(self):
        if not (REPO / '.tools/syft').is_file():
            self.skipTest('pinned Syft binary not installed')
        source = self.root / 'source'
        source.mkdir()
        (source / 'requirements.txt').write_text('requests==2.31.0\nurllib3==1.26.18\n')
        out, _ = collect(self.config('''[[directories]]
id = "source"
path = "source"
role = "source"
'''))
        inventory = reconcile(out)
        self.assertEqual(inventory['coverage']['status'], 'complete', out['sources'])
        self.assertIn('pkg:pypi/requests@2.31.0', {c['identity']['purl'] for c in inventory['components']})
        self.assertTrue(all(c['presence']['shipped'] == 'unknown' for c in inventory['components']))

    def test_real_c_and_cpp_artifacts_need_no_conan(self):
        for compiler, suffix, code in [('cc', 'c', 'int main(void) {return 0;}'), ('c++', 'cpp', 'int main() {return 0;}')]:
            if not shutil.which(compiler):
                self.skipTest(f'{compiler} compiler unavailable')
            source = self.root / f'app.{suffix}'
            source.write_text(code)
            subprocess.run([compiler, str(source), '-o', str(self.root / f'app-{suffix}')], check=True, capture_output=True)
        config = self.config('''[[artifacts]]
id = "c-app"
path = "app-c"
[[artifacts]]
id = "cpp-app"
path = "app-cpp"
''')
        out, _ = collect(config)
        self.assertEqual({a['format'] for a in out['artifacts']}, {'elf'})
        self.assertEqual({a['id'] for a in out['artifacts']}, {'c-app', 'cpp-app'})
        # A successful compiler run alone does not identify system package versions.
        self.assertEqual(reconcile(out)['coverage']['status'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
