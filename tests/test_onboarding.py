"""Onboarding must be generic, conservative, repeatable and safe without tools/network."""
import argparse
import contextlib
import io
import json
import os
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

import helpers
from cra.cli import build_parser, main
from cra.common.errors import ConfigError, UntrustedInputError
from cra.common.mappings import load_cpe_mappings, valid_cpe
from cra.common.safety import read_json
from cra.common.schema import validate
from cra.onboard.init import generate
from cra.onboard.validate import preflight


class Init(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{},clear=True);self.env.start();self.addCleanup(self.env.stop)

    def args(self,*values):
        return build_parser().parse_args(['init','--root',str(self.root),'--name','widget','--version','1.2.3','--skip-cpe-check',*values])

    def run_init(self,*values): return generate(self.args(*values))

    def write(self,name,text):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);return path

    def test_dry_run_does_not_write_even_directories(self):
        before=list(self.root.iterdir())
        result=self.run_init('--dry-run','--with-readiness')
        self.assertEqual(before,list(self.root.iterdir()))
        self.assertIn('readiness/product.json',result['files'])
        self.assertIn('cra data update --config cra.toml',result['next_commands'])

    def test_write_validate_and_schema_crosscheck(self):
        self.run_init('--with-readiness','--author','Security reviewer')
        config,warnings=preflight(self.root/'cra.toml')
        self.assertEqual(config.product_name,'widget')
        self.assertEqual((self.root/'.gitignore').read_text(),'/.cra/\n/data/\n/.cra-init.lock\n')
        import jsonschema
        for filename,schema in [('cra.toml','config'),('policy.toml','policy'),('records/components.json','component-records')]:
            value=tomllib.loads((self.root/filename).read_text()) if filename.endswith('.toml') else read_json(self.root/filename)
            jsonschema.Draft202012Validator(read_json(helpers.REPO/'src/cra/schemas'/f'{schema}.schema.json')).validate(value)
        policy=tomllib.loads((self.root/'policy.toml').read_text())
        self.assertEqual(policy['vex']['trusted_authors'],['Security reviewer'])

    def test_no_identity_is_invented(self):
        args=build_parser().parse_args(['init','--root',str(self.root),'--dry-run'])
        with self.assertRaises(ConfigError):generate(args)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_identity_precedence_and_literal_build_inputs(self):
        self.write('CMakeLists.txt','project("native" VERSION "2.0" LANGUAGES C)')
        self.write('pyproject.toml','[project]\nname="python"\nversion="3.0"\n')
        args=build_parser().parse_args(['init','--root',str(self.root),'--dry-run','--skip-cpe-check'])
        data=tomllib.loads(generate(args)['files']['cra.toml'])
        self.assertEqual(data['product'],{'name':'native','version':'2.0'})
        data=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual(data['product']['name'],'widget')
        self.assertNotIn('supplier',data['product'])

    def test_package_cargo_go_identity(self):
        for filename,content,name in [('package.json','{"name":"node","version":"1"}','node'),('Cargo.toml','[package]\nname="rust"\nversion="1"','rust'),('go.mod','module example.org/project\n','example.org/project')]:
            with self.subTest(filename=filename):
                self.write(filename,content)
                args=build_parser().parse_args(['init','--root',str(self.root),'--version','1','--dry-run','--skip-cpe-check'])
                self.assertEqual(tomllib.loads(generate(args)['files']['cra.toml'])['product']['name'],name)
                (self.root/filename).unlink()

    def test_python_environment_capture_and_source_lockfiles(self):
        self.write('.venv/pyvenv.cfg','home=/usr/bin')
        self.write('package-lock.json','{"lockfileVersion":3}')
        result=self.run_init('--dry-run');config=tomllib.loads(result['files']['cra.toml'])
        self.assertEqual(config['configurations'][0]['pip_inspect'],'pip-inspect.json')
        self.assertFalse(config['configurations'][0]['pip_inspect_shipped'])
        self.assertEqual(config['directories'][0]['role'],'source')
        self.assertTrue(any('pip inspect --local' in x for x in result['warnings']))
        self.write('pip-inspect.json','{"version":"1","installed":[]}')
        config=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual(len(config['configurations']),1)

    def test_plain_c_source_is_not_selected(self):
        self.write('main.c','int main(){}')
        result=self.run_init('--dry-run');config=tomllib.loads(result['files']['cra.toml'])
        self.assertEqual(config['directories'],[])
        self.assertEqual(config['artifacts'],[])
        self.assertTrue(any('No usable evidence' in x for x in result['warnings']))

    def test_conan2_and_cmake_capture(self):
        fixture=helpers.FIXTURES/'release-static.graph.json'
        self.write('build/graph.json',fixture.read_text())
        self.write('build/CMakeCache.txt','CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_SYSTEM_NAME:STRING=Linux\n')
        result=self.run_init('--dry-run');config=tomllib.loads(result['files']['cra.toml'])
        self.assertEqual(len(config['configurations']),1)
        cfg=config['configurations'][0]
        self.assertEqual(cfg['conan_graph'],'build/graph.json')
        self.assertEqual(cfg['cmake_build_dir'],'build')
        records=json.loads(result['files']['records/components.json'])['components']
        self.assertTrue(records)
        self.assertTrue(all(row['generated'] and row['reviewed_by']=='' for row in records))
        self.assertTrue(all('shipped' not in row for row in records))
        self.assertIn('sha256:',result['files']['cra.toml'])

    def test_conan1_is_explicit_limited_fallback(self):
        self.write('build/conaninfo.txt','[settings]\nos=Neutrino\nos.version=7.1\n')
        self.write('build/conan.lock','{"graph_lock":{"nodes":{}}}')
        result=self.run_init('--dry-run')
        cfg=tomllib.loads(result['files']['cra.toml'])
        self.assertEqual(len(cfg['directories']),1)
        self.assertTrue(any('Conan 1' in x for x in result['warnings']))
        self.assertTrue(any('QNX target detected' in x for x in result['warnings']))

    def test_no_overwrite_without_force(self):
        self.run_init();before=(self.root/'cra.toml').read_bytes()
        with self.assertRaises(ConfigError):self.run_init()
        self.assertEqual(before,(self.root/'cra.toml').read_bytes())

    def test_merge_keeps_reviews_notes_manual_records_and_policy(self):
        self.run_init()
        record={'name':'vendor-sdk','version':'1','reviewed_by':'Alice','notes':'Reviewed offline','shipped':True}
        self.write('records/components.json',json.dumps({'schema_version':'cra.component-records/1','components':[record]}))
        self.write('policy.toml','schema_version="cra.policy/1"\nversion="reviewed"\n[vex]\ntrusted_authors=[]\n')
        self.write('package-lock.json','{}')
        self.run_init('--force','--author','do not add')
        self.assertEqual(read_json(self.root/'records/components.json')['components'][0],record)
        self.assertEqual(tomllib.loads((self.root/'policy.toml').read_text())['version'],'reviewed')
        self.assertEqual(tomllib.loads((self.root/'policy.toml').read_text())['vex']['trusted_authors'],[])
        self.run_init('--force')
        self.assertEqual((self.root/'.gitignore').read_text().count('.cra/'),1)

    def test_rerun_adds_new_evidence_after_initial_empty_scaffold(self):
        self.run_init()
        self.write('package-lock.json','{}')
        self.run_init('--force')
        self.assertEqual(len(tomllib.loads((self.root/'cra.toml').read_text())['directories']),1)

    def test_symlink_output_is_rejected_even_with_force(self):
        outside=self.root.parent/(self.root.name+'-outside');outside.mkdir();self.addCleanup(shutil.rmtree,outside)
        (self.root/'records').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(ConfigError):self.run_init('--force')
        self.assertEqual(list(outside.iterdir()),[])
        self.assertFalse((self.root/'cra.toml').exists())

    def test_invalid_manual_file_aborts_before_any_writes(self):
        self.run_init();before=(self.root/'cra.toml').read_bytes()
        self.write('records/components.json','{"schema_version":"cra.component-records/1","components":[{"name":"x","shipped":"true"}]}')
        with self.assertRaises(ConfigError):self.run_init('--force')
        self.assertEqual(before,(self.root/'cra.toml').read_bytes())

    def test_explicit_sdk_no_fixed_path_and_mismatch(self):
        sdk=self.root/'sdk';meta=sdk/'.packages/metadata'
        (meta/'com.qnx.qnx710/7.1.0.00472T202006132107S').mkdir(parents=True)
        (meta/'com.qnx.core/1.2.3.02000T202311092015S').mkdir(parents=True)
        self.write('build/conaninfo.txt','os=Neutrino\nos.version=7.1\n')
        result=self.run_init('--sdk-root',str(sdk),'--dry-run')
        records=json.loads(result['files']['records/components.json'])['components']
        self.assertEqual({r['name'] for r in records},{'qnx-software-development-platform','qnx-neutrino-rtos'})
        self.assertTrue(all(r['patch_builds'] for r in records))
        self.assertTrue(all(not r.get('cpes') for r in records))
        self.write('build/conaninfo.txt','os=Neutrino\nos.version=8.0\n')
        with self.assertRaises(ConfigError) as caught:self.run_init('--sdk-root',str(sdk))
        self.assertEqual(caught.exception.code,'init_sdk_mismatch')
        self.assertFalse((self.root/'cra.toml').exists())

    def test_spdx_and_zephyr(self):
        self.write('zephyr/VERSION','VERSION_MAJOR = 3\nVERSION_MINOR = 7\nPATCHLEVEL = 1\n')
        self.write('zephyr/Kconfig.zephyr','# marker')
        self.write('yocto/image.spdx.json',json.dumps({'spdxVersion':'SPDX-2.3','packages':[{'name':'vendor-rtos','versionInfo':'2','SPDXID':'SPDXRef-rtos'}]}))
        result=self.run_init('--dry-run');records=json.loads(result['files']['records/components.json'])['components']
        self.assertEqual({r['name'] for r in records},{'zephyr','vendor-rtos'})

    def test_settings_are_generic_and_mapping_is_used(self):
        self.write('image.spdx.json','{"spdxVersion":"SPDX-2.3","packages":[{"name":"vendor-rtos","versionInfo":"2"}]}')
        self.write('maps.json',json.dumps({'schema_version':'cra.cpe-mappings/1','mappings':{'vendor-rtos':'cpe:2.3:o:vendor:rtos:{version}:*:*:*:*:*:*:*'}}))
        settings=self.write('init.toml','schema_version="cra.init-settings/1"\ntrusted_authors=["Security"]\ncpe_mappings="maps.json"\ntest_frameworks=["my-test-lib"]\n')
        result=self.run_init('--settings',str(settings),'--dry-run')
        record=json.loads(result['files']['records/components.json'])['components'][0]
        self.assertEqual(record['cpes'],['cpe:2.3:o:vendor:rtos:2:*:*:*:*:*:*:*'])
        self.assertIn('records/cpe-mappings.json',result['files'])

    def test_policy_template_is_same_as_engine_default(self):
        from cra.engine.policy import DEFAULT
        from cra.onboard.policy import generate as make
        got=make();got['version']=DEFAULT['version']
        self.assertEqual(got,DEFAULT)
        self.assertTrue(make('strict')['release']['require_readiness'])

    def test_cpe_no_advisories_is_not_clean(self):
        self.write('graph.json',(helpers.FIXTURES/'release-static.graph.json').read_text())
        args=self.args('--dry-run');args.skip_cpe_check=False
        with patch('cra.onboard.init.cpe_check',return_value='no_advisories'):
            result=generate(args)
        self.assertTrue(any('No result does not validate' in x for x in result['warnings']))

    def test_generated_unreviewed_record_cannot_claim_not_shipped(self):
        from cra.collector.records import parse_records
        doc={'schema_version':'cra.component-records/1','components':[{'name':'rtos','version':'1','generated':True,'reviewed_by':'','shipped':False,'source_paths':['vendor']} ]}
        observations,covered=parse_records(doc,'ev')
        self.assertIsNone(observations[0]['shipped_claim'])
        self.assertEqual(covered,{})

    def test_bad_cpe_part_rejected(self):
        self.assertFalse(valid_cpe('cpe:2.3:x:vendor:product:1:*:*:*:*:*:*:*'))
        self.assertTrue(valid_cpe('cpe:2.3:o:vendor:product:1:*:*:*:*:*:*:*'))

    def test_validate_before_collect_flags_missing_capture(self):
        self.write('pyproject.toml','[project]\nname="example"\nversion="1"\n')
        self.run_init()
        with self.assertRaises(ConfigError):preflight(self.root/'cra.toml',True)

    def test_data_import_preserves_previous_catalogue_on_failure(self):
        from cra.data_update import update
        self.run_init()
        good={'dateReleased':'2026-11-12T00:00:00Z','vulnerabilities':[{'cveID':'CVE-2020-0001'}]}
        self.write('valid-kev.json',json.dumps(good))
        update(self.root/'cra.toml',kev_file=self.root/'valid-kev.json',skip_db=True)
        before=(self.root/'data/kev.json').read_bytes()
        self.write('invalid-kev.json','{}')
        with self.assertRaises(ConfigError):update(self.root/'cra.toml',kev_file=self.root/'invalid-kev.json',skip_db=True)
        self.assertEqual(before,(self.root/'data/kev.json').read_bytes())

    def test_grype_db_update_allows_large_database_and_reports_cause(self):
        from cra import data_update
        from cra.common.errors import OperationalError
        from cra.common.safety import ToolResult
        self.run_init()
        seen=[]
        def missing(argv,**kwargs):
            seen.append(kwargs['limits']);return ToolResult(127,'cannot start grype: No such file or directory',False,missing=True)
        with patch.object(data_update,'run_tool',side_effect=missing),self.assertRaises(OperationalError) as caught:
            data_update.update(self.root/'cra.toml')
        self.assertIn('cannot start grype',str(caught.exception))
        self.assertIn('tools.grype',str(caught.exception))
        # The Grype v6 database exceeds the 2 GiB default scanner output limit.
        self.assertGreater(seen[0].output_bytes,4*1024**3)
        with patch.object(data_update,'run_tool',return_value=ToolResult(1,'[0010] ERROR unable to download db: disk full\n',False)),self.assertRaises(OperationalError) as caught:
            data_update.update(self.root/'cra.toml')
        self.assertIn('disk full',str(caught.exception))

    def test_cli_policy_and_validate(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['policy','init','--out',str(self.root/'policy.toml'),'--author','Team']),0)
        self.assertEqual(tomllib.loads((self.root/'policy.toml').read_text())['vex']['trusted_authors'],['Team'])

    def test_unreviewed_generated_record_makes_inventory_incomplete(self):
        from cra.collector.collect import collect
        from cra.engine.reconcile import reconcile
        self.run_init()
        self.write('records/components.json',json.dumps({'schema_version':'cra.component-records/1','components':[{'name':'vendor-rtos','version':'1','generated':True,'reviewed_by':''}]}))
        config,_=preflight(self.root/'cra.toml')
        collection,_=collect(config)
        self.assertIn('generated_record_unreviewed',{r['code'] for r in reconcile(collection)['coverage']['incomplete_reasons']})

    def test_cmake_test_only_scope_does_not_hide_shared_runtime_library(self):
        from cra.collector.cmake import analyze_reply
        def target(name,kind,deps=(),links=()):
            return {'name':name,'type':kind,'dependencies':[{'id':x} for x in deps],
                    'artifacts':[{'path':name}],
                    'link':{'commandFragments':[{'role':'libraries','fragment':' '.join(links)}]}}
        data={'app':target('app','EXECUTABLE',['shared']),
              'tests':target('unit_tests','EXECUTABLE',['shared','testlib'],['/packages/gtest/lib/libgtest.a']),
              'shared':target('shared','STATIC_LIBRARY',[],['/packages/zlib/lib/libz.a']),
              'testlib':target('testlib','STATIC_LIBRARY',[],['/packages/fmt/lib/libfmt.a'])}
        files={'index':{},'codemodel':{'configurations':[{'name':'Release','targets':[{'id':key,'jsonFile':key} for key in data]}]},'targets':data}
        folders={f'/packages/{name}':{'name':name,'version':'1','purl':f'pkg:conan/{name}@1','ecosystem':'conan'} for name in ('gtest','zlib','fmt')}
        parsed=analyze_reply(files,'release','Release',folders,'ev',self.root)
        scopes={x['name']:x['scope'] for x in parsed['targets']}
        self.assertEqual(scopes,{'app':'runtime','unit_tests':'test','shared':'runtime','testlib':'test'})
        runtime=[x for x in parsed['observations'] if x['attributes']['target']=='app']
        self.assertTrue(all(x['scope']=='runtime' for x in runtime))
        # An empty framework list disables the heuristic.
        parsed=analyze_reply(files,'release','Release',folders,'ev',self.root,test_frameworks=[])
        self.assertTrue(all(x['scope']=='runtime' for x in parsed['targets']))

    def test_cmake_existing_file_api_artifact_is_detected(self):
        from cra.onboard.context import Context
        from cra.onboard.detectors.cmake import detect
        self.write('build/CMakeCache.txt','CMAKE_BUILD_TYPE:STRING=Release')
        binary=self.write('build/app','binary')
        index=self.write('build/.cmake/api/v1/reply/index-test.json','{}')
        files={'codemodel':{'configurations':[{'name':'Release','targets':[{'jsonFile':'app.json'}]}]},
               'targets':{'app.json':{'type':'EXECUTABLE','artifacts':[{'path':'app'}]}}}
        ctx=Context(self.root,{})
        with patch('cra.onboard.detectors.cmake.cmake.read_reply',return_value=files):detect(ctx)
        self.assertEqual(ctx.artifacts[0]['path'],'build/app')
        self.assertFalse(ctx.artifacts[0]['shipped'])

    def test_valid_oci_archive_detected_without_docker(self):
        import tarfile
        path=self.root/'image.tar'
        with tarfile.open(path,'w') as archive:
            for name,body in [('oci-layout',b'{"imageLayoutVersion":"1.0.0"}'),('index.json',b'{"manifests":[{"digest":"sha256:abc"}]}')]:
                row=tarfile.TarInfo(name);row.size=len(body);archive.addfile(row,io.BytesIO(body))
        config=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual(config['images'][0]['format'],'oci-archive')
        self.assertEqual(config['images'][0]['role'],'build-stage')

    def test_changed_review_file_aborts_publication(self):
        from cra.onboard.init import write_plan
        import hashlib
        path=self.write('policy.toml','old')
        expected={'policy.toml':hashlib.sha256(path.read_bytes()).hexdigest()}
        path.write_text('new human review')
        with self.assertRaises(ConfigError) as caught:write_plan(self.root,{'policy.toml':'generated'},True,expected)
        self.assertEqual(caught.exception.code,'init_concurrent_change')
        self.assertEqual(path.read_text(),'new human review')
        self.assertFalse((self.root/'.cra-init.lock').exists())

    def test_normal_publish_failure_rolls_back_prior_files(self):
        from cra.onboard.init import write_plan
        self.write('first','reviewed-first');self.write('second','reviewed-second')
        original=os.replace
        def replace(source,target):
            if Path(target).name=='second':raise OSError('simulated disk error')
            return original(source,target)
        with patch('cra.onboard.init.os.replace',side_effect=replace):
            with self.assertRaises(OSError):write_plan(self.root,{'first':'new-first','second':'new-second'},True)
        self.assertEqual((self.root/'first').read_text(),'reviewed-first')
        self.assertEqual((self.root/'second').read_text(),'reviewed-second')

    def test_collector_only_init_and_validate(self):
        import subprocess,sys
        package=self.root/'distribution/cra'
        shutil.copytree(helpers.REPO/'src/cra',package,ignore=shutil.ignore_patterns('engine','hosted','__pycache__'))
        project=self.root/'customer';project.mkdir()
        env={'PYTHONPATH':str(package.parent),'PATH':f'{Path(sys.executable).parent}:/usr/bin:/bin'}
        command=[sys.executable,'-m','cra.cli_main']
        result=subprocess.run(command+['init','--root',str(project),'--name','sample','--version','1','--skip-cpe-check'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        result=subprocess.run(command+['validate','--config',str(project/'cra.toml')],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_cpe_check_uses_local_database_and_bounds(self):
        from cra.onboard.init import cpe_check
        from types import SimpleNamespace
        def run(argv,**kwargs):
            self.assertEqual(argv[1:4],['db','search','--pkg'])
            self.assertEqual(kwargs['env']['GRYPE_DB_AUTO_UPDATE'],'false')
            Path(kwargs['stdout_path']).write_text('[]')
            return SimpleNamespace(returncode=0,missing=False,timed_out=False)
        with patch('cra.onboard.init.run_tool',side_effect=run):
            self.assertEqual(cpe_check('cpe:2.3:o:vendor:rtos:1:*:*:*:*:*:*:*','grype'),'no_advisories')

    def test_rerun_cpe_map_and_new_records_use_same_reviewed_mapping(self):
        self.write('maps.json',json.dumps({'schema_version':'cra.cpe-mappings/1','mappings':{'vendor-rtos':'cpe:2.3:o:oldvendor:rtos:{version}:*:*:*:*:*:*:*'}}))
        settings=self.write('init.toml','schema_version="cra.init-settings/1"\ncpe_mappings="maps.json"\n')
        self.run_init('--settings',str(settings))
        self.write('maps.json',json.dumps({'schema_version':'cra.cpe-mappings/1','mappings':{'vendor-rtos':'cpe:2.3:o:newvendor:rtos:{version}:*:*:*:*:*:*:*'}}))
        self.write('image.spdx.json','{"spdxVersion":"SPDX-2.3","packages":[{"name":"vendor-rtos","versionInfo":"2"}]}')
        self.run_init('--force','--settings',str(settings))
        record=read_json(self.root/'records/components.json')['components'][0]
        template=read_json(self.root/'records/cpe-mappings.json')['mappings']['vendor-rtos']
        self.assertEqual(record['cpes'],[template.format(version='2')])
        self.assertIn(':oldvendor:',record['cpes'][0])

    def test_capture_detection_is_not_tied_to_filename(self):
        self.write('release-dependencies.json',(helpers.FIXTURES/'release-static.graph.json').read_text())
        self.write('environment-snapshot.json','{"version":"1","installed":[]}')
        config=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual(len(config['configurations']),2)
        self.assertTrue(any(c.get('conan_graph')=='release-dependencies.json' for c in config['configurations']))
        self.assertTrue(any(c.get('pip_inspect')=='environment-snapshot.json' for c in config['configurations']))

    def test_rerun_accepts_existing_multiple_configuration_versions(self):
        for index,version in enumerate(('1','2')):
            self.write(f'config{index}.spdx.json',json.dumps({'spdxVersion':'SPDX-2.3','packages':[{'name':'variant-sdk','versionInfo':version}]}))
        self.run_init()
        self.run_init('--force')
        self.assertEqual({r['version'] for r in read_json(self.root/'records/components.json')['components']},{'1','2'})
        # A genuinely new version must still prompt manual reconciliation.
        self.write('config0.spdx.json','{"spdxVersion":"SPDX-2.3","packages":[{"name":"variant-sdk","versionInfo":"3"}]}')
        with self.assertRaises(ConfigError):self.run_init('--force')

    def _graph_with_folders(self,name,build_folder,recipe_folder=None):
        doc=json.loads((helpers.FIXTURES/'release-static.graph.json').read_text())
        node=doc['graph']['nodes']['0']
        node['build_folder']=str(build_folder);node['generators_folder']=str(build_folder/'generators')
        if recipe_folder: node['recipe_folder']=str(recipe_folder)
        self.write(name,json.dumps(doc))

    def test_conan_graph_pairs_with_cmake_tree_in_another_directory(self):
        # The usual layout: graph captured to out/, CMake tree under the Conan output folder.
        tree=self.root/'app/build-rel/build/Release'
        self.write('app/conanfile.py','# recipe, never executed by init\n')
        self._graph_with_folders('out/rel.graph.json',tree,self.root/'app')
        self.write('app/build-rel/build/Release/CMakeCache.txt',
                   f'CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_CACHEFILE_DIR:INTERNAL={tree}\nCMAKE_TOOLCHAIN_FILE:FILEPATH={tree}/generators/conan_toolchain.cmake\n')
        config=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual(len(config['configurations']),1)
        cfg=config['configurations'][0]
        self.assertEqual((cfg['conan_graph'],cfg['cmake_build_dir'],cfg['conan_manifest']),
                         ('out/rel.graph.json','app/build-rel/build/Release','app/conanfile.py'))

    def test_unrelated_cmake_tree_is_not_paired_with_conan_graph(self):
        self._graph_with_folders('out/rel.graph.json',self.root/'elsewhere')
        self.write('other/CMakeCache.txt',f'CMAKE_CACHEFILE_DIR:INTERNAL={self.root}/other\n')
        config=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual(len(config['configurations']),2)
        self.assertFalse(any('conan_graph' in c and 'cmake_build_dir' in c for c in config['configurations']))

    def test_static_archives_are_not_selected_as_artifacts(self):
        from cra.onboard.context import Context
        from cra.onboard.detectors.cmake import detect
        self.write('build/CMakeCache.txt','CMAKE_BUILD_TYPE:STRING=Release')
        self.write('build/app','binary');self.write('build/libcore.a','archive')
        self.write('build/.cmake/api/v1/reply/index-test.json','{}')
        files={'codemodel':{'configurations':[{'name':'Release','targets':[{'jsonFile':'app.json'},{'jsonFile':'core.json'}]}]},
               'targets':{'app.json':{'type':'EXECUTABLE','artifacts':[{'path':'app'}]},
                          'core.json':{'type':'STATIC_LIBRARY','artifacts':[{'path':'libcore.a'}]}}}
        ctx=Context(self.root,{})
        with patch('cra.onboard.detectors.cmake.cmake.read_reply',return_value=files):detect(ctx)
        self.assertEqual([a['path'] for a in ctx.artifacts],['build/app'])

    def test_cpe_check_limit_reached_means_advisories_exist(self):
        # Real Grype 0.121.2 exits 1 with this message when a CPE has more records than --limit.
        from cra.onboard.init import cpe_check
        from types import SimpleNamespace
        def run(argv,**kwargs):
            Path(kwargs['stdout_path']).write_text('[]')
            return SimpleNamespace(returncode=1,missing=False,timed_out=False,stderr='ERROR unable to fetch CPE records: query limit reached')
        with patch('cra.onboard.init.run_tool',side_effect=run):
            self.assertEqual(cpe_check('cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*','grype'),'has_advisories')
        def broken(argv,**kwargs):
            return SimpleNamespace(returncode=1,missing=False,timed_out=False,stderr='database not found')
        with patch('cra.onboard.init.run_tool',side_effect=broken):
            self.assertEqual(cpe_check('cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*','grype'),'unavailable')

    def test_provenance_is_project_relative_and_per_record(self):
        self.write('build/graph.json',(helpers.FIXTURES/'release-static.graph.json').read_text())
        self.write('package-lock.json','{}')
        result=self.run_init('--dry-run')
        self.assertNotIn(str(self.root),result['files']['cra.toml'])
        self.assertNotIn(str(self.root),result['files']['records/components.json'])
        for row in json.loads(result['files']['records/components.json'])['components']:
            self.assertEqual(list(row['provenance']['input_hashes']),['build/graph.json'])

    def test_nested_data_folder_is_scanned_but_root_data_is_not(self):
        self.write('data/package-lock.json','{}')
        self.write('service/data/package-lock.json','{}')
        config=tomllib.loads(self.run_init('--dry-run')['files']['cra.toml'])
        self.assertEqual([d['path'] for d in config['directories']],['service/data'])


if __name__=='__main__':unittest.main()
