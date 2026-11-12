"""Generate a reviewable configuration plan, validate it, then commit managed files.

No detector runs project code. Reruns never silently replace reviewed values.
"""
import datetime as dt
import hashlib
import json
import os
import tempfile
import tomllib
from pathlib import Path
from importlib.resources import files
from .. import __version__
from ..common.config import parse_config
from ..common.errors import ConfigError
from ..common.mappings import load_cpe_mappings, test_frameworks
from ..common.safety import Limits, read_json, run_tool, tool_environment
from ..common.schema import validate
from .context import Context
from .detectors import DETECTORS
from .detectors.identity import detect as identity
from .policy import generate as policy
from .serialize import toml, merge
from .validate import document

SETTINGS = {'schema_version','product','trusted_authors','policy_version','test_frameworks','sdk_roots','rootfs','cpe_mappings','overrides','exclude_detectors','test_targets'}


def settings_file(path):
    if path is None: return {}
    candidate=Path(path)
    if not candidate.is_file() or candidate.stat().st_size>1024*1024: raise ConfigError('init_settings','Settings must be a regular file of at most 1 MiB')
    with candidate.open('rb') as handle: raw=handle.read(1024*1024+1)
    if len(raw)>1024*1024: raise ConfigError('init_settings','Settings exceed 1 MiB')
    value=tomllib.loads(raw.decode())
    if set(value)-SETTINGS or value.get('schema_version')!='cra.init-settings/1': raise ConfigError('init_settings','Expected cra.init-settings/1 and documented settings keys')
    for key in ('trusted_authors','test_frameworks','sdk_roots','rootfs','exclude_detectors','test_targets'):
        if key in value and (not isinstance(value[key],list) or any(not isinstance(x,str) or not x.strip() for x in value[key])): raise ConfigError('init_settings',f'{key} must list nonempty strings')
    if not isinstance(value.get('product',{}),dict) or set(value.get('product',{}))-{'name','version','supplier'}: raise ConfigError('init_settings','Invalid product settings')
    if not isinstance(value.get('overrides',{}),dict): raise ConfigError('init_settings','overrides must be tables by package name')
    return value


def _safe_destination(root,name):
    path=root/name
    if not path.resolve().is_relative_to(root): raise ConfigError('init_output_unsafe',f'Output escapes project: {path}')
    for node in [path,*path.parents]:
        if node.is_symlink(): raise ConfigError('init_output_unsafe',f'Symlink in output path: {node}')
    if path.exists() and not path.is_file(): raise ConfigError('init_output_unsafe',f'Output is not a regular file: {path}')
    return path


def write_plan(root,plan,force=False,expected=None):
    """Exclusive generator lock, staged writes, rollback on normal write errors.

Not a filesystem-wide transaction across power failure. Existing content is
retained in memory until publication finishes; no unrelated files are removed.
"""
    root=Path(root).resolve()
    for name in plan:
        path=_safe_destination(root,name)
        if path.exists() and not force and name!='.gitignore': raise ConfigError('init_exists',f'{name} exists; use --force to merge, not replace')
    lock=root/'.cra-init.lock'
    try: fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    except FileExistsError: raise ConfigError('init_busy','Another init may be active; inspect .cra-init.lock before removing a stale lock') from None
    os.close(fd)
    expected = expected or {}
    def unchanged(path):
        name=path.relative_to(root).as_posix()
        if name not in expected:return
        actual=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        if actual!=expected[name]:raise ConfigError('init_concurrent_change',f'{name} changed during generation; rerun to merge the new content')
    staged=[];published=[]
    try:
        for name,content in plan.items():
            path=_safe_destination(root,name)
            if path.exists() and not force and name!='.gitignore': raise ConfigError('init_exists',f'{name} appeared during generation')
            unchanged(path)
            old=path.read_bytes() if path.exists() else None
            path.parent.mkdir(parents=True,exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.cra-init-',delete=False) as temp:
                temp.write(content.encode());temp.flush();os.fsync(temp.fileno())
                staged.append((path,Path(temp.name),old))
        for path,temp,old in staged:
            _safe_destination(root,path.relative_to(root))
            unchanged(path)
            if old is None:
                os.link(temp,path,follow_symlinks=False)
                temp.unlink()
            else:
                os.replace(temp,path)
            published.append((path,old))
    except BaseException:
        for path,old in reversed(published):
            if old is None: path.unlink(missing_ok=True)
            else: path.write_bytes(old)
        raise
    finally:
        for _,temp,_ in staged: temp.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)


def cpe_check(cpe,grype):
    with tempfile.TemporaryDirectory(prefix='cra-cpe-check-') as temporary:
        output=Path(temporary)/'result.json'
        env=tool_environment({'HOME':temporary,'GRYPE_DB_AUTO_UPDATE':'false','GRYPE_CHECK_FOR_APP_UPDATE':'false',
                              'GRYPE_DB_CACHE_DIR':os.environ.get('GRYPE_DB_CACHE_DIR',str(Path.home()/'.cache/grype/db'))})
        result=run_tool([grype,'db','search','--pkg',cpe,'--limit','1','-o','json'],stdout_path=output,
                        limits=Limits(timeout_seconds=30,output_bytes=4*1024*1024),env=env,cwd=temporary)
        if result.returncode or result.missing or result.timed_out: return 'unavailable'
        from ..common.errors import UntrustedInputError
        try: value=read_json(output,4*1024*1024)
        except UntrustedInputError:return 'invalid_output'
        if isinstance(value,list): return 'has_advisories' if value else 'no_advisories'
        # Unknown schemas must not be mistaken for either coverage or a clean CPE.
        return 'unrecognised_output'


def generate(args):
    if Path(args.root).is_symlink(): raise ConfigError('init_root_unsafe','Project root must not be a symlink')
    root=Path(args.root).resolve()
    if not root.is_dir(): raise ConfigError('init_root','Project root must already exist')
    settings=settings_file(args.settings)
    if args.sdk_root: settings['sdk_roots']=[*settings.get('sdk_roots',[]),*args.sdk_root]
    ctx=Context(root,settings)
    if args.settings:
        source=Path(args.settings).resolve()
        ctx.inputs[source]=hashlib.sha256(source.read_bytes()).hexdigest()
    product=identity(ctx,{'name':args.name,'version':args.product_version,'supplier':args.supplier})
    excludes=settings.get('exclude_detectors',[])
    known={x.__name__.rsplit('.',1)[-1] for x in DETECTORS}
    if set(excludes)-known: raise ConfigError('init_settings','Unknown detector exclusion')
    for detector in DETECTORS:
        if detector.__name__.rsplit('.',1)[-1] not in excludes: detector.detect(ctx)
    mappings=load_cpe_mappings()
    if settings.get('cpe_mappings'):
        m=Path(settings['cpe_mappings']);m=m if m.is_absolute() else root/m
        mappings=load_cpe_mappings(m);ctx.inputs[m]=hashlib.sha256(m.read_bytes()).hexdigest()
    if settings.get('cpe_mappings'):
        previous_map=_safe_destination(root,'records/cpe-mappings.json')
        if previous_map.exists():
            load_cpe_mappings(previous_map)  # validate before merging a reviewed map
            previous=read_json(previous_map)['mappings']
            mappings.update(previous)
            ctx.inputs[previous_map]=hashlib.sha256(previous_map.read_bytes()).hexdigest()
            ctx.warnings.append('Existing project CPE mappings take precedence over proposed settings mappings.')
    # SDK/OS metadata can be inferred even when no installed SDK was supplied.
    for target in ctx.targets:
        if target['os'].lower() in ('qnx','neutrino') and not any(r['name']=='qnx-neutrino-rtos' for r in ctx.records):
            ctx.generated('qnx-neutrino-rtos',target.get('version'),provenance={'detector':'target-os','source':target['source']})
    combined={}
    for row in ctx.records:
        override=settings.get('overrides',{}).get(row['name'],{})
        if not isinstance(override,dict): raise ConfigError('init_settings','Each override must be a table')
        row.update(override)
        name=row['name'].lower();version=row.get('version')
        if not row.get('cpes') and name in mappings and version:
            row['cpes']=[mappings[name].format(version=version)]
        if not row.get('cpes') and (not row.get('purl') or row['purl'].startswith(('pkg:conan/','pkg:generic/'))):
            ctx.warnings.append(f'{row["name"]}: no CPE mapping; absence of findings is not evidence of safety.')
        # Keep a provenance hash map in each generated claim.
        provenance=row.setdefault('provenance',{})
        provenance['input_hashes']={str(p):h for p,h in sorted(ctx.inputs.items())}
        label=row.get('purl') or (row['name'],row.get('version'))
        if label in combined:
            previous=combined[label]
            for cfg in row.get('configurations',[]):
                if cfg not in previous.setdefault('configurations',[]):previous['configurations'].append(cfg)
        else: combined[label]=row
    records={'schema_version':'cra.component-records/1','components':list(combined.values())}
    authors=args.author or settings.get('trusted_authors',[])
    if not authors: ctx.warnings.append('No trusted VEX authors: generated policy trusts no author. Set --author after deciding who may triage.')
    policy_doc=policy(args.policy,authors,settings.get('policy_version',product['name']+'-policy-1'))
    config={'schema_version':'cra.config/1','product':product,'scope':{'roots':['.']},'output':{'dir':'.cra'},
            'configurations':ctx.configurations,'directories':ctx.directories,'artifacts':ctx.artifacts,'images':ctx.images,
            'components':{'records':['records/components.json']},
            'tools':{'test_frameworks':settings.get('test_frameworks',test_frameworks()), 'test_targets':settings.get('test_targets',[])},
            'analysis':{'policy':'policy.toml','kev':'data/kev.json'}}
    if args.grype!='grype':config['tools']['grype']=args.grype
    if settings.get('cpe_mappings'):
        # Copy the complete reviewed map into a stable project-local file used by analysis.
        config['tools']['cpe_mappings']='records/cpe-mappings.json'
    if not ctx.artifacts:ctx.warnings.append('No artifacts found: build first and rerun for stronger evidence. Plain C/C++ source is not automatically selected.')
    if not (ctx.configurations or ctx.directories or ctx.images or ctx.artifacts or ctx.records):ctx.warnings.append('No usable evidence detected. Records scaffold is empty; identify vendor/RTOS components before collection.')
    docs={'cra.toml':config,'policy.toml':policy_doc,'records/components.json':records}
    if args.with_readiness:
        for filename in ('product.json','risk-assessment.json','register.json','openvex.json'):
            value=read_json(files('cra').joinpath('data/templates',filename))
            if filename=='product.json':value.update(product=product['name'],firmware_version=product['version'],manufacturer=product.get('supplier',''))
            if filename=='openvex.json':value.update(author=authors[0] if authors else '',timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),**{'@id':'urn:cra:generated:openvex'})
            docs['readiness/'+filename]=value
        config['analysis'].update(product_file='readiness/product.json',risk_file='readiness/risk-assessment.json',register_file='readiness/register.json',vex=['readiness/openvex.json'])
        ctx.warnings.append('Readiness templates are incomplete by design; fill and review them. No generated VEX decision is trusted.')
    expected={}
    for name,value in list(docs.items()):
        path=_safe_destination(root,name)
        expected[name]=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        if not path.exists():continue
        if not args.force:raise ConfigError('init_exists',f'{name} already exists; use --force to merge while preserving existing values')
        existing=tomllib.loads(path.read_text()) if name.endswith('.toml') else read_json(path)
        if not isinstance(existing,dict):raise ConfigError('init_existing_invalid',f'{name} must contain an object/table')
        if name=='records/components.json':document(existing,'component-records')
        if name=='cra.toml':
            validate(existing,'config.schema.json')
            for field in existing.get('product',{}):ctx.identity_sources[field]='existing cra.toml (preserved)'
        ctx.inputs[path]=expected[name]
        if name=='records/components.json':
            old_versions={}
            for old in existing.get('components',[]):
                if old.get('version'):old_versions.setdefault(old['name'],set()).add(old['version'])
            for new in value['components']:
                previous=old_versions.get(new['name'])
                if previous and new.get('version') and new['version'] not in previous:
                    raise ConfigError('init_record_conflict',f'{new["name"]}: detected version {new["version"]} disagrees with existing versions {sorted(previous)}; review manually')
        docs[name]=merge(existing,value)
        ctx.warnings.append(f'Merged {name}; existing scalar values and intentional empty lists win. Formatting/comments may change.')
    validate(docs['cra.toml'],'config.schema.json');parse_config(docs['cra.toml'],root/'cra.toml')
    document(docs['policy.toml'],'policy');document(docs['records/components.json'],'component-records')
    if not args.skip_cpe_check:
        for cpe in sorted({cpe for r in docs['records/components.json']['components'] for cpe in r.get('cpes',[])}):
            status=cpe_check(cpe,args.grype)
            ctx.detected.append(f'CPE database check: {cpe}: {status}')
            if status!='has_advisories': ctx.warnings.append(f'CPE {status}: {cpe}. No result does not validate identity or prove safety; review vendor advisories.')
    else: ctx.warnings.append('CPE database checks explicitly skipped; mapping validity/coverage is not established.')
    now=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    header=f'# Generated by cra init {__version__} at {now}\n# Detection is evidence, not deployment attestation. Review generated records.\n'
    for key,source in sorted(ctx.identity_sources.items()):
        header+='# Product.'+key+' from '+json.dumps(source,ensure_ascii=True)+'\n'
    for path,digest in sorted(ctx.inputs.items()):
        header+=('# Directory-listing ' if path.is_dir() else '# Input ')+json.dumps(str(path),ensure_ascii=True)+' sha256:'+digest+'\n'
    plan={name:(header if name=='cra.toml' else '# CRA policy; existing reviewed values preserved on merge.\n' if name.endswith('.toml') else '')+
          (toml(value) if name.endswith('.toml') else json.dumps(value,indent=2,sort_keys=True)+'\n') for name,value in docs.items()}
    if settings.get('cpe_mappings'):
        map_path=_safe_destination(root,'records/cpe-mappings.json')
        expected['records/cpe-mappings.json']=hashlib.sha256(map_path.read_bytes()).hexdigest() if map_path.exists() else None
        if map_path.exists() and not args.force:raise ConfigError('init_exists','records/cpe-mappings.json already exists')
        plan['records/cpe-mappings.json']=json.dumps({'schema_version':'cra.cpe-mappings/1','mappings':mappings},indent=2)+'\n'
    ignore=_safe_destination(root,'.gitignore')
    expected['.gitignore']=hashlib.sha256(ignore.read_bytes()).hexdigest() if ignore.exists() else None
    previous=ignore.read_text() if ignore.exists() else ''
    entries=[x for x in ('.cra/','data/','.cra-init.lock') if x not in previous.splitlines()]
    plan['.gitignore']=previous+('\n' if previous and not previous.endswith('\n') else '')+''.join(x+'\n' for x in entries)
    if not args.dry_run:write_plan(root,plan,args.force,expected)
    import shlex
    output=docs['cra.toml'].get('output',{}).get('dir','.cra')
    gate_result=shlex.quote(str(Path(output)/'analysis'))
    return {'dry_run':args.dry_run,'files':plan,'detected':ctx.detected,'warnings':list(dict.fromkeys(ctx.warnings)),
            'next_commands':['cra validate --config cra.toml','cra data update --config cra.toml',
                             'cra prepare --config cra.toml # before CMake configure, if applicable',
                             'cra collect --config cra.toml','cra analyze --config cra.toml',f'cra gate --result {gate_result} --mode build']}
