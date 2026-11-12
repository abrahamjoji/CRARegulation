"""SDK plugin registry: QNX installed metadata, Zephyr VERSION, SPDX 2 JSON.

No path guessing, SDK execution, NVD lookup or invented patch/build numbers.
"""
import os
import re
from pathlib import Path
from ...common.errors import ConfigError
from ...common.mappings import valid_cpe


def _version(value):
    return tuple(int(x) for x in re.findall(r'\d+', value or '')[:3])


def qnx(ctx):
    roots = list(ctx.sdk_roots)
    for value in ctx.settings.get('sdk_roots', []): roots.append((ctx.root / value).resolve())
    if os.environ.get('QNX_BASE'): roots.append(Path(os.environ['QNX_BASE']).resolve())
    roots = sorted(set(roots))
    ctx.sdk_roots = roots
    for root in tuple(roots):
        metadata = root/'.packages/metadata'
        if not metadata.is_dir() and (root.parent/'.packages/metadata').is_dir(): metadata = root.parent/'.packages/metadata'
        if not metadata.is_dir():
            ctx.warnings.append(f'SDK root has no recognised QNX metadata: {root}');continue
        if metadata.is_symlink(): raise ConfigError('init_sdk_unsafe', f'SDK metadata is a symlink: {metadata}')
        metadata_root = metadata.resolve().parent.parent
        if metadata_root not in ctx.sdk_roots: ctx.sdk_roots.append(metadata_root)
        packages = sorted(metadata.iterdir())
        if len(packages) > 5000: raise ConfigError('init_sdk_limit','Too many SDK packages')
        baselines = []
        builds = []
        for package in packages:
            if package.is_symlink() or not package.is_dir(): continue
            versions = sorted(x.name for x in package.iterdir() if x.is_dir() and not x.is_symlink())
            if len(versions) != 1:
                ctx.warnings.append(f'{package}: expected one installed version, found {len(versions)}; not choosing the newest lexically.')
                continue
            builds.append({'package':package.name,'build':versions[0]})
            # Provenance of directory-derived facts is stored explicitly in records.
            if re.fullmatch(r'com\.qnx\.qnx\d+',package.name): baselines.append((package.name,versions[0]))
        if len(baselines) != 1:
            raise ConfigError('init_sdk_ambiguous', f'{metadata}: expected one unambiguous QNX baseline')
        name, full = baselines[0]
        match = re.match(r'(\d+\.\d+\.\d+)(?:\.|$)',full)
        if not match: raise ConfigError('init_sdk_version', f'Unrecognised QNX version: {full}')
        version = match[1]
        targets = [x for x in ctx.targets if x['os'].lower() in ('qnx','neutrino')]
        for target in targets:
            expected = _version(target.get('version'))
            if expected and _version(version)[:len(expected)] != expected:
                raise ConfigError('init_sdk_mismatch', f'SDK {version} disagrees with target {target["version"]} in {target["source"]}')
        import hashlib, json
        ctx.inputs[metadata] = hashlib.sha256(json.dumps(builds,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        provenance = {'detector':'qnx','metadata_directory':str(metadata),'installed_packages':builds}
        ctx.generated('qnx-software-development-platform',version,scope='build_tool',patch_builds=[full],provenance=provenance)
        if targets:
            ctx.generated('qnx-neutrino-rtos',version,patch_builds=[x['build'] for x in builds],provenance=provenance)
        ctx.detected.append(f'QNX SDK {version} with {len(builds)} installed package builds; deployment unverified')
        ctx.warnings.append('QNX SDK installation does not prove target patch level or shipping. No QNX CPE is guessed; supply a reviewed mapping.')
    if any(x['os'].lower() in ('qnx','neutrino') for x in ctx.targets) and not roots:
        ctx.warnings.append('QNX target detected without installed SDK metadata. Use --sdk-root or QNX_BASE; no fixed install path is assumed.')


def zephyr(ctx):
    for path in ctx.paths:
        if path.name != 'VERSION': continue
        text = ctx.read(path)
        fields = dict(re.findall(r'(?m)^\s*(VERSION_MAJOR|VERSION_MINOR|PATCHLEVEL|EXTRAVERSION)\s*=\s*(\S*)',text))
        if not all(k in fields for k in ('VERSION_MAJOR','VERSION_MINOR','PATCHLEVEL')): continue
        # Require a Zephyr marker, rather than identifying arbitrary VERSION files as Zephyr.
        if not (path.parent/'Kconfig.zephyr').is_file() and not (path.parent/'include/zephyr').is_dir(): continue
        version = '.'.join(fields[k] for k in ('VERSION_MAJOR','VERSION_MINOR','PATCHLEVEL'))
        if fields.get('EXTRAVERSION'): version += '-'+fields['EXTRAVERSION']
        ctx.generated('zephyr',version,provenance={'detector':'zephyr-version','source':ctx.rel(path)})
        ctx.detected.append(f'Zephyr {version}: {ctx.rel(path)} (deployment unverified)')


def spdx(ctx):
    for path in ctx.paths:
        if not path.name.endswith(('.spdx.json','.spdx')): continue
        if path.suffix != '.json':
            ctx.warnings.append(f'{ctx.rel(path)}: SPDX tag-value input is not supported; export SPDX 2 JSON.');continue
        doc = ctx.json(path)
        if not isinstance(doc,dict) or not str(doc.get('spdxVersion','')).startswith('SPDX-2.'):
            ctx.warnings.append(f'{ctx.rel(path)}: only SPDX 2 JSON is supported');continue
        for package in doc.get('packages',[]):
            if not isinstance(package,dict) or not isinstance(package.get('name'),str): raise ConfigError('init_spdx','SPDX package needs a name')
            extras = {'provenance':{'detector':'spdx','source':ctx.rel(path),'SPDXID':package.get('SPDXID','')}}
            cpes=[]
            for ref in package.get('externalRefs',[]):
                if ref.get('referenceType') == 'purl': extras['purl']=ref['referenceLocator']
                if ref.get('referenceType') in ('cpe23Type','cpe23') and valid_cpe(ref.get('referenceLocator')): cpes.append(ref['referenceLocator'])
            if cpes: extras['cpes']=cpes
            version=package.get('versionInfo')
            ctx.generated(package['name'],version if version not in ('NOASSERTION','NONE','') else None,**extras)
        ctx.detected.append(f'SPDX packages: {ctx.rel(path)}; shipping requires review')


SDK_DETECTORS = (qnx, zephyr, spdx)


def detect(ctx):
    for plugin in SDK_DETECTORS: plugin(ctx)
