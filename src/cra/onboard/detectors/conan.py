"""Actual Conan 2 graph capture, plus explicit limited Conan 1 fallback."""
from pathlib import Path
from ...collector.conan import collect_graph


def detect(ctx):
    for path in ctx.paths:
        if path.suffix == '.json' and ('graph' in path.name.lower() or path.name in ('conan.json', 'conan-install.json') or ctx.has_json_key(path, 'graph')):
            doc = ctx.json(path)
            if not isinstance(doc, dict) or 'graph' not in doc: continue
            parsed = collect_graph(doc, 'discovery', 'discovery')
            config = ctx.config(path.parent)
            if config.get('conan_graph') and config['conan_graph'] != ctx.rel(path):
                # Several captures in one directory are distinct configurations.
                config = {'id':ctx.identifier('conan', path)}
                ctx.configurations.append(config)
            config['conan_graph'] = ctx.rel(path)
            ctx.detected.append(f'Conan 2 graph: {ctx.rel(path)}')
            root = (doc['graph'].get('nodes') or {}).get('0', {})
            # Folders Conan recorded for this install; the CMake detector pairs a build tree only
            # when its own cache names the same folders. String comparison, no filesystem lookup.
            folders = {str(root[key]).rstrip('/') for key in ('build_folder', 'generators_folder') if isinstance(root.get(key), str) and root[key]}
            if folders: ctx.conan_folders[config['id']] = folders
            recipe = root.get('recipe_folder')
            if isinstance(recipe, str) and recipe and not config.get('conan_manifest'):
                for name in ('conanfile.py', 'conanfile.txt'):
                    candidate = Path(recipe) / name
                    if candidate.is_file() and not candidate.is_symlink() and candidate.resolve().is_relative_to(ctx.root):
                        ctx.read(candidate)
                        config['conan_manifest'] = ctx.rel(candidate)
                        break
            settings = root.get('settings') or {}
            if settings.get('os'): ctx.targets.append({'os':settings['os'], 'version':settings.get('os.version'), 'source':str(path)})
            for observation in parsed['observations']:
                if observation['state'] != 'resolved': continue
                if observation['scope'] not in ('runtime', 'test', 'build_tool'): continue
                # A record preserves feed identity and classification, not a shipping claim.
                identity = observation['identity']
                ctx.generated(identity['name'], identity['version'], purl=identity['purl'], scope=observation['scope'],
                              configurations=[config['id']], provenance={'detector':'conan2','source':ctx.rel(path)})
        if path.name == 'conaninfo.txt':
            text = ctx.read(path)
            import re
            settings = dict(re.findall(r'(?m)^\s*(os(?:\.version)?)\s*=\s*([^\r\n]+)', text))
            if settings.get('os'): ctx.targets.append({'os':settings['os'], 'version':settings.get('os.version'), 'source':str(path)})
        if path.name in ('conan.lock', 'conaninfo.txt'):
            if path.name == 'conan.lock':
                doc = ctx.json(path)
                # Conan 2 lockfiles do not replace a captured graph either.
                if isinstance(doc, dict) and 'graph_lock' not in doc and 'requires' in doc:
                    ctx.warnings.append(f'{ctx.rel(path)} is a lockfile, not a captured resolved graph.')
            ctx.read(path)
            entry = {'id':ctx.identifier('conan-files', path.parent), 'path':ctx.rel(path.parent), 'role':'source'}
            if entry not in ctx.directories: ctx.directories.append(entry)
            ctx.warnings.append(f'{ctx.rel(path)}: directory fallback only. Conan 1/lockfile metadata may not identify packages; review coverage and add records.')
