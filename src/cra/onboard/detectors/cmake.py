"""Discover CMake caches and actual File API output artifacts, never guess install paths."""
import re
from pathlib import Path
from ...collector import cmake


def detect(ctx):
    for path in ctx.paths:
        if path.name != 'CMakeCache.txt': continue
        cache = dict(re.findall(r'(?m)^([^#/:\n][^:\n]*):[^=\n]*=(.*)$', ctx.read(path)))
        config = ctx.config(path.parent)
        config['cmake_build_dir'] = ctx.rel(path.parent)
        if cache.get('CMAKE_BUILD_TYPE'): config['cmake_config'] = cache['CMAKE_BUILD_TYPE']
        ctx.detected.append(f'CMake tree: {ctx.rel(path.parent)}')
        ctx.warnings.append(f'Run cra prepare before the next configure for {ctx.rel(path.parent)}.')
        system = cache.get('CMAKE_SYSTEM_NAME')
        version = cache.get('CMAKE_SYSTEM_VERSION')
        toolchain = cache.get('CMAKE_TOOLCHAIN_FILE')
        if toolchain:
            candidate = Path(toolchain)
            if not candidate.is_absolute(): candidate = path.parent / candidate
            if candidate.is_file() and candidate.resolve().is_relative_to(ctx.root):
                text = ctx.read(candidate)
                for key in ('CMAKE_SYSTEM_NAME', 'CMAKE_SYSTEM_VERSION'):
                    match = re.search(r'(?im)\bset\s*\(\s*'+key+r'\s+"?([\w.\-]+)"?\s*\)', text)
                    if match:
                        if key.endswith('NAME'): system = system or match[1]
                        else: version = version or match[1]
                # Only literal existing SDK paths; no variable expansion or toolchain evaluation.
                for match in re.finditer(r'(?im)\bset\s*\(\s*(?:QNX_BASE|QNX_TARGET)\s+"?([^"\s)]+)', text):
                    sdk = Path(match[1]); sdk = sdk if sdk.is_absolute() else candidate.parent / sdk
                    if sdk.is_dir(): ctx.sdk_roots.append(sdk.resolve())
        for system_file in sorted(path.parent.glob('CMakeFiles/*/CMakeSystem.cmake')):
            if system_file.is_symlink(): continue
            text = ctx.read(system_file)
            values = dict(re.findall(r'(?im)\bset\s*\(\s*(CMAKE_SYSTEM_NAME|CMAKE_SYSTEM_VERSION)\s+"?([^"\s)]+)', text))
            system = system or values.get('CMAKE_SYSTEM_NAME')
            version = version or values.get('CMAKE_SYSTEM_VERSION')
        if system: ctx.targets.append({'os':system, 'version':version, 'source':str(path)})
        index = cmake.find_index(path.parent)
        if index is None: continue
        ctx.read(index)
        files = cmake.read_reply(index)
        # Hash all consulted reply files, including every target, for provenance.
        for item in index.parent.glob('*.json'): ctx.read(item)
        configurations = (files.get('codemodel') or {}).get('configurations') or []
        for variant in configurations:
            selected = config
            if len(configurations) > 1:
                selected = {**config, 'id':ctx.identifier('cmake', path.parent / (variant.get('name') or 'default')), 'cmake_config':variant.get('name') or ''}
                if config in ctx.configurations: ctx.configurations.remove(config)
                ctx.configurations.append(selected)
            for target in variant.get('targets') or []:
                data = files['targets'].get(target.get('jsonFile'), {})
                if data.get('type') not in ('EXECUTABLE', 'STATIC_LIBRARY', 'SHARED_LIBRARY', 'MODULE_LIBRARY'): continue
                for artifact in data.get('artifacts') or []:
                    candidate = path.parent / artifact['path']
                    if candidate.is_file() and not candidate.is_symlink() and candidate.resolve().is_relative_to(ctx.root):
                        entry = {'id':ctx.identifier('artifact', candidate), 'path':ctx.rel(candidate), 'configuration':selected['id'], 'shipped':False}
                        if entry not in ctx.artifacts: ctx.artifacts.append(entry)
        ctx.warnings.append('CMake artifacts default to shipped=false: build outputs/install rules do not attest deployment. Set shipped=true after review.')
