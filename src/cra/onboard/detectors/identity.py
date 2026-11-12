"""Literal product metadata only; no CMake, Python, Cargo or Node execution."""
import re
import tomllib
from pathlib import Path
from ...common.errors import ConfigError
from ...common.safety import Limits, run_tool, tool_environment


def detect(ctx, explicit):
    found = {}
    cmake = ctx.root / 'CMakeLists.txt'
    if cmake.is_file():
        text = re.sub(r'(?m)#.*$', '', ctx.read(cmake))
        match = re.search(r'(?is)\bproject\s*\(\s*"?([\w.\-]+)"?\s*([^)]*)\)', text)
        if match:
            found['name'] = match[1]
            ctx.identity_sources['name'] = str(cmake)
            version = re.search(r'\bVERSION\s+"?([0-9]+(?:\.[0-9]+){0,3})"?(?:\s|$)', match[2], re.I)
            if version:
                found['version'] = version[1]
                ctx.identity_sources['version'] = str(cmake)
    for filename, table in [('pyproject.toml', 'project'), ('package.json', None), ('Cargo.toml', 'package')]:
        path = ctx.root / filename
        if not path.is_file(): continue
        doc = ctx.json(path) if filename.endswith('.json') else tomllib.loads(ctx.read(path))
        values = doc.get(table, {}) if table else doc
        if not isinstance(values, dict): continue
        for key in ('name', 'version'):
            value = values.get(key)
            if key not in found and isinstance(value, str) and value.strip():
                found[key] = value
                ctx.identity_sources[key] = str(path)
    path = ctx.root / 'go.mod'
    if path.is_file():
        text = ctx.read(path)
        match = re.search(r'(?m)^module\s+(\S+)', text)
        if match and 'name' not in found:
            found['name'] = match[1].strip('"')
            ctx.identity_sources['name'] = str(path)
    for key in ('name', 'version', 'supplier'):
        value = explicit.get(key) or ctx.settings.get('product', {}).get(key)
        if value is not None:
            if not isinstance(value, str) or not value.strip(): raise ConfigError('init_identity', f'{key} must be nonempty')
            found[key] = value
            ctx.identity_sources[key] = 'command-line option' if explicit.get(key) else 'settings file'
    if 'version' not in found:
        # Repository config is never used to select an executable or run a hook.
        import tempfile
        with tempfile.NamedTemporaryFile() as capture:
            result = run_tool(['git', '-c', 'core.fsmonitor=false', '-c', f'safe.directory={ctx.root}', '-C', str(ctx.root),
                               'describe', '--tags', '--always', '--dirty'], stdout_path=capture.name,
                              limits=Limits(timeout_seconds=10), env=tool_environment({'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null', 'HOME':'/nonexistent'}))
            if not result.returncode:
                value = Path(capture.name).read_text().strip()
                if value:
                    found['version'] = value
                    ctx.identity_sources['version'] = 'git describe --tags --always --dirty'
                    head = ctx.root / '.git' / 'HEAD'
                    if head.is_file() and not head.is_symlink(): ctx.read(head)
                    ctx.detected.append(f'Version fallback from git describe: {value}')
                    ctx.warnings.append('git describe is a source label, not necessarily the released product version.')
    missing = [key for key in ('name', 'version') if not found.get(key)]
    if missing: raise ConfigError('init_identity_missing', 'Cannot infer '+', '.join(missing)+'; provide --name and --version. No version is invented.')
    if not found.get('supplier'): ctx.warnings.append('No supplier configured; set --supplier. No team/author identity was inferred.')
    return found
