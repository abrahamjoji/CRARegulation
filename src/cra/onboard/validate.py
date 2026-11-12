"""Preflight validation before any collection/scanner invocation."""
import tomllib
from ..common.config import load_config
from ..common.errors import ConfigError
from ..common.mappings import load_cpe_mappings
from ..common.safety import read_json
from ..common.schema import validate
from ..collector.records import parse_records


def document(value, kind):
    validate(value, kind+'.schema.json')
    if kind=='component-records': parse_records(value,'preflight')
    if kind=='policy':
        from ..common.policy import _validated
        _validated(value, 'preflight')


def _preflight(path, check_inputs=False):
    config=load_config(path)
    validate(tomllib.loads(config.path.read_text()),'config.schema.json')
    warnings=[]
    if config.analysis.policy: document(tomllib.loads(config.analysis.policy.read_text()),'policy')
    for record in config.records:
        doc=read_json(record);document(doc,'component-records')
        for row in doc['components']:
            if row.get('generated') and not row.get('reviewed_by','').strip(): warnings.append(f'Unreviewed generated component: {row["name"]}')
    load_cpe_mappings(config.tools.cpe_mappings)
    if check_inputs:
        paths=[x for c in config.configurations for x in (c.conan_graph,c.conan_lockfile,c.conan_manifest,c.cmake_build_dir,c.pip_inspect) if x]
        paths += [x.path for x in config.artifacts+config.directories]+[x.archive for x in config.images if x.archive]
        for candidate in paths:
            config.scope.require(candidate,'preflight input')
            if not candidate.exists(): raise ConfigError('preflight_missing',f'Missing input: {candidate}')
        if not paths and not config.images and not config.records: warnings.append('No evidence configured; init does not invent dependencies.')
    return config,warnings


def preflight(path, check_inputs=False):
    try:
        return _preflight(path, check_inputs)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError('preflight_invalid', f'Cannot validate input: {exc}') from exc
