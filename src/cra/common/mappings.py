"""Reviewed identity hints are data, not scanner code. No mapping proves safety."""
import re
from importlib.resources import files
from .errors import ConfigError
from .safety import read_json


def valid_cpe(value, *, template=False):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    parts = re.split(r'(?<!\\):', value)
    if len(parts) != 13 or parts[:2] != ['cpe', '2.3'] or parts[2] not in ('a', 'o', 'h'):
        return False
    if any(not p or any(ord(c) <= 32 for c in p) for p in parts[3:]):
        return False
    return (value.count('{version}') == 1 and not re.search(r'[{}]', value.replace('{version}', ''))) if template else not re.search(r'[{}]', value)


def load_cpe_mappings(path=None):
    bundled = read_json(files('cra').joinpath('data/cpe-mappings.json'))
    result = dict(bundled['mappings'])
    if path:
        document = read_json(path, 1024 * 1024)
        if not isinstance(document, dict) or document.get('schema_version') != 'cra.cpe-mappings/1' or not isinstance(document.get('mappings'), dict):
            raise ConfigError('cpe_mappings_invalid', 'Expected cra.cpe-mappings/1 and a mappings object')
        result.update(document['mappings'])
    for name, value in result.items():
        if not isinstance(name, str) or not name or not valid_cpe(value, template=True):
            raise ConfigError('cpe_mappings_invalid', f'Invalid name or CPE template for {name!r}')
    return result


def test_frameworks():
    return read_json(files('cra').joinpath('data/test-frameworks.json'))['packages']
