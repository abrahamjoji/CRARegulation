"""Dependency-free validator for the keywords used by our bundled input schemas.

Not a general JSON Schema implementation. Unsupported validation keywords fail
closed, and tests cross-check generated documents using jsonschema Draft202012.
"""
import math
import re
from importlib.resources import files
from .errors import ConfigError
from .safety import read_json

ANNOTATIONS = {'$schema', '$id', '$defs', 'title', 'description', 'default', 'examples', '$comment'}
KEYWORDS = {'$ref', 'type', 'required', 'properties', 'additionalProperties', 'items', 'const', 'enum', 'pattern',
            'minLength', 'maxLength', 'minimum', 'maximum', 'minItems', 'maxItems', 'uniqueItems', 'oneOf', 'anyOf', 'allOf', 'not'}


def validate(value, name):
    schema = read_json(files('cra').joinpath('schemas', name))
    def fail(where, reason):
        raise ConfigError('schema_invalid', f'{name} {where}: {reason}')
    def check(item, rule, where='$'):
        if isinstance(rule, bool):
            if not rule: fail(where, 'value is forbidden')
            return
        if set(rule) - ANNOTATIONS - KEYWORDS:
            fail(where, f'unsupported schema keywords: {sorted(set(rule) - ANNOTATIONS - KEYWORDS)}')
        if '$ref' in rule:
            reference = rule['$ref']
            if not reference.startswith('#/'):
                fail(where, 'external schema references are forbidden')
            target = schema
            for part in reference[2:].split('/'):
                target = target[part.replace('~1', '/').replace('~0', '~')]
            check(item, target, where)
        kind = rule.get('type')
        types = {'object': lambda x: isinstance(x, dict), 'array': lambda x: isinstance(x, list),
                 'string': lambda x: isinstance(x, str), 'boolean': lambda x: isinstance(x, bool),
                 'integer': lambda x: isinstance(x, int) and not isinstance(x, bool),
                 'number': lambda x: isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x),
                 'null': lambda x: x is None}
        if kind and not any(types[k](item) for k in (kind if isinstance(kind, list) else [kind])):
            fail(where, f'expected {kind}')
        if 'const' in rule and item != rule['const']: fail(where, 'unexpected constant')
        if 'enum' in rule and item not in rule['enum']: fail(where, 'not an allowed value')
        for key in ('oneOf', 'anyOf', 'allOf', 'not'):
            if key not in rule: continue
            checks = rule[key] if key != 'not' else [rule[key]]
            count = 0
            for sub in checks:
                try: check(item, sub, where)
                except ConfigError: pass
                else: count += 1
            if (key == 'oneOf' and count != 1) or (key == 'anyOf' and not count) or (key == 'allOf' and count != len(checks)) or (key == 'not' and count):
                fail(where, f'{key} constraint failed')
        if isinstance(item, dict):
            if set(rule.get('required', [])) - set(item): fail(where, 'missing required keys')
            for key, child in item.items():
                sub = rule.get('properties', {}).get(key, rule.get('additionalProperties', True))
                check(child, sub, f'{where}.{key}')
        if isinstance(item, list):
            if len(item) < rule.get('minItems', 0) or len(item) > rule.get('maxItems', float('inf')): fail(where, 'array size')
            if rule.get('uniqueItems') and any(x in item[:i] for i, x in enumerate(item)): fail(where, 'duplicate array item')
            for i, child in enumerate(item): check(child, rule.get('items', True), f'{where}[{i}]')
        if isinstance(item, str):
            if len(item) < rule.get('minLength', 0) or len(item) > rule.get('maxLength', float('inf')): fail(where, 'string length')
            if 'pattern' in rule and not re.search(rule['pattern'], item): fail(where, 'pattern mismatch')
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            if item < rule.get('minimum', -float('inf')) or item > rule.get('maximum', float('inf')): fail(where, 'numeric range')
    check(value, schema)
