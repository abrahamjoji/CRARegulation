"""Policy templates with explicit customer identity, never guessed VEX authors."""
import copy
from importlib.resources import files
from ..common.safety import read_json


def generate(name='default', authors=(), version='policy-1'):
    result=copy.deepcopy(read_json(files('cra').joinpath('data/policy-default.json')))
    result['version']=version
    result['vex']['trusted_authors']=list(authors)
    if name=='strict':
        result['build'].update(block_severities=['critical','high','medium'], minimum_confidence='low', block_conflicts=True)
        result['release'].update(block_severities=['critical','high','medium','low'], require_readiness=True)
    return result
