"""Small deterministic TOML writer for our JSON-compatible settings, not executable text."""
import json
import re
from ..common.errors import ConfigError


def toml(document):
    lines=[]
    def key(value):
        return value if re.fullmatch(r'[A-Za-z0-9_-]+',value) else json.dumps(value)
    def scalar(value):
        if isinstance(value,str): return json.dumps(value,ensure_ascii=False)
        if isinstance(value,bool): return 'true' if value else 'false'
        if isinstance(value,(int,float)): return str(value)
        if isinstance(value,list) and all(not isinstance(x,dict) for x in value): return '['+', '.join(scalar(x) for x in value)+']'
        raise ConfigError('init_serialize','Unsupported TOML value')
    def emit(table,path=(),header=None):
        if header: lines.extend(['',header])
        for name,value in table.items():
            if isinstance(value,dict) or (isinstance(value,list) and value and isinstance(value[0],dict)): continue
            lines.append(f'{key(name)} = {scalar(value)}')
        for name,value in table.items():
            nested=path+(name,); label='.'.join(key(x) for x in nested)
            if isinstance(value,dict): emit(value,nested,f'[{label}]')
            elif isinstance(value,list) and value and isinstance(value[0],dict):
                for row in value: emit(row,nested,f'[[{label}]]')
    emit(document)
    return '\n'.join(lines).strip()+'\n'


def merge(existing, proposed, path=()):
    """Existing reviewed values win. Arrays of identified objects grow, never shrink."""
    if isinstance(existing,dict) and isinstance(proposed,dict):
        result=dict(existing)
        for key,value in proposed.items(): result[key]=merge(existing[key],value,path+(key,)) if key in existing else value
        return result
    if isinstance(existing,list) and isinstance(proposed,list):
        if not existing:
            return list(proposed) if path and path[-1] in ('configurations','directories','artifacts','images','components') else []
        if all(isinstance(x,dict) for x in existing+proposed):
            def ident(row): return row.get('id') or row.get('purl') or (row.get('name'),row.get('version'))
            result=list(existing);index={str(ident(x)):i for i,x in enumerate(result)}
            for row in proposed:
                label=str(ident(row))
                if label in index: result[index[label]]=merge(result[index[label]],row,path)
                else: index[label]=len(result); result.append(row)
            return result
        return list(existing)
    return existing
