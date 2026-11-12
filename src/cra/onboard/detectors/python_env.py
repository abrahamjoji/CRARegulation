"""Use captured pip inspect data. Never execute an interpreter found in a project."""


def detect(ctx):
    captures = []
    for path in ctx.paths:
        if path.suffix == '.json' and ('pip' in path.name.lower() or path.name == 'inspect.json' or ctx.has_json_key(path, 'installed')):
            doc = ctx.json(path)
            if isinstance(doc, dict) and doc.get('version') == '1' and isinstance(doc.get('installed'), list):
                entry = {'id':ctx.identifier('python', path), 'pip_inspect':ctx.rel(path), 'pip_inspect_shipped':False, 'pip_inspect_scope':'runtime'}
                ctx.configurations.append(entry); captures.append(path)
                ctx.detected.append(f'Python captured environment: {ctx.rel(path)}')
    environments = [p for p in ctx.paths if p.name == 'pyvenv.cfg']
    # Conventional environments are excluded from recursive discovery but their marker is safe to inspect.
    for name in ('.venv', 'venv'):
        marker = ctx.root / name / 'pyvenv.cfg'
        if marker.is_file() and not marker.is_symlink(): environments.append(marker)
    if not captures and (environments or (ctx.root/'pyproject.toml').is_file()):
        for marker in environments: ctx.read(marker)
        ctx.configurations.append({'id':'python-environment','pip_inspect':'pip-inspect.json','pip_inspect_shipped':False})
        ctx.warnings.append('Capture the intended environment first: python -m pip inspect --local > pip-inspect.json. Set pip_inspect_shipped=true only after confirming deployment.')
