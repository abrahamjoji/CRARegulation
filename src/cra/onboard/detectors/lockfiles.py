"""Manifest detection provides source declarations, never proof of shipping."""
LOCKFILES = {'package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','Cargo.lock','go.sum',
             'poetry.lock','Pipfile.lock','uv.lock','requirements.txt','packages.lock.json','Gemfile.lock','composer.lock'}


def detect(ctx):
    for path in ctx.paths:
        if path.name not in LOCKFILES: continue
        ctx.read(path)
        row = {'id':ctx.identifier('source',path.parent),'path':ctx.rel(path.parent),'role':'source'}
        if not any(x['path'] == row['path'] for x in ctx.directories): ctx.directories.append(row)
        ctx.detected.append(f'Source dependency metadata: {ctx.rel(path)} (shipping unknown)')
    # A rootfs is only selected explicitly, to avoid treating a development tree as a deployment.
    for value in ctx.settings.get('rootfs', []):
        path = (ctx.root / value).resolve()
        if not path.is_relative_to(ctx.root) or not path.is_dir():
            from ...common.errors import ConfigError
            raise ConfigError('init_rootfs', f'rootfs must name a directory inside the project: {value}')
        ctx.directories.append({'id':ctx.identifier('rootfs',path),'path':ctx.rel(path),'role':'final'})
        ctx.detected.append(f'User-selected final rootfs: {ctx.rel(path)}')
