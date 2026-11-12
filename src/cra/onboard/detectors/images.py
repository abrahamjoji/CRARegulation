"""Recognise archives from their validated layout, not their filename alone."""
import tarfile
from ...collector.container import inspect_image_archive
from ...common.errors import UntrustedInputError


def detect(ctx):
    for path in ctx.paths:
        if not path.name.endswith(('.tar','.tar.gz','.tgz')): continue
        try:
            # Layout checks include archive traversal, links and size limits.
            format = 'oci-archive'
            try: inspect_image_archive(path, format)
            except UntrustedInputError as exc:
                if exc.code != 'image_archive_invalid': raise
                format = 'docker-archive'; inspect_image_archive(path, format)
        except (UntrustedInputError, tarfile.TarError, OSError) as exc:
            ctx.warnings.append(f'Archive not selected: {ctx.rel(path)} ({getattr(exc,"code",type(exc).__name__)})')
            continue
        # Whole image hashes can be large; streamed provenance avoids loading their bytes.
        from ...common.safety import sha256_file
        ctx.inputs[path] = sha256_file(path)
        ctx.images.append({'id':ctx.identifier('image',path),'archive':ctx.rel(path),'format':format,'role':'build-stage'})
        ctx.detected.append(f'Image archive: {ctx.rel(path)}; role defaults to build-stage until deployment is reviewed.')
