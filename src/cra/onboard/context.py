"""Bounded, deterministic detector input with explicit external SDK roots."""
import hashlib
import os
import re
from pathlib import Path
from ..common.errors import ConfigError
from ..common.safety import parse_json_bytes

SKIP = {'.git', '.cra', '.tools', '.venv', 'venv', 'node_modules', 'data', '__pycache__', '.tox', '.mypy_cache'}
MAX_FILES = 20000
MAX_INPUT_BYTES = 32 * 1024 * 1024


class Context:
    def __init__(self, root, settings):
        self.root = Path(root).resolve()
        self.settings = settings
        self.inputs = {}
        self.warnings = []
        self.detected = []
        self.configurations = []
        self.directories = []
        self.artifacts = []
        self.images = []
        self.records = []
        self.targets = []
        self.identity_sources = {}
        self.sdk_roots = []
        self.total = 0
        self.paths = self.walk(self.root)

    def walk(self, root, depth=8):
        result = []
        def error(exc): raise ConfigError('init_discovery', str(exc))
        for current, dirs, names in os.walk(root, followlinks=False, onerror=error):
            current = Path(current)
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (current/d).is_symlink() and len((current/d).relative_to(root).parts) <= depth)
            for name in sorted(names):
                path = current / name
                if path.is_symlink(): continue
                if len(result) >= MAX_FILES:
                    raise ConfigError('init_discovery_limit', f'More than {MAX_FILES} files under {root}; use a narrower project root')
                result.append(path)
        return sorted(result)

    def read(self, path):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or not any(path.resolve().is_relative_to(p) for p in [self.root, *self.sdk_roots]):
            raise ConfigError('init_input_unsafe', f'Detector input is not a contained regular file: {path}')
        # Reject intermediate symlinks as well.
        if any(parent.is_symlink() for parent in [path, *path.parents]):
            raise ConfigError('init_input_unsafe', f'Symlink in input path: {path}')
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ConfigError('init_input_limit', f'{path} exceeds 4 MiB detector input limit')
        with path.open('rb') as handle:
            raw = handle.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ConfigError('init_input_limit', f'{path} grew beyond the detector limit')
        if path not in self.inputs:
            self.total += len(raw)
            if self.total > MAX_INPUT_BYTES: raise ConfigError('init_input_limit', 'Detector inputs exceed 32 MiB')
        self.inputs[path] = hashlib.sha256(raw).hexdigest()
        return raw.decode('utf-8')

    def has_json_key(self, path, key):
        """Bounded content sniff: capture files need not use a prescribed filename."""
        path = Path(path)
        if path.suffix != '.json' or path.is_symlink() or not path.is_file():
            return False
        # Discovery already skipped symlink directories; do not follow a substituted leaf.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            prefix = os.read(fd, 4096)
        finally:
            os.close(fd)
        return re.search(rb'"' + key.encode('ascii') + rb'"\s*:', prefix) is not None

    def json(self, path):
        return parse_json_bytes(self.read(path).encode(), str(path))

    def rel(self, path):
        return Path(path).resolve().relative_to(self.root).as_posix()

    def identifier(self, prefix, path):
        relative = self.rel(path)
        readable = re.sub('[^A-Za-z0-9._-]', '-', relative)[-38:]
        return f'{prefix}-{readable}-{hashlib.sha256(relative.encode()).hexdigest()[:8]}'[:64]

    def config(self, directory):
        ident = self.identifier('build', directory)
        found = next((x for x in self.configurations if x['id'] == ident), None)
        if found is None:
            found = {'id': ident}
            self.configurations.append(found)
        return found

    def generated(self, name, version=None, **extras):
        record = {'name': name, 'scope': 'unknown', 'generated': True, 'reviewed_by': '',
                  'note': 'Generated claim. Review identity, version, scope, deployment and CPE before relying on it.', **extras}
        if version: record['version'] = version
        self.records.append(record)
        return record
