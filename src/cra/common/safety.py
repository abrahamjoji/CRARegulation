"""Boundaries for untrusted input: bounded parsing, path scope, subprocesses, redaction."""
import hashlib
import json
import os
import re
import resource
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import UntrustedInputError

MIB = 1024 * 1024
DEFAULT_MAX_JSON = 64 * MIB
MAX_JSON_DEPTH = 128


def _reject_constant(name):
    raise ValueError(f"non-finite JSON number {name}")


def _check_depth(value):
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise UntrustedInputError("json_too_deep", f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def parse_json_bytes(data, label="input"):
    try:
        value = json.loads(data, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise UntrustedInputError("json_too_deep", f"{label}: JSON nesting is too deep") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise UntrustedInputError("json_invalid", f"{label}: invalid JSON ({exc})") from exc
    _check_depth(value)
    return value


def read_json(path, max_bytes=DEFAULT_MAX_JSON):
    """Read a regular JSON file, refusing oversize input before loading it."""
    path = Path(path)
    try:
        info = path.stat()
    except OSError as exc:
        raise UntrustedInputError("file_unreadable", f"{path}: {exc.strerror or exc}") from exc
    if not path.is_file():
        raise UntrustedInputError("not_a_file", f"{path}: not a regular file")
    if info.st_size > max_bytes:
        raise UntrustedInputError("file_too_large", f"{path}: {info.st_size} bytes exceeds the {max_bytes} byte limit")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UntrustedInputError("file_too_large", f"{path}: exceeds the {max_bytes} byte limit")
    return parse_json_bytes(data, str(path))


def write_json(path, value):
    """Atomically write deterministic JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def stable_id(prefix, *parts):
    text = "\x1f".join("" if part is None else str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}"


class PathScope:
    """Explicit list of directories the collector may read. Symlinks resolve before the check."""

    def __init__(self, roots):
        self.roots = [Path(root).resolve() for root in roots]

    def contains(self, path):
        resolved = Path(path).resolve()
        return any(resolved.is_relative_to(root) for root in self.roots)

    def require(self, path, label="path"):
        resolved = Path(path).resolve()
        if not any(resolved.is_relative_to(root) for root in self.roots):
            raise UntrustedInputError("path_out_of_scope", f"{label}: {path} is outside the configured filesystem scope")
        return resolved


# Secret redaction. Evidence keeps its structure; only values that look sensitive change.
REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(r"(?i)(pass(word|wd|phrase)?|secret|token|api[_-]?key|credential|private[_-]?key|auth(orization)?)$|(_|-)(pass|pwd|key)$")
_VALUE_PATTERNS = [
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\bcra_[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
]
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@:]+(:[^\s/@]*)?@")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9+/_.=\-]{8,}")
_ASSIGNMENT = re.compile(r"(?i)\b([A-Z0-9_.\-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY)[A-Z0-9_.\-]*)=(\S+)")


def redact_text(text):
    """Return (redacted text, replacement count)."""
    total = 0
    for pattern in _VALUE_PATTERNS:
        text, count = pattern.subn(REDACTED, text)
        total += count
    text, count = _URL_USERINFO.subn(lambda m: f"{m.group(1)}{REDACTED}@", text)
    total += count
    text, count = _BEARER.subn(lambda m: f"{m.group(1)} {REDACTED}", text)
    total += count
    text, count = _ASSIGNMENT.subn(lambda m: f"{m.group(1)}={REDACTED}", text)
    return text, total + count


def redact(value):
    """Redact a JSON value. Sensitive keys lose their value; other strings are pattern-scanned."""
    count = 0

    def walk(item, key=""):
        nonlocal count
        if isinstance(item, dict):
            # CMake cache entries carry the key in "name" beside the secret in "value".
            sibling = item.get("name") if isinstance(item.get("name"), str) else ""
            out = {}
            for name, entry in item.items():
                sensitive = _SECRET_KEY.search(str(name)) or (name == "value" and _SECRET_KEY.search(sibling))
                if sensitive and isinstance(entry, (str, int, float)) and entry not in ("", None, False, True):
                    out[name] = REDACTED
                    count += 1
                else:
                    out[name] = walk(entry, str(name))
            return out
        if isinstance(item, list):
            return [walk(entry, key) for entry in item]
        if isinstance(item, str):
            cleaned, replaced = redact_text(item)
            count += replaced
            return cleaned
        return item

    return walk(value), count


# Safe subprocesses: an argument list, never a shell; a scrubbed environment; limits.
ENV_BASE = ("PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")


@dataclass(frozen=True)
class Limits:
    timeout_seconds: int = 600
    cpu_seconds: int = 1800
    output_bytes: int = 2048 * MIB
    memory_bytes: int = 16 * 1024 * MIB
    open_files: int = 4096


@dataclass
class ToolResult:
    returncode: int
    stderr: str
    timed_out: bool
    missing: bool = False


def _apply_limits(limits):
    def apply():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.output_bytes, limits.output_bytes))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
    return apply


def tool_environment(extra=None, passthrough=()):
    """Build an allow-listed environment so credentials do not reach scanner processes."""
    env = {name: os.environ[name] for name in ENV_BASE if name in os.environ}
    env.update({name: os.environ[name] for name in passthrough if name in os.environ})
    env.update(extra or {})
    return env


def run_tool(argv, *, stdout_path=None, limits=Limits(), env=None, cwd=None):
    """Run a tool without a shell. stdout goes to a file so large output cannot fill memory."""
    if not argv or not all(isinstance(part, str) for part in argv):
        raise ValueError("argv must be a non-empty list of strings")
    with tempfile.TemporaryFile() as stderr_file:
        stdout_target = open(stdout_path, "wb") if stdout_path else subprocess.DEVNULL
        try:
            try:
                process = subprocess.Popen(
                    argv, stdin=subprocess.DEVNULL, stdout=stdout_target, stderr=stderr_file,
                    env=tool_environment() if env is None else env, cwd=cwd, shell=False,
                    start_new_session=True, close_fds=True, preexec_fn=_apply_limits(limits),
                )
            except (FileNotFoundError, PermissionError, NotADirectoryError) as exc:
                return ToolResult(127, f"cannot start {argv[0]}: {exc.strerror}", False, missing=True)
            timed_out = False
            try:
                process.wait(timeout=limits.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        finally:
            if stdout_path:
                stdout_target.close()
        stderr_file.seek(0)
        tail = stderr_file.read(64 * 1024).decode("utf-8", "replace")
    return ToolResult(process.returncode, redact_text(tail)[0], timed_out)


def text_field(value, label, *, max_length=4096, required=True):
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise UntrustedInputError("field_invalid", f"{label}: expected a non-empty string")
    if len(value) > max_length:
        raise UntrustedInputError("field_too_long", f"{label}: longer than {max_length} characters")
    if any(ord(c) < 32 and c not in "\t\n\r" for c in value):
        raise UntrustedInputError("field_invalid", f"{label}: contains control characters")
    return value
