"""Tar handling for hostile input. Nothing is written until every member passes."""
import gzip
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import UntrustedInputError
from .safety import MIB


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int = 20000
    max_total_bytes: int = 4096 * MIB
    max_member_bytes: int = 2048 * MIB


def _member_path(name):
    path = PurePosixPath(name)
    if not name or "\x00" in name or "\\" in name or path.is_absolute() or ".." in path.parts:
        raise UntrustedInputError("archive_traversal", f"unsafe archive member path: {name!r}")
    return path


def _open(path):
    try:
        return tarfile.open(path, mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UntrustedInputError("archive_invalid", f"{path}: not a readable tar archive ({exc})") from exc


def inspect_tar(path, limits=ArchiveLimits()):
    """Validate every member; links, devices and traversal are refused. Returns name -> size."""
    members, total = {}, 0
    with _open(path) as archive:
        try:
            for member in archive:
                location = _member_path(member.name)
                if member.issym() or member.islnk():
                    raise UntrustedInputError("archive_link", f"archive member is a link: {member.name!r}")
                if not (member.isfile() or member.isdir()):
                    raise UntrustedInputError("archive_special", f"special file in archive: {member.name!r}")
                if len(members) >= limits.max_members:
                    raise UntrustedInputError("archive_too_many", f"more than {limits.max_members} archive members")
                if member.size > limits.max_member_bytes:
                    raise UntrustedInputError("archive_too_large", f"member too large: {member.name!r}")
                total += member.size
                if total > limits.max_total_bytes:
                    raise UntrustedInputError("archive_too_large", f"archive expands beyond {limits.max_total_bytes} bytes")
                key = location.as_posix()
                if key in members:
                    raise UntrustedInputError("archive_duplicate", f"duplicate archive member: {member.name!r}")
                members[key] = member.size
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise UntrustedInputError("archive_invalid", f"{path}: corrupt tar archive ({exc})") from exc
    return members


def read_member(path, name, max_bytes=16 * MIB):
    """Read one validated member from an archive."""
    with _open(path) as archive:
        try:
            member = archive.getmember(name)
        except KeyError as exc:
            raise UntrustedInputError("archive_member_missing", f"{path}: no member {name!r}") from exc
        if not member.isfile() or member.size > max_bytes:
            raise UntrustedInputError("archive_member_invalid", f"{path}: {name!r} is not a small regular file")
        handle = archive.extractfile(member)
        return handle.read(max_bytes + 1)


def safe_extract(path, destination, limits=ArchiveLimits()):
    """Extract regular files and directories only, into an empty directory."""
    inspect_tar(path, limits)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise UntrustedInputError("archive_destination", "extraction directory must be empty")
    root = destination.resolve()
    with _open(path) as archive:
        for member in archive:
            target = root.joinpath(*_member_path(member.name).parts)
            if not target.resolve().is_relative_to(root):
                raise UntrustedInputError("archive_traversal", f"member escapes destination: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            # O_EXCL and O_NOFOLLOW: never write through something that already exists.
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "wb") as output:
                remaining = member.size
                while remaining > 0:
                    block = source.read(min(MIB, remaining))
                    if not block:
                        raise UntrustedInputError("archive_invalid", f"truncated member: {member.name!r}")
                    output.write(block)
                    remaining -= len(block)
    return root


def create_tar_gz(source_dir, destination):
    """Pack a directory into a gzip tar with normalized ownership and times."""
    source_dir = Path(source_dir)

    def clean(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        info.mode = 0o755 if info.isdir() else 0o644
        return info

    # mtime=0 and sorted members make the bytes reproducible, so a retried upload
    # of the same evidence has the same hash and the same idempotency key.
    with open(destination, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=6) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in sorted(source_dir.rglob("*")):
                if path.is_symlink():
                    raise UntrustedInputError("bundle_symlink", f"refusing to pack a symlink: {path}")
                archive.add(path, arcname=path.relative_to(source_dir).as_posix(), recursive=False, filter=clean)
    return destination
