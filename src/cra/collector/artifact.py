"""Evidence from explicitly selected build outputs.

The parser reads ELF structure from untrusted bytes with bounds checks and runs
nothing. Finding no identity in a binary is reported as no evidence, not as no
dependencies: static linking, stripping and vendor SDKs all hide components.
"""
import mmap
import re
import struct
from pathlib import Path

from ..common.errors import UntrustedInputError
from ..common.safety import sha256_file, stable_id

MAX_SCAN = 512 * 1024 * 1024
MAX_SECTIONS = 65535
# Upstream version strings. A hit is evidence of presence in the file; a miss proves nothing.
SIGNATURES = (
    ("zlib", re.compile(rb"(?:deflate|inflate) (\d+\.\d+(?:\.\d+){0,2}) Copyright")),
    ("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)[ \x00]")),
    ("mbedtls", re.compile(rb"[Mm]bed ?TLS (\d+\.\d+\.\d+)")),
    ("curl", re.compile(rb"libcurl/(\d+\.\d+\.\d+)")),
)
LIMITATIONS = {
    "static": "Statically linked: dependencies do not appear in the dynamic section. Only embedded version strings can be seen.",
    "stripped": "Stripped: no symbol table, so symbol-based identification is unavailable.",
    "no_signature": "No known version string found. Link-time garbage collection or patching can remove them, so this does not show a component is absent.",
    "vendor": "Vendor SDK and patched components cannot be identified from this file alone; declare them in a component record.",
}


def parse_elf(data):
    """Return ELF facts, or None when the bytes are not ELF. Malformed ELF raises UntrustedInputError."""
    if data[:4] != b"\x7fELF":
        return None
    try:
        return _parse_elf(data)
    except (OverflowError, ValueError, IndexError, struct.error) as exc:
        raise UntrustedInputError("elf_invalid", f"malformed ELF structure: {exc}") from exc


def _parse_elf(data):
    if len(data) < 64:
        raise UntrustedInputError("elf_invalid", "truncated ELF header")
    bits, endian = data[4], data[5]
    if bits not in (1, 2) or endian not in (1, 2):
        raise UntrustedInputError("elf_invalid", "unknown ELF class or byte order")
    order = "<" if endian == 1 else ">"

    def unpack(fmt, offset):
        try:
            return struct.unpack_from(order + fmt, data, offset)
        except struct.error as exc:
            raise UntrustedInputError("elf_invalid", f"ELF structure out of bounds at offset {offset}") from exc

    machine = unpack("H", 18)[0]
    elf_type = unpack("H", 16)[0]
    if bits == 2:
        phoff, shoff = unpack("QQ", 32)
        phentsize, phnum, shentsize, shnum, shstrndx = unpack("HHHHH", 54)
    else:
        phoff, shoff = unpack("II", 28)
        phentsize, phnum, shentsize, shnum, shstrndx = unpack("HHHHH", 42)

    def program(index):
        offset = phoff + index * phentsize
        if bits == 2:
            kind, _, file_offset, vaddr, _, filesz = unpack("IIQQQQ", offset)
        else:
            kind, file_offset, vaddr, _, filesz = unpack("IIIII", offset)
        return kind, file_offset, vaddr, filesz

    def section(index):
        offset = shoff + index * shentsize
        if bits == 2:
            name, kind, _, _, file_offset, size = unpack("IIQQQQ", offset)
        else:
            name, kind, _, _, file_offset, size = unpack("IIIIII", offset)
        return name, kind, file_offset, size

    def cstring(offset, limit=4096):
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset, offset + limit)
        return data[offset:end if end != -1 else offset + limit].decode("utf-8", "replace")

    if phentsize == 0 and phnum:
        raise UntrustedInputError("elf_invalid", "zero program header size")
    segments = [program(index) for index in range(min(phnum, 4096))]
    loads = [item for item in segments if item[0] == 1]
    has_interp = any(item[0] == 3 for item in segments)
    dynamic = next((item for item in segments if item[0] == 2), None)
    needed, soname, runpath = [], "", ""

    def virtual_to_file(address):
        for _, file_offset, vaddr, filesz in loads:
            if vaddr <= address < vaddr + filesz:
                return file_offset + address - vaddr
        return None

    if dynamic:
        entry_format, entry_size = ("qQ", 16) if bits == 2 else ("iI", 8)
        entries, offset = [], dynamic[1]
        end = min(offset + dynamic[3], len(data))
        while offset + entry_size <= end and len(entries) < 8192:
            tag, value = unpack(entry_format, offset)
            if tag == 0:
                break
            entries.append((tag, value))
            offset += entry_size
        strtab_address = next((value for tag, value in entries if tag == 5), None)
        strtab = virtual_to_file(strtab_address) if strtab_address is not None else None
        if strtab is not None:
            for tag, value in entries:
                if tag == 1:
                    needed.append(cstring(strtab + value))
                elif tag == 14:
                    soname = cstring(strtab + value)
                elif tag in (15, 29):
                    runpath = cstring(strtab + value)

    has_symtab, build_id = False, ""
    if shoff and shentsize and 0 < shnum <= MAX_SECTIONS:
        for index in range(min(shnum, 8192)):
            _, kind, file_offset, size = section(index)
            if kind == 2:
                has_symtab = True
            elif kind == 7 and size >= 16 and file_offset + size <= len(data):
                namesz, descsz, note_type = unpack("III", file_offset)
                if note_type == 3 and namesz == 4 and data[file_offset + 12:file_offset + 15] == b"GNU":
                    build_id = data[file_offset + 16:file_offset + 16 + min(descsz, 64)].hex()
    return {"format": "elf", "class": 64 if bits == 2 else 32, "machine": machine,
            "type": {1: "relocatable", 2: "executable", 3: "shared-object"}.get(elf_type, "other"),
            "statically_linked": not dynamic and not has_interp, "needed": [item for item in needed if item],
            "soname": soname, "runpath": runpath, "stripped": not has_symtab, "build_id": build_id}


def scan_signatures(path):
    """Search a bounded prefix for upstream version strings."""
    hits = {}
    with open(path, "rb") as handle:
        size = Path(path).stat().st_size
        if not size:
            return hits, False
        with mmap.mmap(handle.fileno(), min(size, MAX_SCAN), prot=mmap.PROT_READ) as view:
            for name, pattern in SIGNATURES:
                for match in pattern.finditer(view):
                    hits.setdefault(name, set()).add(match.group(1).decode("ascii", "replace"))
                    if len(hits[name]) > 16:
                        break
    return {key: sorted(value) for key, value in hits.items()}, size > MAX_SCAN


def collect_artifact(artifact, evidence_id):
    """Facts and observations for one selected file. Unsupported formats are reported."""
    path = Path(artifact.path)
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(4)
    record = {"id": artifact.id, "kind": "file", "path": str(path), "name": path.name, "sha256": sha256_file(path), "bytes": size,
              "shipped": artifact.shipped, "configuration": artifact.configuration, "format": "unknown",
              "limitations": [], "evidence": evidence_id}
    observations, status, reason = [], "complete", ""
    if header != b"\x7fELF":
        record["limitations"].append("Unsupported file format: recorded by hash only, so dependencies were not inspected.")
        return record, observations, "unsupported", "file format is not supported for dependency inspection"
    if size > MAX_SCAN:
        record["limitations"].append(f"Only the first {MAX_SCAN} bytes were inspected.")
        status, reason = "partial", "file exceeds the inspection limit"
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), min(size, MAX_SCAN), prot=mmap.PROT_READ) as view:
        facts = parse_elf(view)
    record.update(format="elf", elf=facts)
    record["limitations"].append(LIMITATIONS["vendor"])
    if facts["statically_linked"]:
        record["limitations"].append(LIMITATIONS["static"])
    if facts["stripped"]:
        record["limitations"].append(LIMITATIONS["stripped"])
    hits, _ = scan_signatures(path)
    if not hits:
        record["limitations"].append(LIMITATIONS["no_signature"])
    for name, versions in sorted(hits.items()):
        for version in versions:
            observations.append({
                "id": stable_id("obs", "artifact", artifact.id, name, version), "source": "artifact-signature", "state": "observed",
                "configuration": artifact.configuration, "artifact": artifact.id,
                "identity": {"ecosystem": "generic", "name": name, "version": version, "purl": f"pkg:generic/{name}@{version}",
                             "supplier": "", "license": "", "cpes": []},
                "upstream_name": name, "scope": "runtime", "linkage": "static-or-embedded", "location": f"version string in {path.name}",
                "evidence": evidence_id, "confidence": "medium", "attributes": {"signature": name},
            })
    for library in facts["needed"]:
        observations.append({
            "id": stable_id("obs", "artifact-needed", artifact.id, library), "source": "artifact-needed", "state": "observed",
            "configuration": artifact.configuration, "artifact": artifact.id, "identity": None, "soname": library,
            "scope": "runtime", "linkage": "shared", "location": f"DT_NEEDED of {path.name}", "evidence": evidence_id,
            "confidence": "high", "attributes": {},
        })
    return record, observations, status, reason
