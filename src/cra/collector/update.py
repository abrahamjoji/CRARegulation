"""Controlled collector updates: verify, activate, roll back. Never fetches or runs remote code.

A release directory holds a wheel or similar payload, release.json, and a cosign
signature over release.json. Trust comes from the configured public key or
identity. The hash list inside release.json binds the payload to the signature.
"""
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from ..common.errors import EXIT_PASSED, ConfigError, CraError, EXIT_AUTH, OperationalError
from ..common.safety import Limits, read_json, run_tool, sha256_file, tool_environment, write_json

RELEASE_SCHEMA = "cra.release/1"
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def _version_tuple(value):
    return tuple(int(part) for part in value.split("."))


class VerificationError(CraError):
    def __init__(self, code, message):
        super().__init__(code, message, EXIT_AUTH, {})


def verify_release(release_dir, *, cosign="cosign", public_key=None, certificate_identity=None, certificate_issuer=None):
    """Verify signature first, then hashes. Returns the release document."""
    release_dir = Path(release_dir).resolve()
    document_path = release_dir / "release.json"
    bundle = release_dir / "release.json.sigstore.json"
    if document_path.is_symlink() or bundle.is_symlink() or not document_path.is_file() or not bundle.is_file():
        raise VerificationError("release_unsigned", "A release needs release.json and release.json.sigstore.json.")
    if bool(public_key) == bool(certificate_identity):
        raise ConfigError("release_trust_missing", "Choose one trust root: --public-key, or --certificate-identity with --certificate-issuer.")
    argv = [cosign, "verify-blob", str(document_path), "--bundle", str(bundle)]
    if public_key:
        argv += ["--key", str(public_key), "--insecure-ignore-tlog=true"]
    else:
        if not certificate_issuer:
            raise ConfigError("release_trust_missing", "--certificate-identity also needs --certificate-issuer.")
        argv += ["--certificate-identity", certificate_identity, "--certificate-oidc-issuer", certificate_issuer]
    with tempfile.TemporaryDirectory(prefix="cra-cosign-") as cache:
        result = run_tool(argv, limits=Limits(timeout_seconds=120), env=tool_environment({"HOME": cache, "TUF_ROOT": str(Path(cache) / "tuf")}))
    if result.missing:
        raise OperationalError("cosign_missing", f"cosign is not available: {result.stderr}")
    if result.returncode:
        raise VerificationError("release_signature_invalid", f"Signature verification failed: {result.stderr[:400]}")
    document = read_json(document_path, 1024 * 1024)
    if not isinstance(document, dict) or document.get("schema_version") != RELEASE_SCHEMA or not _VERSION.fullmatch(str(document.get("version"))):
        raise VerificationError("release_document_invalid", f"release.json is not a valid {RELEASE_SCHEMA} document.")
    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise VerificationError("release_document_invalid", "release.json lists no files.")
    names = set()
    for entry in files:
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or name in names or name in ("release.json", "release.json.sigstore.json"):
            raise VerificationError("release_document_invalid", f"unsafe file name in release.json: {name!r}")
        names.add(name)
        target = release_dir / name
        if not target.is_file() or target.is_symlink():
            raise VerificationError("release_file_missing", f"{name} is listed but not present.")
        if sha256_file(target) != entry.get("sha256"):
            raise VerificationError("release_hash_mismatch", f"{name} does not match the signed hash.")
    return document


def _state_path(home):
    return Path(home) / "state.json"


def load_state(home):
    path = _state_path(home)
    return read_json(path, 1024 * 1024) if path.exists() else {"schema_version": "cra.release-state/1", "current": None, "previous": None, "history": []}


def activate(release_dir, home, *, allow_downgrade=False, **trust):
    """Verify, copy to an immutable versioned directory, then switch the state atomically."""
    document = verify_release(release_dir, **trust)
    version = document["version"]
    home = Path(home)
    state = load_state(home)
    current = state.get("current")
    if current and _version_tuple(version) < _version_tuple(current) and not allow_downgrade:
        raise VerificationError("release_downgrade", f"Refusing to move from {current} to older {version}. Use `cra release rollback` or --allow-downgrade.")
    versions = home / "versions"
    versions.mkdir(parents=True, exist_ok=True)
    target = versions / version
    if target.exists():
        if target.is_symlink():
            raise VerificationError("release_mutated", "Installed releases must not be symlinks.")
        existing = verify_release(target, **trust)
        if existing.get("files") != document.get("files"):
            raise VerificationError("release_mutated", f"Version {version} is already installed with different content. Releases are immutable.")
    else:
        with tempfile.TemporaryDirectory(prefix=f".{version}.", dir=versions) as temporary:
            staging = Path(temporary) / "release"
            staging.mkdir()
            for name in ["release.json", "release.json.sigstore.json"] + [entry["name"] for entry in document["files"]]:
                shutil.copyfile(Path(release_dir) / name, staging / name)
            if verify_release(staging, **trust) != document:
                raise VerificationError("release_mutated", "Release changed while being installed.")
            os.replace(staging, target)
    if current != version:
        state["previous"], state["current"] = current, version
    state["history"].append({"action": "activate", "version": version})
    write_json(_state_path(home), state)
    return state


def rollback(home, *, to_version=None, **trust):
    """Return to an installed release after re-verifying it. Nothing is downloaded."""
    home = Path(home)
    state = load_state(home)
    version = to_version or state.get("previous")
    if not version:
        raise CraError("rollback_unavailable", "There is no earlier release to return to.", 30, {})
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise VerificationError("release_document_invalid", "Rollback version must be a semantic version.")
    target = home / "versions" / version
    if target.is_symlink():
        raise VerificationError("release_mutated", "Installed releases must not be symlinks.")
    if not target.is_dir():
        raise CraError("rollback_unavailable", f"Release {version} is not installed.", 30, {})
    if verify_release(target, **trust)["version"] != version:
        raise VerificationError("release_mutated", "Installed release version does not match its directory.")
    state["previous"], state["current"] = state.get("current"), version
    state["history"].append({"action": "rollback", "version": version})
    write_json(_state_path(home), state)
    return state


def add_arguments(parser):
    parser.add_argument("action", choices=("verify", "activate", "rollback", "status"))
    parser.add_argument("--dir", help="Release directory to verify or activate")
    parser.add_argument("--home", default=os.environ.get("CRA_HOME", ".cra/releases"))
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--public-key")
    parser.add_argument("--certificate-identity")
    parser.add_argument("--certificate-issuer")
    parser.add_argument("--allow-downgrade", action="store_true")
    parser.add_argument("--to-version")


def main(args):
    trust = {"cosign": args.cosign, "public_key": args.public_key, "certificate_identity": args.certificate_identity, "certificate_issuer": args.certificate_issuer}
    if args.action == "status":
        print(json.dumps(load_state(args.home), indent=2))
    elif args.action == "rollback":
        print(json.dumps(rollback(args.home, to_version=args.to_version, **trust), indent=2))
    else:
        if not args.dir:
            raise ConfigError("release_dir_missing", f"`cra release {args.action}` needs --dir.")
        if args.action == "verify":
            print(json.dumps(verify_release(args.dir, **trust), indent=2))
        else:
            print(json.dumps(activate(args.dir, args.home, allow_downgrade=args.allow_downgrade, **trust), indent=2))
    return EXIT_PASSED
