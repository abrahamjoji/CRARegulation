"""Minimal package URL handling for identity comparison (spec: github.com/package-url/purl-spec)."""
from urllib.parse import quote, unquote


def build(ecosystem, name, version=None, namespace=None):
    parts = [quote(ecosystem, safe="")]
    if namespace:
        parts.append(quote(namespace, safe="/"))
    parts.append(quote(name, safe=""))
    purl = "pkg:" + "/".join(parts)
    return f"{purl}@{quote(version, safe='')}" if version else purl


def parse(purl):
    """Return dict(ecosystem, namespace, name, version, qualifiers) or None if malformed."""
    if not isinstance(purl, str) or not purl.startswith("pkg:") or len(purl) > 2048:
        return None
    body = purl[4:].lstrip("/").split("#", 1)[0]
    body, _, query = body.partition("?")
    head, separator, version = body.rpartition("@")
    if not separator or "/" in version:
        head, version = body, ""
    segments = [segment for segment in head.split("/") if segment]
    if len(segments) < 2:
        return None
    qualifiers = {}
    for pair in query.split("&") if query else []:
        key, _, value = pair.partition("=")
        qualifiers[key.lower()] = unquote(value)
    return {"ecosystem": segments[0].lower(), "namespace": unquote("/".join(segments[1:-1])) or None,
            "name": unquote(segments[-1]), "version": unquote(version) or None, "qualifiers": qualifiers}


def strip(purl):
    """Identity without qualifiers or subpath, used as the reconciliation key."""
    return purl.split("#", 1)[0].split("?", 1)[0] if isinstance(purl, str) else purl
