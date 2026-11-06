"""CISA Known Exploited Vulnerabilities catalogue. A listing starts an investigation.

It shows exploitation somewhere. It does not show exploitation in this product.
"""
from ..common.errors import UntrustedInputError
from ..common.safety import MIB, read_json, sha256_file

MEANING = "Listed as exploited in the wild. This triggers an investigation and does not show exploitation in this product."


def load(path):
    """Return (index, identity, diagnostic message)."""
    if path is None:
        return None, None, "no KEV catalogue was configured"
    try:
        document = read_json(path, 32 * MIB)
        entries = document.get("vulnerabilities") if isinstance(document, dict) else None
        if not isinstance(entries, list) or not entries:
            raise UntrustedInputError("kev_empty", "catalogue has no vulnerabilities")
    except UntrustedInputError as exc:
        return None, None, str(exc)
    index = {item["cveID"]: {"date_added": item.get("dateAdded"), "due_date": item.get("dueDate"), "known_ransomware": item.get("knownRansomwareCampaignUse")}
             for item in entries if isinstance(item, dict) and isinstance(item.get("cveID"), str)}
    if not index:
        return None, None, "catalogue has no usable entries"
    identity = {"catalog_version": document.get("catalogVersion"), "date_released": document.get("dateReleased"),
                "count": len(index), "sha256": sha256_file(path), "title": document.get("title")}
    return index, identity, None
