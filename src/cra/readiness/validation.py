"""Security-sensitive structural checks; independent of user checklist content."""

PART_1_IDS = {f"I.2({letter})" for letter in "abcdefghijklm"}
PART_2_IDS = {f"II.{number}" for number in range(1, 9)}
REQUIREMENT_IDS = PART_1_IDS | PART_2_IDS | {"I.1"}


def validate_product(product):
    if not isinstance(product, dict):
        raise ValueError("product must be an object")
    for field in ("product", "manufacturer", "firmware_version", "build_id", "security_contact"):
        if not isinstance(product.get(field), str):
            raise ValueError(f"product.{field} must be a string")
    annex = product.get("annex_i")
    if not isinstance(annex, dict):
        raise ValueError("product.annex_i must be an object")
    for part, expected in (("part_1", PART_1_IDS), ("part_2", PART_2_IDS)):
        items = annex.get(part)
        if not isinstance(items, list):
            raise ValueError(f"annex_i.{part} must be a list")
        seen = set()
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ValueError(f"annex_i.{part}: every item needs a string id")
            identity = item["id"]
            if identity not in expected or identity in seen:
                raise ValueError(f"annex_i.{part}: unknown or duplicate requirement {identity}")
            seen.add(identity)
            if "computed" in item:
                raise ValueError(f"{identity}: computed is reserved for pipeline-generated items")
            for field in ("req", "evidence", "status"):
                if not isinstance(item.get(field), str):
                    raise ValueError(f"{identity}.{field} must be a string")
            refs = item.get("evidence_refs", [])
            if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
                raise ValueError(f"{identity}.evidence_refs must be a list of non-empty paths")
        if seen != expected:
            raise ValueError(f"annex_i.{part}: missing requirements {', '.join(sorted(expected - seen))}")


def finding_key(vulnerability, purl):
    return vulnerability, purl or None
