"""CRA readiness evidence, reusing the existing checks. This is not conformity assessment.

A manufacturer's records are checked for presence and consistency. The output
gives counts, not a percentage, so no number can be read as compliance.
"""
import datetime as dt
from pathlib import Path

from ..common.errors import UntrustedInputError
from ..common.safety import read_json
from ..readiness import checks, validation

DISCLAIMER = ("Readiness evidence only. This does not certify conformity, determine legal applicability, or replace product testing. "
              "The manufacturer remains responsible for the risk assessment, the EU declaration of conformity and CE marking.")


def assess(product_file, risk_file, register_file, sbom_ok, now):
    """Return a readiness section, plus register entries used to enrich findings."""
    today = now.date()
    try:
        product = read_json(product_file, 8 * 1024 * 1024)
        validation.validate_product(product)
        risk = read_json(risk_file, 8 * 1024 * 1024) if risk_file else None
        register = read_json(register_file, 32 * 1024 * 1024) if register_file else None
    except (UntrustedInputError, ValueError) as exc:
        raise UntrustedInputError("readiness_invalid", f"readiness records are invalid: {exc}") from exc
    known = validation.REQUIREMENT_IDS
    risk_problems = checks.validate_risk_assessment(risk, known)
    rationales = checks.not_applicable_rationales(risk)
    entries, register_problems = checks.validate_register(register)
    items = list(product["annex_i"]["part_1"]) + list(product["annex_i"]["part_2"])
    open_without_decision = sum(1 for entry in entries if entry.get("type") == "vulnerability" and not entry.get("release_decision"))
    root = Path(product_file).resolve().parent
    evaluated = [checks.general_requirement(risk, risk_problems, Path(risk_file).name if risk_file else "")]
    evaluated[0]["effective"] = evaluated[0]["status"]
    evaluated[0]["flag"] = ""
    evaluated += [checks.evaluate_item(item, root, rationales, sbom_ok, open_without_decision) for item in items]
    counts = {}
    for item in evaluated:
        counts[item["effective"]] = counts.get(item["effective"], 0) + 1
    product_problems = checks.product_problems(product, today)
    clocks = []
    for entry in entries:
        clock = checks.reporting_clock(entry, now)
        if clock:
            clocks.append({"entry": entry.get("id"), "clock": clock})
    failures = list(risk_problems) + list(product_problems) + list(register_problems)
    failures += [f"{item['id']} is incomplete: {item['effective']}" for item in evaluated if item["effective"] in ("missing", "partial")]
    failures += [f"{item['id']} is marked met without evidence: {item['flag']}" for item in evaluated if item["effective"] == "unverified"]
    for row in clocks:
        failures += [f"Article 14 overdue for {row['entry']}: {step['label']} was due {step['due']}" for step in row["clock"].get("steps", []) if step["state"] == "overdue"]
        if not row["clock"].get("users_informed", True):
            failures.append(f"{row['entry']}: impacted users not yet informed (Article 14(8))")
    return {"disclaimer": DISCLAIMER, "demo_data": bool(product.get("demo")),
            "product": product.get("product"), "firmware_version": product.get("firmware_version"),
            "checklist_counts": counts, "checklist": [{key: item.get(key) for key in ("id", "req", "status", "effective", "flag", "evidence", "computed")} for item in evaluated],
            "risk_problems": risk_problems, "product_problems": product_problems, "register_problems": register_problems,
            "article_14": clocks, "duties": checks.duties(product, today), "release_failures": failures}, entries


def now_utc():
    return dt.datetime.now(dt.timezone.utc)
